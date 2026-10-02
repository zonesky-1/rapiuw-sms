const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const { run, get, all } = require('../database');
const wa = require('../whatsapp');

// Auth middleware for protected API endpoints
async function authenticateKey(req, res, next) {
    let token = req.headers['authorization'] || req.query.token || req.body?.token;
    if (token && token.startsWith('Bearer ')) {
        token = token.slice(7).trim();
    }

    if (!token) {
        return res.status(401).json({
            status: false,
            message: 'Unauthorized: API Token is required in Authorization header or query parameter'
        });
    }

    try {
        const keyRecord = await get('SELECT * FROM api_keys WHERE api_token = ?', [token]);
        if (!keyRecord) {
            return res.status(401).json({
                status: false,
                message: 'Unauthorized: Invalid API Token'
            });
        }
        req.apiKey = keyRecord;
        next();
    } catch (err) {
        console.error('Auth error:', err);
        res.status(500).json({ status: false, message: 'Internal server error' });
    }
}

// Auth middleware for protected API endpoints & Multi-User session
function getUserIdFromReq(req) {
    if (req.user && req.user.id) return req.user.id;
    if (req.apiKey && req.apiKey.user_id) return req.apiKey.user_id;
    return null;
}

// Management endpoints require either admin secret OR authenticated user session
function authenticateAdmin(req, res, next) {
    if (req.isAuthenticated && req.isAuthenticated() && req.user) {
        return next();
    }
    const configured = process.env.ADMIN_API_TOKEN;
    const supplied = (req.headers['x-admin-token'] || '').trim();
    if (!configured) {
        return res.status(503).json({ status: false, message: 'Admin API belum dikonfigurasi.' });
    }
    if (!supplied || supplied.length !== configured.length || !crypto.timingSafeEqual(Buffer.from(supplied), Buffer.from(configured))) {
        return res.status(401).json({ status: false, message: 'Unauthorized: sesi login atau admin token tidak valid.' });
    }
    next();
}

// --------------------- OTP API ---------------------

// Helper rate limiter OTP (max 3 req / 10 min per target, 30s cooldown)
async function checkOtpRateLimit(target) {
    const cleanTarget = target.replace(/[^0-9]/g, '');
    const now = new Date();
    const limitRecord = await get('SELECT * FROM otp_rate_limits WHERE target = ?', [cleanTarget]);

    if (!limitRecord) {
        await run(
            'INSERT INTO otp_rate_limits (target, request_count, window_start, last_sent) VALUES (?, 1, ?, ?)',
            [cleanTarget, now.toISOString(), now.toISOString()]
        );
        return { allowed: true };
    }

    const lastSent = new Date(limitRecord.last_sent);
    const windowStart = new Date(limitRecord.window_start);
    const cooldownMs = 30 * 1000;
    const windowMs = 10 * 60 * 1000;

    if (now - lastSent < cooldownMs) {
        const remainingCd = Math.ceil((cooldownMs - (now - lastSent)) / 1000);
        return { allowed: false, message: `Harap tunggu ${remainingCd} detik sebelum meminta OTP lagi.` };
    }

    if (now - windowStart > windowMs) {
        await run(
            'UPDATE otp_rate_limits SET request_count = 1, window_start = ?, last_sent = ? WHERE target = ?',
            [now.toISOString(), now.toISOString(), cleanTarget]
        );
        return { allowed: true };
    }

    if (limitRecord.request_count >= 3) {
        const remainingWin = Math.ceil((windowMs - (now - windowStart)) / 1000 / 60);
        return { allowed: false, message: `Batas pengiriman OTP tercapai (maks 3/10m). Coba lagi dalam ${remainingWin} menit.` };
    }

    await run(
        'UPDATE otp_rate_limits SET request_count = request_count + 1, last_sent = ? WHERE target = ?',
        [now.toISOString(), cleanTarget]
    );
    return { allowed: true };
}

// Generate & Send OTP
router.post('/otp/send', authenticateKey, async (req, res) => {
    try {
        let { target, length, expiry, template, purpose } = req.body;

        if (!target) {
            return res.status(400).json({ status: false, message: 'Field "target" (nomor WhatsApp) wajib diisi.' });
        }

        const rateCheck = await checkOtpRateLimit(target);
        if (!rateCheck.allowed) {
            return res.status(429).json({ status: false, message: rateCheck.message });
        }

        const otpLength = parseInt(length) || 6;
        if (otpLength < 4 || otpLength > 8) {
            return res.status(400).json({ status: false, message: 'Panjang OTP harus antara 4 hingga 8 digit.' });
        }

        const expirySeconds = parseInt(expiry) || 300; // 5 menit default
        const expiryMinutes = Math.ceil(expirySeconds / 60);

        // Generate numerical OTP
        let otpCode = '';
        for (let i = 0; i < otpLength; i++) {
            otpCode += crypto.randomInt(0, 10).toString();
        }

        const purposeText = purpose || 'Verifikasi Akun';

        // Calculate expires_at
        const now = new Date();
        const expiresAt = new Date(now.getTime() + expirySeconds * 1000);

        // Default template if not provided
        const defaultTemplate = 
`🔒 *KODE VERIFIKASI OTP*

Halo! Kode OTP Anda untuk *${purposeText}* adalah:

👉 *${otpCode}* 👈

Kode ini berlaku selama *${expiryMinutes} menit*.
⚠️ _JANGAN bagikan kode ini kepada siapapun termasuk pihak kami demi keamanan akun Anda._`;

        let messageText = template ? template.replace(/\{otp\}/g, otpCode).replace(/\{expiry_minutes\}/g, expiryMinutes) : defaultTemplate;

        // Save OTP record to database
        const cleanTarget = target.replace(/[^0-9]/g, '');
        const insertResult = await run(
            'INSERT INTO otps (target, otp_code, purpose, status, expires_at) VALUES (?, ?, ?, ?, ?)',
            [cleanTarget, otpCode, purposeText, 'pending', expiresAt.toISOString()]
        );

        // Send via WhatsApp
        let sendResult;
        try {
            sendResult = await wa.sendMessage(target, messageText, { type: 'otp' });
        } catch (sendErr) {
            // Update OTP status to failed
            await run('UPDATE otps SET status = ? WHERE id = ?', ['failed', insertResult.id]);
            return res.status(500).json({
                status: false,
                message: `Gagal mengirim WhatsApp: ${sendErr.message}`,
                error_detail: sendErr.message
            });
        }

        res.json({
            status: true,
            message: 'Kode OTP berhasil dibuat dan dikirim ke WhatsApp target.',
            data: {
                id: insertResult.id,
                target: wa.formatPhoneDisplay(target),
                purpose: purposeText,
                expires_at: expiresAt.toISOString(),
                expires_in_seconds: expirySeconds,
                message_id: sendResult.messageId
            }
        });
    } catch (err) {
        console.error('OTP Send error:', err);
        res.status(500).json({ status: false, message: err.message });
    }
});

// Verify OTP
router.post('/otp/verify', authenticateKey, async (req, res) => {
    try {
        let { target, code, purpose } = req.body;

        if (!target || !code) {
            return res.status(400).json({
                status: false,
                message: 'Field "target" dan "code" wajib diisi.'
            });
        }

        const cleanTarget = target.replace(/[^0-9]/g, '');
        const cleanCode = code.toString().trim();
        const maxAttempts = 5;

        // Find active OTP record for this target (strict match, 1 record only)
        const activeOtp = await get(
            `SELECT * FROM otps WHERE target = ? AND status = 'pending' ORDER BY id DESC LIMIT 1`,
            [cleanTarget]
        );

        if (!activeOtp) {
            // Check if any recently failed/locked
            const recentOtp = await get(
                `SELECT * FROM otps WHERE target = ? AND status IN ('failed','locked') ORDER BY id DESC LIMIT 1`,
                [cleanTarget]
            );
            if (recentOtp) {
                return res.status(403).json({
                    status: false,
                    message: 'Akun OTP untuk nomor ini telah dikunci akibat percobaan berlebih. Hubungi admin atau tunggu reset.'
                });
            }
            return res.status(404).json({
                status: false,
                message: 'Tidak ada OTP aktif untuk nomor tersebut. Minta OTP baru terlebih dahulu.'
            });
        }

        // Expiry check
        const now = new Date();
        const expiresAt = new Date(activeOtp.expires_at);
        if (now > expiresAt) {
            await run('UPDATE otps SET status = ? WHERE id = ?', ['expired', activeOtp.id]);
            return res.status(400).json({
                status: false,
                message: 'Kode OTP telah kedaluwarsa. Silakan minta kode baru.'
            });
        }

        // Brute-force counter
        if (activeOtp.attempts >= maxAttempts) {
            await run('UPDATE otps SET status = ? WHERE id = ?', ['locked', activeOtp.id]);
            return res.status(403).json({
                status: false,
                message: 'Terlalu banyak percobaan salah. OTP dikunci.'
            });
        }

        // Constant-time comparison to prevent timing attack
        const targetBuf = Buffer.from(activeOtp.otp_code);
        const suppliedBuf = Buffer.from(cleanCode.padEnd(targetBuf.length, ' '));
        const match = suppliedBuf.length === targetBuf.length &&
            crypto.timingSafeEqual(suppliedBuf, targetBuf);

        if (!match) {
            const newAttempts = activeOtp.attempts + 1;
            if (newAttempts >= maxAttempts) {
                await run('UPDATE otps SET status = ?, attempts = ? WHERE id = ?', ['locked', newAttempts, activeOtp.id]);
                return res.status(403).json({
                    status: false,
                    message: `Percobaan ${newAttempts}/${maxAttempts} salah — OTP dikunci.`
                });
            }
            await run('UPDATE otps SET attempts = ? WHERE id = ?', [newAttempts, activeOtp.id]);
            return res.status(400).json({
                status: false,
                message: `Kode OTP salah. Sisa ${maxAttempts - newAttempts} percobaan.`
            });
        }

        // OTP Valid
        await run(
            'UPDATE otps SET status = ?, verified_at = CURRENT_TIMESTAMP, attempts = 0 WHERE id = ?',
            ['verified', activeOtp.id]
        );

        res.json({
            status: true,
            message: 'Verifikasi OTP berhasil!',
            data: {
                id: activeOtp.id,
                target: wa.formatPhoneDisplay(cleanTarget),
                purpose: activeOtp.purpose,
                verified_at: new Date().toISOString()
            }
        });

    } catch (err) {
        console.error('OTP Verify error:', err);
        res.status(500).json({ status: false, message: err.message });
    }
});

// --------------------- Fonnte Compatible API ---------------------

// Send message (Fonnte API compatibility)
const handleSend = async (req, res) => {
    try {
        const { target, message, countryCode } = req.body;

        if (!target || !message) {
            return res.status(400).json({
                status: false,
                message: 'Parameter "target" dan "message" wajib diisi.'
            });
        }

        const targets = target.toString().split(',').map(t => t.trim()).filter(Boolean);
        const results = [];
        const ids = [];

        for (const t of targets) {
            try {
                const resSend = await wa.sendMessage(t, message, { type: 'broadcast' });
                results.push({ target: t, status: true });
                ids.push(resSend.messageId || 'MSG_' + Date.now());
            } catch (e) {
                results.push({ target: t, status: false, error: e.message });
            }
        }

        res.json({
            status: results.some(r => r.status),
            target: targets,
            id: ids,
            process: 'processing',
            details: results
        });
    } catch (err) {
        console.error('Send message error:', err);
        res.status(500).json({ status: false, message: err.message });
    }
};

router.post('/send', authenticateKey, handleSend);
router.post('/v1/send', authenticateKey, handleSend);

// --------------------- Device Management API ---------------------

router.get('/devices', authenticateAdmin, async (req, res) => {
    try {
        const rows = await all('SELECT id, name, number, status, package_name, quota, expired_at, token, created_at FROM devices ORDER BY id DESC');
        res.json({ status: true, data: rows });
    } catch (err) {
        res.status(500).json({ status: false, message: err.message });
    }
});

router.post('/devices', authenticateAdmin, async (req, res) => {
    try {
        const { name } = req.body;
        if (!name || name.length > 80) {
            return res.status(400).json({ status: false, message: 'Nama device wajib (maks 80 karakter).' });
        }
        const token = 'fn-' + crypto.randomBytes(16).toString('hex');
        const exp = new Date();
        exp.setFullYear(exp.getFullYear() + 1);
        const result = await run(
            'INSERT INTO devices (name, status, package_name, quota, expired_at, token) VALUES (?, ?, ?, ?, ?, ?)',
            [name, 'disconnect', 'Free', 1000, exp.toISOString(), token]
        );
        const device = await get('SELECT id, name, number, status, package_name, quota, expired_at, token, created_at FROM devices WHERE id = ?', [result.id]);
        res.status(201).json({ status: true, data: device });
    } catch (err) {
        res.status(500).json({ status: false, message: err.message });
    }
});

router.patch('/devices/:id', authenticateAdmin, async (req, res) => {
    try {
        const { name, number } = req.body;
        const device = await get('SELECT id FROM devices WHERE id = ?', [req.params.id]);
        if (!device) return res.status(404).json({ status: false, message: 'Device tidak ditemukan.' });
        await run('UPDATE devices SET name = COALESCE(?, name), number = COALESCE(?, number) WHERE id = ?', [name || null, number || null, req.params.id]);
        res.json({ status: true, message: 'Device diperbarui.' });
    } catch (err) {
        res.status(500).json({ status: false, message: err.message });
    }
});

router.delete('/devices/:id', authenticateAdmin, async (req, res) => {
    try {
        const result = await run('DELETE FROM devices WHERE id = ?', [req.params.id]);
        if (!result.changes) return res.status(404).json({ status: false, message: 'Device tidak ditemukan.' });
        res.json({ status: true, message: 'Device dihapus.' });
    } catch (err) {
        res.status(500).json({ status: false, message: err.message });
    }
});

// --------------------- Device & System API ---------------------

router.get('/device/status', authenticateAdmin, (req, res) => {
    res.json({
        status: true,
        data: wa.getStatus()
    });
});

router.post('/device/reconnect', authenticateAdmin, async (req, res) => {
    try {
        await wa.connectToWhatsApp();
        res.json({ status: true, message: 'Mencoba menghubungkan ulang ke WhatsApp...' });
    } catch (err) {
        res.status(500).json({ status: false, message: err.message });
    }
});

router.post('/device/logout', authenticateAdmin, async (req, res) => {
    try {
        await wa.logoutWhatsApp();
        res.json({ status: true, message: 'Perangkat WhatsApp berhasil logout.' });
    } catch (err) {
        res.status(500).json({ status: false, message: err.message });
    }
});

// --------------------- Dashboard Management APIs ---------------------

router.get('/stats', authenticateAdmin, async (req, res) => {
    try {
        const totalOtps = await get('SELECT COUNT(*) as count FROM otps');
        const verifiedOtps = await get("SELECT COUNT(*) as count FROM otps WHERE status = 'verified'");
        const totalMessages = await get('SELECT COUNT(*) as count FROM messages');
        const recentOtps = await all('SELECT * FROM otps ORDER BY id DESC LIMIT 10');
        const deviceStatus = wa.getStatus();

        const successRate = totalOtps.count > 0 
            ? ((verifiedOtps.count / totalOtps.count) * 100).toFixed(1) 
            : '0.0';

        res.json({
            status: true,
            data: {
                total_otps: totalOtps.count,
                verified_otps: verifiedOtps.count,
                success_rate: `${successRate}%`,
                total_messages: totalMessages.count,
                device: deviceStatus,
                recent_otps: recentOtps
            }
        });
    } catch (err) {
        res.status(500).json({ status: false, message: err.message });
    }
});

router.get('/logs/otps', authenticateAdmin, async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 50;
        const rows = await all('SELECT * FROM otps ORDER BY id DESC LIMIT ?', [limit]);
        res.json({ status: true, data: rows });
    } catch (err) {
        res.status(500).json({ status: false, message: err.message });
    }
});

router.get('/logs/messages', authenticateAdmin, async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 50;
        const rows = await all('SELECT * FROM messages ORDER BY id DESC LIMIT ?', [limit]);
        res.json({ status: true, data: rows });
    } catch (err) {
        res.status(500).json({ status: false, message: err.message });
    }
});

router.get('/keys', authenticateAdmin, async (req, res) => {
    try {
        const rows = await all('SELECT * FROM api_keys ORDER BY id DESC');
        res.json({ status: true, data: rows });
    } catch (err) {
        res.status(500).json({ status: false, message: err.message });
    }
});

router.post('/keys', authenticateAdmin, async (req, res) => {
    try {
        const { key_name } = req.body;
        const token = 'rapiuw-' + crypto.randomBytes(16).toString('hex');
        const result = await run(
            'INSERT INTO api_keys (key_name, api_token) VALUES (?, ?)',
            [key_name || 'API Token Baru', token]
        );
        res.json({
            status: true,
            message: 'API Key berhasil dibuat!',
            data: { id: result.id, key_name: key_name || 'API Token Baru', api_token: token }
        });
    } catch (err) {
        res.status(500).json({ status: false, message: err.message });
    }
});

router.delete('/keys/:id', async (req, res) => {
    try {
        await run('DELETE FROM api_keys WHERE id = ?', [req.params.id]);
        res.json({ status: true, message: 'API Key berhasil dihapus.' });
    } catch (err) {
        res.status(500).json({ status: false, message: err.message });
    }
});

// --------------------- Auth Login API using API Key ---------------------

// Verify / Login with API Key
router.post('/auth/login', async (req, res) => {
    try {
        let token = req.body?.api_token || req.body?.api_key || req.body?.token;
        if (!token && req.headers['authorization']) {
            token = req.headers['authorization'].replace(/^Bearer\s+/i, '').trim();
        }

        if (!token) {
            return res.status(400).json({
                status: false,
                message: 'API Key (token) wajib diisi untuk login.'
            });
        }

        const keyRecord = await get('SELECT id, key_name, api_token, created_at FROM api_keys WHERE api_token = ?', [token]);
        if (!keyRecord) {
            return res.status(401).json({
                status: false,
                message: 'Login gagal: API Key tidak valid atau tidak terdaftar.'
            });
        }

        res.json({
            status: true,
            message: 'Autentikasi login berhasil!',
            data: {
                id: keyRecord.id,
                name: keyRecord.key_name,
                created_at: keyRecord.created_at
            }
        });
    } catch (err) {
        console.error('Auth login error:', err);
        res.status(500).json({ status: false, message: err.message });
    }
});

// Check auth status
router.get('/auth/me', authenticateKey, (req, res) => {
    res.json({
        status: true,
        message: 'Token aktif dan terverifikasi.',
        data: {
            id: req.apiKey.id,
            name: req.apiKey.key_name,
            created_at: req.apiKey.created_at
        }
    });
});

module.exports = router;
