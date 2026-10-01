const {
    default: makeWASocket,
    useMultiFileAuthState,
    DisconnectReason,
    fetchLatestBaileysVersion,
    makeCacheableSignalKeyStore,
    delay
} = require('@whiskeysockets/baileys');
const pino = require('pino');
const QRCode = require('qrcode');
const path = require('path');
const fs = require('fs');
const { run, get, all } = require('./database');

let sock = null;
let ioInstance = null;
let qrCodeData = null;
let connectionStatus = 'disconnected'; // disconnected, connecting, connected
let connectedUser = null;

const sessionDir = path.join(__dirname, 'sessions', 'main-session');
if (!fs.existsSync(sessionDir)) {
    fs.mkdirSync(sessionDir, { recursive: true });
}

// Phone number standardizer (e.g., 08123456789 -> 628123456789)
function formatToJid(number) {
    if (!number) return null;
    let clean = number.replace(/[^0-9]/g, '');
    if (clean.startsWith('0')) {
        clean = '62' + clean.slice(1);
    } else if (!clean.startsWith('62') && clean.length <= 11) {
        clean = '62' + clean;
    }
    return clean.includes('@s.whatsapp.net') ? clean : `${clean}@s.whatsapp.net`;
}

function formatPhoneDisplay(number) {
    if (!number) return '';
    let clean = number.split('@')[0];
    if (clean.startsWith('62')) {
        return '0' + clean.slice(2);
    }
    return clean;
}

const logger = pino({ level: 'silent' });

async function connectToWhatsApp(io) {
    if (io) ioInstance = io;
    connectionStatus = 'connecting';
    broadcastStatus();

    try {
        const { state, saveCreds } = await useMultiFileAuthState(sessionDir);
        const { version, isLatest } = await fetchLatestBaileysVersion();

        sock = makeWASocket({
            version,
            logger,
            printQRInTerminal: false,
            auth: {
                creds: state.creds,
                keys: makeCacheableSignalKeyStore(state.keys, logger)
            },
            browser: ['Fonte OTP Platform', 'Chrome', '1.0.0']
        });

        sock.ev.on('creds.update', saveCreds);

        sock.ev.on('connection.update', async (update) => {
            const { connection, lastDisconnect, qr } = update;

            if (qr) {
                try {
                    qrCodeData = await QRCode.toDataURL(qr);
                    connectionStatus = 'connecting';
                    broadcastStatus();
                    console.log('[WA] New QR Code generated');
                } catch (err) {
                    console.error('[WA] Failed to generate QR code DataURL:', err);
                }
            }

            if (connection === 'close') {
                qrCodeData = null;
                const statusCode = lastDisconnect?.error?.output?.statusCode;
                const shouldReconnect = statusCode !== DisconnectReason.loggedOut;
                console.log(`[WA] Connection closed due to: ${lastDisconnect?.error}, statusCode: ${statusCode}. Reconnecting: ${shouldReconnect}`);

                if (shouldReconnect) {
                    connectionStatus = 'connecting';
                    broadcastStatus();
                    setTimeout(() => connectToWhatsApp(ioInstance), 3000);
                } else {
                    connectionStatus = 'disconnected';
                    connectedUser = null;
                    broadcastStatus();
                    // Clear session files if logged out
                    fs.rmSync(sessionDir, { recursive: true, force: true });
                    fs.mkdirSync(sessionDir, { recursive: true });
                }
            } else if (connection === 'open') {
                qrCodeData = null;
                connectionStatus = 'connected';
                connectedUser = {
                    id: sock.user?.id ? formatPhoneDisplay(sock.user.id) : 'Connected',
                    name: sock.user?.name || 'WhatsApp Device',
                    rawJid: sock.user?.id
                };
                console.log('[WA] Connection opened! Connected user:', connectedUser);
                broadcastStatus();
            }
        });

    } catch (err) {
        console.error('[WA] Connection error:', err);
        connectionStatus = 'disconnected';
        broadcastStatus();
    }
}

function broadcastStatus() {
    if (ioInstance) {
        ioInstance.emit('wa:status', {
            status: connectionStatus,
            qr: qrCodeData,
            user: connectedUser
        });
    }
}

function getStatus() {
    return {
        status: connectionStatus,
        qr: qrCodeData,
        user: connectedUser
    };
}

async function logoutWhatsApp() {
    if (sock) {
        try {
            await sock.logout();
        } catch (e) {
            console.error('[WA] Error logging out:', e);
        }
    }
    fs.rmSync(sessionDir, { recursive: true, force: true });
    fs.mkdirSync(sessionDir, { recursive: true });
    connectionStatus = 'disconnected';
    connectedUser = null;
    qrCodeData = null;
    broadcastStatus();
}

async function sendMessage(target, messageText, options = {}) {
    if (connectionStatus !== 'connected' || !sock) {
        throw new Error('WhatsApp device is not connected. Please scan QR Code first.');
    }

    const jid = formatToJid(target);
    if (!jid) {
        throw new Error('Invalid target phone number format.');
    }

    // Send message via Baileys
    const result = await sock.sendMessage(jid, { text: messageText });

    // Record in DB
    const displayPhone = formatPhoneDisplay(jid);
    await run(
        'INSERT INTO messages (target, message, type, status, response_data) VALUES (?, ?, ?, ?, ?)',
        [displayPhone, messageText, options.type || 'text', 'sent', JSON.stringify(result)]
    );

    if (ioInstance) {
        ioInstance.emit('wa:message_sent', {
            target: displayPhone,
            message: messageText,
            type: options.type || 'text',
            status: 'sent',
            time: new Date()
        });
    }

    return {
        success: true,
        target: displayPhone,
        messageId: result?.key?.id || null
    };
}

module.exports = {
    connectToWhatsApp,
    getStatus,
    logoutWhatsApp,
    sendMessage,
    formatToJid,
    formatPhoneDisplay
};
