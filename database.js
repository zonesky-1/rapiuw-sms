const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
}

const dbPath = path.join(dataDir, 'fonte.db');
const db = new sqlite3.Database(dbPath);

// Promisified helpers
const run = (sql, params = []) => {
    return new Promise((resolve, reject) => {
        db.run(sql, params, function (err) {
            if (err) reject(err);
            else resolve({ id: this.lastID, changes: this.changes });
        });
    });
};

const get = (sql, params = []) => {
    return new Promise((resolve, reject) => {
        db.get(sql, params, (err, row) => {
            if (err) reject(err);
            else resolve(row);
        });
    });
};

const all = (sql, params = []) => {
    return new Promise((resolve, reject) => {
        db.all(sql, params, (err, rows) => {
            if (err) reject(err);
            else resolve(rows);
        });
    });
};

const initDB = async () => {
    await run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            name TEXT,
            picture TEXT,
            google_id TEXT UNIQUE,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    await run(`
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            key_name TEXT NOT NULL,
            api_token TEXT UNIQUE NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    `);

    await run(`
        CREATE TABLE IF NOT EXISTS otps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            otp_code TEXT NOT NULL,
            purpose TEXT DEFAULT 'verification',
            status TEXT DEFAULT 'pending',
            attempts INTEGER DEFAULT 0,
            max_attempts INTEGER DEFAULT 5,
            expires_at DATETIME NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            verified_at DATETIME
        )
    `);

    // Migration helper: alter table safely if columns don't exist
    try {
        const cols = await all("PRAGMA table_info(otps)");
        const colNames = cols.map(c => c.name);
        if (!colNames.includes('attempts')) {
            await run("ALTER TABLE otps ADD COLUMN attempts INTEGER DEFAULT 0");
        }
        if (!colNames.includes('max_attempts')) {
            await run("ALTER TABLE otps ADD COLUMN max_attempts INTEGER DEFAULT 5");
        }
    } catch (e) {
        console.error('[DB] Migration error on otps:', e.message);
    }

    await run(`
        CREATE TABLE IF NOT EXISTS otp_rate_limits (
            target TEXT PRIMARY KEY,
            request_count INTEGER DEFAULT 0,
            window_start DATETIME NOT NULL,
            last_sent DATETIME
        )
    `);

    await run(`
        CREATE TABLE IF NOT EXISTS webhooks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            events TEXT NOT NULL,
            secret TEXT,
            is_active BOOLEAN DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    await run(`
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            message TEXT NOT NULL,
            type TEXT DEFAULT 'text',
            status TEXT DEFAULT 'sent',
            response_data TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    await run(`
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    `);

    await run(`
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            name TEXT NOT NULL DEFAULT 'rapi',
            number TEXT DEFAULT '-',
            status TEXT DEFAULT 'disconnect',
            package_name TEXT DEFAULT 'Free',
            quota INTEGER DEFAULT 1000,
            expired_at DATETIME,
            token TEXT UNIQUE,
            flow_config TEXT DEFAULT '{}',
            ai_config TEXT DEFAULT '{}',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    `);

    // Migration helper for user_id columns on devices, otps, messages
    try {
        const devCols = await all("PRAGMA table_info(devices)");
        if (!devCols.map(c => c.name).includes('user_id')) {
            await run("ALTER TABLE devices ADD COLUMN user_id INTEGER");
        }
        const otpCols = await all("PRAGMA table_info(otps)");
        if (!otpCols.map(c => c.name).includes('user_id')) {
            await run("ALTER TABLE otps ADD COLUMN user_id INTEGER");
        }
        const msgCols = await all("PRAGMA table_info(messages)");
        if (!msgCols.map(c => c.name).includes('user_id')) {
            await run("ALTER TABLE messages ADD COLUMN user_id INTEGER");
        }
    } catch (e) {
        console.error('[DB] Migration error on user_id columns:', e.message);
    }

    // Ensure default device exists for initial display
    const devCount = await get('SELECT COUNT(*) as count FROM devices');
    if (devCount.count === 0) {
        const crypto = require('crypto');
        const defaultDevToken = 'fn-' + crypto.randomBytes(12).toString('hex');
        const expDate = new Date();
        expDate.setFullYear(expDate.getFullYear() + 1);
        await run(`
            INSERT INTO devices (name, number, status, package_name, quota, expired_at, token)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `, ['rapi', '6288298674462', 'disconnect', 'Free', 982, expDate.toISOString(), defaultDevToken]);
    }

    // Check if default API key exists, if not create one
    const defaultKey = await get('SELECT * FROM api_keys LIMIT 1');
    if (!defaultKey) {
        const crypto = require('crypto');
        const defaultToken = 'rapiuw-' + crypto.randomBytes(16).toString('hex');
        await run('INSERT INTO api_keys (key_name, api_token) VALUES (?, ?)', ['Default Key', defaultToken]);
        console.log(`[DB] Created default API Key: ${defaultToken}`);
    }
};

module.exports = {
    db,
    run,
    get,
    all,
    initDB
};
