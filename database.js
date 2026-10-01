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
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_name TEXT NOT NULL,
            api_token TEXT UNIQUE NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    await run(`
        CREATE TABLE IF NOT EXISTS otps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            otp_code TEXT NOT NULL,
            purpose TEXT DEFAULT 'verification',
            status TEXT DEFAULT 'pending', -- pending, verified, expired, failed
            expires_at DATETIME NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            verified_at DATETIME
        )
    `);

    await run(`
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            message TEXT NOT NULL,
            type TEXT DEFAULT 'text', -- otp, text, media, broadcast
            status TEXT DEFAULT 'sent', -- pending, sent, delivered, failed
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
