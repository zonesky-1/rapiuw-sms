# 📲 Rapiuw SMS & WhatsApp Gateway Platform

Platform gateway pengiriman pesan instan dan verifikasi OTP aman yang menggabungkan integrasi WhatsApp Web otomatis dengan RESTful API berkinerja tinggi.

---

## ✨ Fitur Unggulan

- **WhatsApp Web Gateway**: Koneksi multi-sesi WhatsApp tanpa ketergantungan API berbayar menggunakan protokol Baileys.
- **Generator & Validator OTP**: Pembuatan kode OTP aman dengan batas kedaluwarsa (TTL) dan verifikasi instan.
- **Dashboard Admin Terpadu**: Antarmuka web untuk memantau status sesi QR Code, log pesan masuk, dan riwayat pengiriman.
- **Google OAuth 2.0**: Otentikasi pengelola yang aman menggunakan integrasi akun Google (`routes/auth_google.js`).
- **Penyimpanan Database SQLite**: Database lokal terenkripsi di `data/` tanpa perlu setup server database berat.

---

## 🛠️ Stack Teknologi

- **Backend Runtime**: Node.js & Express.js
- **WhatsApp Engine**: `@whiskeysockets/baileys`
- **Database**: SQLite3 (`database.js`)
- **Otentikasi**: Passport.js Google Strategy

---

## 🚀 Panduan Memulai

```bash
# 1. Install dependensi
npm install

# 2. Konfigurasi kredensial pada .admin.env
PORT=3000
GOOGLE_CLIENT_ID=your_client_id
GOOGLE_CLIENT_SECRET=your_client_secret

# 3. Jalankan server gateway
node server.js
```
Akses dashboard di browser melalui: `http://localhost:3000`
