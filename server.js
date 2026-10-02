const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const morgan = require('morgan');
const path = require('path');
const session = require('express-session');
const passport = require('passport');
require('dotenv').config({ path: path.join(__dirname, '.admin.env') });
const { initDB, get } = require('./database');
const wa = require('./whatsapp');
const apiRoutes = require('./routes/api');
const googleAuthRoutes = require('./routes/auth_google');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: { origin: '*' }
});

const PORT = process.env.PORT || 3000;

app.use(cors({ origin: process.env.CORS_ORIGINS || '*', credentials: true }));
app.use(express.json({ limit: '50kb', type: 'application/json' }));
app.use(express.urlencoded({ extended: true, limit: '50kb' }));
app.use(morgan('dev'));

// Session & Passport for Google OAuth
app.use(session({
    secret: process.env.SESSION_SECRET || 'rapiuw-sms-secret-key-2026',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));
app.use(passport.initialize());
app.use(passport.session());

// Security headers
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'deny');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    next();
});

// Static dashboard files
app.use(express.static(path.join(__dirname, 'public')));

// Healthcheck endpoint for tunnel/monitoring
app.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        service: 'rapiuw-sms Platform',
        uptime: process.uptime(),
        timestamp: new Date().toISOString()
    });
});

// Login page
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Dashboard page
app.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Google OAuth routes
app.use('/auth', googleAuthRoutes);

// API routes
app.use('/api', apiRoutes);

// Socket.io connection handling
io.on('connection', (socket) => {
    // Send current status immediately on connection
    socket.emit('wa:status', wa.getStatus());

    socket.on('disconnect', () => {
        // Socket disconnected
    });
});

async function startServer() {
    try {
        await initDB();
        console.log('[App] Database ready.');

        server.listen(PORT, '0.0.0.0', () => {
            console.log(`[App] Fonte OTP Platform listening on http://0.0.0.0:${PORT}`);
        });

        // Initialize WhatsApp connection in background
        wa.connectToWhatsApp(io);
    } catch (err) {
        console.error('[App] Failed to start server:', err);
        process.exit(1);
    }
}

startServer();
