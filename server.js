const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const morgan = require('morgan');
const path = require('path');
const { initDB, get } = require('./database');
const wa = require('./whatsapp');
const apiRoutes = require('./routes/api');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: { origin: '*' }
});

const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(morgan('dev'));

// Static dashboard files
app.use(express.static(path.join(__dirname, 'public')));

// Healthcheck endpoint for tunnel/monitoring
app.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        service: 'Fonte OTP Gateway Platform',
        uptime: process.uptime(),
        timestamp: new Date().toISOString()
    });
});

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
