const express = require('express');
const router = express.Router();
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { run, get } = require('../database');

// Configure Google OAuth Strategy
// (Uses environment variables or default mockup/fallback for testing without keys)
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || 'dummy_client_id';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || 'dummy_client_secret';
const CALLBACK_URL = process.env.GOOGLE_CALLBACK_URL || 'https://puts-caroline-duncan-extras.trycloudflare.com/auth/google/callback';

passport.use(new GoogleStrategy({
    clientID: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL: CALLBACK_URL,
    passReqToCallback: true
}, async (req, accessToken, refreshToken, profile, done) => {
    try {
        const email = profile.emails && profile.emails[0] ? profile.emails[0].value : `${profile.id}@google.oauth`;
        const name = profile.displayName || 'Google User';
        const picture = profile.photos && profile.photos[0] ? profile.photos[0].value : '';
        const googleId = profile.id;

        // Check if user exists
        let user = await get('SELECT * FROM users WHERE google_id = ? OR email = ?', [googleId, email]);
        
        if (!user) {
            // Create user instance / separate SMS environment
            const result = await run(
                'INSERT INTO users (email, name, picture, google_id) VALUES (?, ?, ?, ?)',
                [email, name, picture, googleId]
            );
            user = { id: result.id, email, name, picture, google_id: googleId };

            // Create default device and API key for this user instance
            const crypto = require('crypto');
            const defaultToken = 'rapiuw-' + crypto.randomBytes(16).toString('hex');
            await run('INSERT INTO api_keys (user_id, key_name, api_token) VALUES (?, ?, ?)', [user.id, 'Default API Key', defaultToken]);
            
            const expDate = new Date();
            expDate.setFullYear(expDate.getFullYear() + 1);
            await run(`
                INSERT INTO devices (name, number, status, package_name, quota, expired_at, token)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            `, ['Device Utama', '62' + Math.floor(1000000000 + Math.random() * 9000000000), 'disconnect', 'Free', 1000, expDate.toISOString(), defaultToken]);
        }

        return done(null, user);
    } catch (err) {
        return done(err, null);
    }
}));

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const user = await get('SELECT * FROM users WHERE id = ?', [id]);
        done(null, user);
    } catch (err) {
        done(err, null);
    }
});

// Routes
router.get('/google', (req, res, next) => {
    // If Google credentials are not set, provide a mock login for seamless testing
    if (GOOGLE_CLIENT_ID === 'dummy_client_id') {
        return res.redirect('/auth/google/mock-login');
    }
    passport.authenticate('google', { scope: ['profile', 'email'] })(req, res, next);
});

router.get('/google/callback', 
    passport.authenticate('google', { failureRedirect: '/login?error=oauth_failed' }),
    (req, res) => {
        // Successful authentication, redirect to Fonnte-style dashboard
        res.redirect('/dashboard');
    }
);

// Mock login route when GOOGLE_CLIENT_ID is not yet configured by user
router.get('/google/mock-login', async (req, res) => {
    try {
        let user = await get('SELECT * FROM users WHERE email = ?', ['demo.user@rapiuw.sms']);
        if (!user) {
            const result = await run(
                'INSERT INTO users (email, name, picture, google_id) VALUES (?, ?, ?, ?)',
                ['demo.user@rapiuw.sms', 'Demo User (Google OAuth)', 'https://ui-avatars.com/api/?name=Demo+User', 'mock_google_id_123']
            );
            user = { id: result.id, email: 'demo.user@rapiuw.sms', name: 'Demo User' };

            const crypto = require('crypto');
            const defaultToken = 'rapiuw-' + crypto.randomBytes(16).toString('hex');
            await run('INSERT INTO api_keys (user_id, key_name, api_token) VALUES (?, ?, ?)', [user.id, 'Demo API Key', defaultToken]);
            
            const expDate = new Date();
            expDate.setFullYear(expDate.getFullYear() + 1);
            await run(`
                INSERT INTO devices (name, number, status, package_name, quota, expired_at, token)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            `, ['rapi', '6288298674462', 'disconnect', 'Free', 982, expDate.toISOString(), defaultToken]);
        }

        req.logIn(user, (err) => {
            if (err) return res.redirect('/login?error=session_error');
            res.redirect('/dashboard');
        });
    } catch (err) {
        res.redirect('/login?error=mock_failed');
    }
});

router.get('/me', (req, res) => {
    if (!req.isAuthenticated || !req.isAuthenticated()) {
        return res.status(401).json({ status: false, message: 'Not authenticated' });
    }
    res.json({ status: true, user: req.user });
});

router.get('/logout', (req, res) => {
    req.logout((err) => {
        res.redirect('/login');
    });
});

module.exports = router;