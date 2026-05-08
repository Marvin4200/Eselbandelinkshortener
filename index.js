'use strict';
require('dotenv').config();

const express = require('express');
const session = require('express-session');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

// ── Config ───────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3010;
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const DISCORD_REDIRECT_URI = process.env.DISCORD_REDIRECT_URI || 'https://go.eselbande.com/auth/callback';
const SESSION_SECRET = process.env.SESSION_SECRET || 'changeme';
const MAX_LINKS_PER_USER = 500;

// ── Database ─────────────────────────────────────────────────────────────────
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

const db = new Database(path.join(dataDir, 'links.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    discord_id TEXT    UNIQUE NOT NULL,
    username   TEXT    NOT NULL,
    avatar     TEXT,
    created_at TEXT    DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS links (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    slug       TEXT    UNIQUE NOT NULL,
    url        TEXT    NOT NULL,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    clicks     INTEGER DEFAULT 0,
    created_at TEXT    DEFAULT (datetime('now'))
  );

  CREATE INDEX IF NOT EXISTS idx_links_user ON links(user_id);
  CREATE INDEX IF NOT EXISTS idx_links_slug ON links(slug);
`);

// ── App ───────────────────────────────────────────────────────────────────────
const app = express();
app.set('trust proxy', 1);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 7 * 24 * 60 * 60 * 1000,
    },
}));
app.use(express.static(path.join(__dirname, 'public')));

// ── Helpers ───────────────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
    if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
    next();
}

function sanitizeSlug(raw) {
    return String(raw || '').replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 40);
}

function isValidUrl(str) {
    try {
        const u = new URL(str);
        return u.protocol === 'http:' || u.protocol === 'https:';
    } catch {
        return false;
    }
}

// ── Auth ──────────────────────────────────────────────────────────────────────
app.get('/auth/login', (req, res) => {
    const params = new URLSearchParams({
        client_id: DISCORD_CLIENT_ID,
        redirect_uri: DISCORD_REDIRECT_URI,
        response_type: 'code',
        scope: 'identify',
    });
    res.redirect(`https://discord.com/oauth2/authorize?${params}`);
});

app.get('/auth/callback', async (req, res) => {
    const { code } = req.query;
    if (!code || typeof code !== 'string') return res.redirect('/?error=missing_code');

    try {
        const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                client_id: DISCORD_CLIENT_ID,
                client_secret: DISCORD_CLIENT_SECRET,
                grant_type: 'authorization_code',
                code,
                redirect_uri: DISCORD_REDIRECT_URI,
            }),
        });
        if (!tokenRes.ok) throw new Error(`Token exchange failed: ${tokenRes.status}`);
        const tokenData = await tokenRes.json();

        const userRes = await fetch('https://discord.com/api/users/@me', {
            headers: { Authorization: `Bearer ${tokenData.access_token}` },
        });
        if (!userRes.ok) throw new Error(`Discord user fetch failed: ${userRes.status}`);
        const du = await userRes.json();

        db.prepare(`
            INSERT INTO users (discord_id, username, avatar)
            VALUES (?, ?, ?)
            ON CONFLICT(discord_id) DO UPDATE SET username = excluded.username, avatar = excluded.avatar
        `).run(String(du.id), String(du.username), du.avatar ? String(du.avatar) : null);

        const user = db.prepare('SELECT * FROM users WHERE discord_id = ?').get(String(du.id));
        req.session.user = { id: user.id, discordId: du.id, username: du.username, avatar: du.avatar };
        res.redirect('/');
    } catch (err) {
        console.error('[AUTH] OAuth error:', err.message);
        res.redirect('/?error=auth_failed');
    }
});

app.get('/auth/logout', (req, res) => {
    req.session.destroy(() => res.redirect('/'));
});

// ── API ───────────────────────────────────────────────────────────────────────
app.get('/api/me', (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
    res.json(req.session.user);
});

app.get('/api/links', requireAuth, (req, res) => {
    const links = db.prepare(
        'SELECT id, slug, url, clicks, created_at FROM links WHERE user_id = ? ORDER BY created_at DESC'
    ).all(req.session.user.id);
    res.json(links);
});

app.post('/api/shorten', requireAuth, (req, res) => {
    const { url, customSlug } = req.body || {};

    if (!url || typeof url !== 'string') return res.status(400).json({ error: 'URL erforderlich' });
    if (!isValidUrl(url)) return res.status(400).json({ error: 'Ungültige URL' });

    // Block self-referential URLs
    try {
        const parsed = new URL(url);
        if (parsed.hostname.endsWith('eselbande.com')) {
            return res.status(400).json({ error: 'eselbande.com URLs können nicht gekürzt werden' });
        }
    } catch { /* already validated above */ }

    const slug = customSlug ? sanitizeSlug(customSlug) : crypto.randomBytes(3).toString('hex');
    if (!slug || slug.length < 1) return res.status(400).json({ error: 'Ungültiger Kurzname' });

    // Reserved slugs
    const reserved = new Set(['auth', 'api', 'dashboard', 'admin', 'static', 'public']);
    if (reserved.has(slug.toLowerCase())) return res.status(400).json({ error: 'Reservierter Kurzname' });

    const count = db.prepare('SELECT COUNT(*) as c FROM links WHERE user_id = ?').get(req.session.user.id);
    if (count.c >= MAX_LINKS_PER_USER) {
        return res.status(429).json({ error: `Link-Limit erreicht (${MAX_LINKS_PER_USER})` });
    }

    try {
        db.prepare('INSERT INTO links (slug, url, user_id) VALUES (?, ?, ?)').run(slug, url, req.session.user.id);
        res.json({ slug, shortUrl: `https://go.eselbande.com/${slug}` });
    } catch (err) {
        if (err.message.includes('UNIQUE')) return res.status(409).json({ error: 'Kurzname bereits vergeben' });
        console.error('[SHORTEN]', err);
        res.status(500).json({ error: 'Interner Fehler' });
    }
});

app.delete('/api/links/:id', requireAuth, (req, res) => {
    const id = parseInt(req.params.id, 10);
    if (!Number.isFinite(id) || id < 1) return res.status(400).json({ error: 'Ungültige ID' });

    const result = db.prepare('DELETE FROM links WHERE id = ? AND user_id = ?').run(id, req.session.user.id);
    if (result.changes === 0) return res.status(404).json({ error: 'Link nicht gefunden' });
    res.json({ success: true });
});

// ── Redirect ──────────────────────────────────────────────────────────────────
const RESERVED_ROUTES = new Set(['auth', 'api']);

app.get('/:slug', (req, res, next) => {
    const { slug } = req.params;
    if (RESERVED_ROUTES.has(slug)) return next();

    const link = db.prepare('SELECT * FROM links WHERE slug = ?').get(slug);
    if (!link) return res.status(404).sendFile(path.join(__dirname, 'public', '404.html'), () => {
        res.status(404).send('<h1>404 – Link nicht gefunden</h1>');
    });

    db.prepare('UPDATE links SET clicks = clicks + 1 WHERE id = ?').run(link.id);
    res.redirect(302, link.url);
});

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => console.log(`[go.eselbande.com] Running on port ${PORT}`));
