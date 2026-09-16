'use strict';

const express  = require('express');
const path     = require('path');
const fs       = require('fs');
const crypto   = require('crypto');
const dns      = require('dns').promises;
const { exec } = require('child_process');

const helmet        = require('helmet');
const session       = require('express-session');
const bcrypt        = require('bcrypt');
const Database      = require('better-sqlite3');
const { RateLimiterMemory } = require('rate-limiter-flexible');

// ─── Data directory (persists user accounts and sessions) ─────────────────────
const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

// ─── SQLite — users + sessions ────────────────────────────────────────────────
const db = new Database(path.join(DATA_DIR, 'users.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT    UNIQUE NOT NULL COLLATE NOCASE,
    hash       TEXT    NOT NULL,
    is_admin   INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
  );
  CREATE TABLE IF NOT EXISTS sessions (
    sid    TEXT    PRIMARY KEY,
    data   TEXT    NOT NULL,
    expire INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS secrets (
    user_id    INTEGER NOT NULL,
    key_name   TEXT    NOT NULL,
    ciphertext TEXT    NOT NULL,
    iv         TEXT    NOT NULL,
    PRIMARY KEY (user_id, key_name),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS user_data (
    user_id    INTEGER PRIMARY KEY,
    entries    TEXT    NOT NULL DEFAULT '[]',
    settings   TEXT    NOT NULL DEFAULT '{}',
    view       TEXT    NOT NULL DEFAULT 'grid',
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
`);

// Migration: add is_admin column to existing DBs that predate this feature
try { db.exec('ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0'); } catch {}
// Ensure the earliest-created user is always admin
db.prepare('UPDATE users SET is_admin = 1 WHERE id = (SELECT MIN(id) FROM users)').run();

// Purge expired sessions every minute
setInterval(() => {
  db.prepare('DELETE FROM sessions WHERE expire < ?').run(Date.now());
}, 60_000);

// ─── SQLite session store ─────────────────────────────────────────────────────
class SQLiteStore extends session.Store {
  get(sid, cb) {
    try {
      const row = db.prepare('SELECT data, expire FROM sessions WHERE sid = ?').get(sid);
      if (!row || row.expire < Date.now()) return cb(null, null);
      cb(null, JSON.parse(row.data));
    } catch (e) { cb(e); }
  }
  set(sid, sess, cb) {
    try {
      const expire = sess.cookie?.expires
        ? new Date(sess.cookie.expires).getTime()
        : Date.now() + SESSION_TTL_MS;
      db.prepare(
        'INSERT OR REPLACE INTO sessions (sid, data, expire) VALUES (?, ?, ?)'
      ).run(sid, JSON.stringify(sess), expire);
      cb(null);
    } catch (e) { cb(e); }
  }
  destroy(sid, cb) {
    try { db.prepare('DELETE FROM sessions WHERE sid = ?').run(sid); cb(null); }
    catch (e) { cb(e); }
  }
  touch(sid, sess, cb) {
    try {
      const expire = sess.cookie?.expires
        ? new Date(sess.cookie.expires).getTime()
        : Date.now() + SESSION_TTL_MS;
      db.prepare('UPDATE sessions SET expire = ? WHERE sid = ?').run(expire, sid);
      cb(null);
    } catch (e) { cb(e); }
  }
}

// ─── Session secret (generated once, then persisted) ─────────────────────────
const SECRET_FILE = path.join(DATA_DIR, 'session.secret');
let SESSION_SECRET;
if (fs.existsSync(SECRET_FILE)) {
  SESSION_SECRET = fs.readFileSync(SECRET_FILE, 'utf8').trim();
} else {
  SESSION_SECRET = crypto.randomBytes(64).toString('hex');
  fs.writeFileSync(SECRET_FILE, SESSION_SECRET, { mode: 0o600 });
}

const SESSION_TTL_MS = (parseInt(process.env.SESSION_IDLE_MINUTES, 10) || 60) * 60 * 1000; // default 60 minutes idle timeout
const ABSOLUTE_SESSION_MAX_MS = 7 * 24 * 60 * 60 * 1000; // 7 days absolute maximum session lifetime
const BCRYPT_ROUNDS  = 12;
// HTTPS is required by default. Set VLT_HTTPS=false to allow plain HTTP (e.g. during local dev).
const httpsRequired  = process.env.VLT_HTTPS !== 'false';

// ─── Rate limiters ─────────────────────────────────────────────────────────────
// Login: 10 attempts per 15 min per IP
const loginLimiter = new RateLimiterMemory({
  points: 10,
  duration: 15 * 60,
});

// Setup: 5 attempts per 15 min per IP
const setupLimiter = new RateLimiterMemory({
  points: 5,
  duration: 15 * 60,
});

// General API / Proxy limiter: 120 requests per minute per IP
const apiLimiter = new RateLimiterMemory({
  points: 120,
  duration: 60,
});

async function rateLimitApi(req, res, next) {
  try {
    await apiLimiter.consume(req.ip);
    next();
  } catch {
    res.status(429).json({ error: 'Too many requests. Please slow down.' });
  }
}

// ─── Express app ─────────────────────────────────────────────────────────────
const app = express();

// Trust the first reverse-proxy (needed for req.secure and correct IP with X-Forwarded-For)
app.set('trust proxy', 1);

// Redirect HTTP → HTTPS when HTTPS is required
if (httpsRequired) {
  app.use((req, res, next) => {
    if (!req.secure) {
      return res.redirect(301, 'https://' + req.hostname + req.originalUrl);
    }
    next();
  });
}

// Industry-standard security headers via Helmet
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", 'https://static.cloudflareinsights.com'],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com'],
      imgSrc: ["'self'", 'data:', 'blob:', 'https:'],
      connectSrc: [
        "'self'",
        'https://api.mangadex.org',
        'https://graphql.anilist.co',
        'https://api.mangaupdates.com',
        'https://nhentai.net',
        'https://hitomi.la',
        'https://cdn.atsu.moe',
        'https://atsu.moe',
        'https://cloudflareinsights.com'
      ],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: false,
  crossOriginOpenerPolicy: false,
  dnsPrefetchControl: { allow: false },
  frameguard: { action: 'deny' },
  hsts: httpsRequired ? { maxAge: 31536000, includeSubDomains: true, preload: true } : false,
  noSniff: true,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
}));

// Body parsing
app.use(express.json({ limit: '10mb' }));

// Session middleware
app.use(session({
  secret: SESSION_SECRET,
  name: 'vlt.sid',
  resave: false,
  saveUninitialized: false,
  rolling: true,              // reset 15-min idle window on every request
  store: new SQLiteStore(),
  cookie: {
    httpOnly: true,           // JS cannot read the cookie
    sameSite: 'strict',       // blocks CSRF via cross-site requests
    secure: httpsRequired,     // false only when VLT_HTTPS=false
    maxAge: SESSION_TTL_MS,
  },
}));

// ─── Auth helpers ─────────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const isApi = (req.path && req.path.startsWith('/api/')) || (req.originalUrl && req.originalUrl.startsWith('/api/'));
  if (req.session?.userId) {
    // Enforce absolute session lifetime (OWASP ASVS 3.3)
    if (req.session.createdAt && (Date.now() - req.session.createdAt > ABSOLUTE_SESSION_MAX_MS)) {
      req.session.destroy(() => {});
      if (!isApi && req.accepts('html')) return res.redirect('/login');
      return res.status(401).json({ error: 'Session expired. Please log in again.', sessionExpired: true });
    }
    const user = db.prepare('SELECT id FROM users WHERE id = ?').get(req.session.userId);
    if (user) return next();
    req.session.destroy(() => {});
  }
  if (!isApi && req.accepts('html')) return res.redirect('/login');
  res.status(401).json({ error: 'Unauthenticated', sessionExpired: true });
}

function setupRequired() {
  return db.prepare('SELECT COUNT(*) AS c FROM users').get().c === 0;
}

// ─── Auth API ─────────────────────────────────────────────────────────────────

// Status check — used by login.html to detect setup mode and auth state
app.get('/api/auth/status', (req, res) => {
  const userId = req.session?.userId ?? null;
  let isAdmin = false;
  let authenticated = false;
  let username = null;
  if (userId) {
    const row = db.prepare('SELECT id, username, is_admin FROM users WHERE id = ?').get(userId);
    if (row) {
      authenticated = true;
      isAdmin = !!row.is_admin;
      username = row.username;
    } else {
      req.session.destroy(() => {});
    }
  }
  res.json({
    authenticated,
    userId: authenticated ? userId : null,
    username,
    isAdmin,
    setupRequired: setupRequired(),
  });
});

// First-run setup — only works while no users exist
app.post('/api/auth/setup', async (req, res) => {
  try {
    await setupLimiter.consume(req.ip);
  } catch {
    return res.status(429).json({ error: 'Too many setup attempts. Try again in 15 minutes.' });
  }

  if (!setupRequired()) {
    return res.status(403).json({ error: 'Setup already complete.' });
  }
  const { username, password } = req.body ?? {};
  if (
    typeof username !== 'string' || username.trim().length < 1 || username.trim().length > 64 ||
    typeof password !== 'string' || password.length < 8 || password.length > 72
  ) {
    return res.status(400).json({ error: 'Invalid username or password (min 8, max 72 chars).' });
  }
  const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
  try {
    const row = db.prepare(
      'INSERT INTO users (username, hash, is_admin) VALUES (?, ?, 1) RETURNING id, username'
    ).get(username.trim(), hash);
    req.session.regenerate((err) => {
      if (err) return res.status(500).json({ error: 'Session error.' });
      req.session.userId    = row.id;
      req.session.username  = row.username;
      req.session.createdAt = Date.now();
      res.json({ ok: true });
    });
  } catch (e) {
    if (e.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(409).json({ error: 'Username already taken.' });
    }
    res.status(500).json({ error: 'Server error.' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  // Rate limit by IP
  try {
    await loginLimiter.consume(req.ip);
  } catch {
    return res.status(429).json({ error: 'Too many login attempts. Try again in 15 minutes.' });
  }

  const { username, password } = req.body ?? {};
  if (typeof username !== 'string' || typeof password !== 'string' || password.length > 72) {
    return res.status(400).json({ error: 'Invalid request.' });
  }

  const user = db.prepare('SELECT id, username, hash FROM users WHERE username = ?').get(username.trim());

  // Always run bcrypt to prevent timing attacks even on unknown usernames
  const dummyHash = '$2b$12$invalidhashpaddingtopreventimingtattack000000000000000000';
  const match = await bcrypt.compare(password, user ? user.hash : dummyHash);

  if (!user || !match) {
    return res.status(401).json({ error: 'Invalid username or password.' });
  }

  // Session fixation prevention — regenerate session ID on login
  req.session.regenerate((err) => {
    if (err) return res.status(500).json({ error: 'Session error.' });
    req.session.userId    = user.id;
    req.session.username  = user.username;
    req.session.createdAt = Date.now();
    res.json({ ok: true });
  });
});

// Logout
app.post('/api/auth/logout', (req, res) => {
  req.session.destroy((err) => {
    res.clearCookie('vlt.sid');
    res.json({ ok: true });
  });
});

// ─── Admin middleware ─────────────────────────────────────────────────────────
function requireAdmin(req, res, next) {
  if (!req.session?.userId) return res.status(401).json({ error: 'Unauthenticated' });
  const row = db.prepare('SELECT is_admin FROM users WHERE id = ?').get(req.session.userId);
  if (!row?.is_admin) return res.status(403).json({ error: 'Admin access required.' });
  next();
}

// ─── User management (admin only) ────────────────────────────────────────────

// List all users
app.get('/api/auth/users', requireAuth, requireAdmin, (req, res) => {
  const users = db.prepare(
    'SELECT id, username, is_admin, created_at FROM users ORDER BY created_at ASC'
  ).all();
  res.json({ users: users.map(u => ({ id: u.id, username: u.username, isAdmin: !!u.is_admin, createdAt: u.created_at })) });
});

// Create a new user account
app.post('/api/auth/users', requireAuth, requireAdmin, async (req, res) => {
  const { username, password } = req.body ?? {};
  if (
    typeof username !== 'string' || username.trim().length < 1 || username.trim().length > 64 ||
    typeof password !== 'string' || password.length < 8 || password.length > 72
  ) {
    return res.status(400).json({ error: 'Invalid username or password (min 8, max 72 chars).' });
  }
  const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
  try {
    const row = db.prepare(
      'INSERT INTO users (username, hash) VALUES (?, ?) RETURNING id, username'
    ).get(username.trim(), hash);
    res.json({ ok: true, user: { id: row.id, username: row.username } });
  } catch (e) {
    if (e.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(409).json({ error: 'Username already taken.' });
    }
    res.status(500).json({ error: 'Server error.' });
  }
});

// Delete a user account (cannot delete yourself or the primary admin)
app.delete('/api/auth/users/:id', requireAuth, requireAdmin, (req, res) => {
  const targetId = parseInt(req.params.id, 10);
  if (!Number.isFinite(targetId)) return res.status(400).json({ error: 'Invalid user ID.' });
  if (targetId === req.session.userId) {
    return res.status(400).json({ error: 'You cannot delete your own account.' });
  }
  // Protect the primary admin account from deletion
  const minUser = db.prepare('SELECT MIN(id) AS min_id FROM users').get();
  if (targetId === minUser?.min_id) {
    return res.status(400).json({ error: 'The primary admin account cannot be deleted.' });
  }
  // Invalidate any active sessions belonging to the deleted user
  try {
    db.prepare(`
      DELETE FROM sessions
      WHERE data LIKE '%"userId":' || ? || ',%'
         OR data LIKE '%"userId":' || ? || '}'
    `).run(targetId, targetId);
  } catch {}

  db.prepare('DELETE FROM secrets WHERE user_id = ?').run(targetId);
  db.prepare('DELETE FROM user_data WHERE user_id = ?').run(targetId);
  const result = db.prepare('DELETE FROM users WHERE id = ?').run(targetId);
  if (result.changes === 0) return res.status(404).json({ error: 'User not found.' });
  res.json({ ok: true });
});

// ─── Server-side secrets (API keys stored encrypted in DB) ───────────────────
// Keys are encrypted with AES-256-GCM using a per-user key derived from the
// session secret + user ID.  The plaintext never leaves the server.

const ALGO = 'aes-256-gcm';

function _deriveUserKey(userId) {
  // 32-byte key: HMAC-SHA256(session_secret, user_id)
  return crypto.createHmac('sha256', SESSION_SECRET).update(String(userId)).digest();
}

function _encryptSecret(userId, plaintext) {
  const key = _deriveUserKey(userId);
  const iv  = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGO, key, iv);
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  // store ciphertext + auth tag together
  return {
    ciphertext: Buffer.concat([ct, tag]).toString('hex'),
    iv: iv.toString('hex'),
  };
}

function _decryptSecret(userId, ciphertextHex, ivHex) {
  const key  = _deriveUserKey(userId);
  const iv   = Buffer.from(ivHex, 'hex');
  const data = Buffer.from(ciphertextHex, 'hex');
  const tag  = data.slice(-16);
  const ct   = data.slice(0, -16);
  const decipher = crypto.createDecipheriv(ALGO, key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
}

const ALLOWED_SECRET_NAMES = new Set(['nh-key']);

// Save a secret (value sent from client, encrypted on server, never stored plain)
app.post('/api/secrets/:name', requireAuth, (req, res) => {
  const { name } = req.params;
  if (!ALLOWED_SECRET_NAMES.has(name)) return res.status(400).json({ error: 'Unknown secret name.' });
  const { value } = req.body ?? {};
  if (typeof value !== 'string' || value.trim().length === 0) {
    return res.status(400).json({ error: 'Value is required.' });
  }
  try {
    const { ciphertext, iv } = _encryptSecret(req.session.userId, value.trim());
    db.prepare(
      'INSERT OR REPLACE INTO secrets (user_id, key_name, ciphertext, iv) VALUES (?, ?, ?, ?)'
    ).run(req.session.userId, name, ciphertext, iv);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Failed to save secret.' });
  }
});

// Delete a secret
app.delete('/api/secrets/:name', requireAuth, (req, res) => {
  const { name } = req.params;
  if (!ALLOWED_SECRET_NAMES.has(name)) return res.status(400).json({ error: 'Unknown secret name.' });
  db.prepare('DELETE FROM secrets WHERE user_id = ? AND key_name = ?').run(req.session.userId, name);
  res.json({ ok: true });
});

// Check if a secret is saved (never returns the value)
app.get('/api/secrets/:name/status', requireAuth, (req, res) => {
  const { name } = req.params;
  if (!ALLOWED_SECRET_NAMES.has(name)) return res.status(400).json({ error: 'Unknown secret name.' });
  const row = db.prepare('SELECT 1 FROM secrets WHERE user_id = ? AND key_name = ?').get(req.session.userId, name);
  res.json({ saved: !!row });
});

// Helper used by the proxy to inject a stored secret value
function getSecretValue(userId, name) {
  const row = db.prepare('SELECT ciphertext, iv FROM secrets WHERE user_id = ? AND key_name = ?').get(userId, name);
  if (!row) return null;
  try { return _decryptSecret(userId, row.ciphertext, row.iv); } catch { return null; }
}

// ─── User Library & Settings Data (persisted in SQLite) ───────────────────────
app.get('/api/data', requireAuth, (req, res) => {
  const row = db.prepare('SELECT entries, settings, view, updated_at FROM user_data WHERE user_id = ?').get(req.session.userId);
  if (!row) {
    return res.json({ entries: [], settings: {}, view: 'grid', updatedAt: 0, isNew: true });
  }
  let entries = [];
  let settings = {};
  try { entries = JSON.parse(row.entries || '[]'); } catch {}
  try { settings = JSON.parse(row.settings || '{}'); } catch {}
  res.json({
    entries,
    settings,
    view: row.view || 'grid',
    updatedAt: row.updated_at,
    isNew: false,
  });
});

function sanitizeSettings(obj) {
  if (typeof obj !== 'object' || obj === null || Array.isArray(obj)) return {};
  const clean = {};
  for (const [k, v] of Object.entries(obj)) {
    if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
    if (typeof v === 'boolean' || typeof v === 'string' || typeof v === 'number') {
      clean[k] = v;
    }
  }
  return clean;
}

function sanitizeServerEntry(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const id = typeof raw.id === 'string' && /^[a-zA-Z0-9_-]{1,64}$/.test(raw.id)
    ? raw.id
    : crypto.randomBytes(8).toString('hex');
  const title = String(raw.title || '').trim().slice(0, 500);
  if (!title) return null;
  const author = String(raw.author || '').trim().slice(0, 300);
  const rawLink = String(raw.link || '').trim();
  const link = /^https?:\/\//i.test(rawLink) ? rawLink.slice(0, 2000) : '';
  const rawThumb = String(raw.thumb || '').trim();
  const thumb = (/^(?:https?:\/\/|\/api\/proxy-img\?|data:image\/|blob:)/i.test(rawThumb)) ? rawThumb.slice(0, 4000) : '';
  const validStatuses = ['reading', 'planning', 'completed', 'paused', 'rereading', 'dropped'];
  const status = validStatuses.includes(raw.status) ? raw.status : 'planning';
  const notes = String(raw.notes || '').trim().slice(0, 5000);
  const validProgressTypes = ['chapters', 'volumes', 'pages'];
  const progressType = validProgressTypes.includes(raw.progressType) ? raw.progressType : 'chapters';
  const toIntOrNull = v => (v != null && !isNaN(Number(v)) && Number(v) >= 0) ? Math.min(Math.floor(Number(v)), 999999) : null;
  const tags = Array.isArray(raw.tags)
    ? raw.tags.map(t => String(t || '').trim().slice(0, 100)).filter(Boolean).slice(0, 100)
    : [];
  const altTitles = Array.isArray(raw.altTitles)
    ? raw.altTitles.map(t => String(t || '').trim().slice(0, 500)).filter(Boolean).slice(0, 50)
    : [];
  const dateAdded = (typeof raw.dateAdded === 'number' && raw.dateAdded > 0) ? raw.dateAdded : Date.now();

  return {
    id,
    title,
    author,
    link,
    thumb,
    status,
    notes,
    progressType,
    chaptersRead: toIntOrNull(raw.chaptersRead),
    chaptersTotal: toIntOrNull(raw.chaptersTotal),
    volumesRead: toIntOrNull(raw.volumesRead),
    volumesTotal: toIntOrNull(raw.volumesTotal),
    pagesRead: toIntOrNull(raw.pagesRead),
    pagesTotal: toIntOrNull(raw.pagesTotal),
    tags,
    altTitles,
    dateAdded,
  };
}

const handleSaveUserData = (req, res) => {
  const { entries, settings, view } = req.body ?? {};
  if (entries !== undefined && !Array.isArray(entries)) {
    return res.status(400).json({ error: 'Entries must be an array.' });
  }
  if (settings !== undefined && (typeof settings !== 'object' || settings === null || Array.isArray(settings))) {
    return res.status(400).json({ error: 'Settings must be an object.' });
  }
  if (view !== undefined && (typeof view !== 'string' || !['list', 'compact', 'grid', 'links'].includes(view))) {
    return res.status(400).json({ error: 'Invalid view value.' });
  }

  const existing = db.prepare('SELECT entries, settings, view FROM user_data WHERE user_id = ?').get(req.session.userId);
  const newEntries = entries !== undefined
    ? JSON.stringify(entries.map(sanitizeServerEntry).filter(Boolean))
    : (existing?.entries || '[]');
  const newSettings = settings !== undefined ? JSON.stringify(sanitizeSettings(settings)) : (existing?.settings || '{}');
  const newView = view !== undefined ? view : (existing?.view || 'grid');
  const now = Math.floor(Date.now() / 1000);

  db.prepare(`
    INSERT INTO user_data (user_id, entries, settings, view, updated_at)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(user_id) DO UPDATE SET
      entries = excluded.entries,
      settings = excluded.settings,
      view = excluded.view,
      updated_at = excluded.updated_at
  `).run(req.session.userId, newEntries, newSettings, newView, now);

  res.json({ ok: true, updatedAt: now });
};

app.put('/api/data', requireAuth, handleSaveUserData);
app.post('/api/data', requireAuth, handleSaveUserData);

// ─── Public routes ───────────────────────────────────────────────────────────
app.get(['/favicon.svg', '/favicon.ico'], (req, res) => {
  res.sendFile(path.join(__dirname, 'favicon.svg'));
});

// Serve login page (public)
app.get('/login', (req, res) => {
  if (req.session?.userId) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'login.html'));
});

// ─── All subsequent routes require authentication ─────────────────────────────
app.use(requireAuth);

// Serve the main app explicitly (never expose raw directory contents or sensitive files)
app.get(['/', '/index.html'], (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ─── HCDN Anti-bot Solver ─────────────────────────────────────────────────────
// Transparently solves HCDN JS proof-of-work challenges (used on sites like apcomics.org).
// Flow: GET page → GET /hcdn-cgi/jschallenge (gets cjs/challengeUrl) →
//       SHA-256(cjs) → POST answer → collect bypass cookies → GET real page.

function isHcdnPage(html) {
  return typeof html === 'string' && html.includes('/hcdn-cgi/jschallenge');
}

function isCloudflarePage(html) {
  if (!html || typeof html !== 'string') return false;
  return html.includes('__cf_chl_opt') ||
         html.includes('cf-browser-verification') ||
         html.includes('cloudflare.com/cdn-cgi/challenge') ||
         /window\._cf_chl_ctx\b/.test(html) ||
         /<title>[^<]*Just a moment/i.test(html) ||
         /Checking your browser before accessing/i.test(html);
}

async function solveHcdnChallenge(targetUrl, baseHeaders) {
  const origin = new URL(targetUrl).origin;
  const jar = {};

  function harvest(resp) {
    const cookies = typeof resp.headers.getSetCookie === 'function'
      ? resp.headers.getSetCookie()
      : (resp.headers.get('set-cookie') ? [resp.headers.get('set-cookie')] : []);
    for (const c of cookies) {
      const part = c.split(';')[0].trim();
      const eq = part.indexOf('=');
      if (eq > 0) jar[part.slice(0, eq).trim()] = part.slice(eq + 1).trim();
    }
  }

  function cookieStr() {
    return Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; ');
  }

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 20000);

  try {
    const h = { ...baseHeaders };

    // 1. Initial request — harvest any session cookies from the challenge page
    const initResp = await fetch(targetUrl, { signal: ctrl.signal, headers: { ...h, Cookie: cookieStr() } });
    harvest(initResp);

    // 2. Load the challenge script — sets cjs, jsChallengeUrl, uri
    const scriptResp = await fetch(`${origin}/hcdn-cgi/jschallenge`, {
      signal: ctrl.signal,
      headers: { ...h, Cookie: cookieStr(), Referer: targetUrl },
    });
    harvest(scriptResp);
    if (!scriptResp.ok) return null;

    const scriptText = await scriptResp.text();
    const cjs          = scriptText.match(/const cjs = '([^']+)'/)?.[1];
    const challengePath = scriptText.match(/const jsChallengeUrl = '([^']+)'/)?.[1];
    if (!cjs || !challengePath) return null;
    const challengeUrl = challengePath.startsWith('/') ? `${origin}${challengePath}` : challengePath;

    // 3. Compute SHA-256 proof-of-work (mirrors browser bbc6cf0(cjs))
    const hash = crypto.createHash('sha256').update(cjs).digest('hex');

    // 4. Submit the answer after a short delay (challenge JS waits 3 s; 700 ms is enough)
    await new Promise(r => setTimeout(r, 700));
    const validateResp = await fetch(challengeUrl, {
      signal: ctrl.signal,
      method: 'POST',
      headers: {
        ...h,
        Cookie: cookieStr(),
        Referer: targetUrl,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: `challenge=${hash}`,
    });
    harvest(validateResp);
    if (!validateResp.ok) return null;

    // 5. Fetch the real page using the bypass cookies
    const finalResp = await fetch(targetUrl, { signal: ctrl.signal, headers: { ...h, Cookie: cookieStr() } });
    harvest(finalResp);
    const html = await finalResp.text();
    return isHcdnPage(html) ? null : html; // null = still blocked
  } finally {
    clearTimeout(timer);
  }
}

// ─── SSRF Protection with DNS Resolution (Anti-DNS Rebinding) ────────────────
function isPrivateIp(ip) {
  const ipv4Match = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4Match) {
    const [_, a, b, c, d] = ipv4Match.map(Number);
    if (a > 255 || b > 255 || c > 255 || d > 255) return true;
    if (a === 0 || a === 127 || a === 10) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 169 && b === 254) return true;
    if (a === 255 && b === 255 && c === 255 && d === 255) return true;
    return false;
  }
  const clean = ip.toLowerCase().replace(/^\[|\]$/g, '');
  if (clean.startsWith('::ffff:')) {
    const rest = clean.slice(7);
    if (rest.includes('.')) return isPrivateIp(rest);
    const parts = rest.split(':');
    if (parts.length === 2) {
      const p1 = parseInt(parts[0], 16);
      const p2 = parseInt(parts[1], 16);
      if (!isNaN(p1) && !isNaN(p2)) {
        const ip4 = `${(p1 >> 8) & 0xff}.${p1 & 0xff}.${(p2 >> 8) & 0xff}.${p2 & 0xff}`;
        return isPrivateIp(ip4);
      }
    }
    return true; // Malformed IPv4-mapped IPv6, reject safely
  }
  if (
    clean === '::1' ||
    clean === '::' ||
    clean.startsWith('fc') ||
    clean.startsWith('fd') ||
    clean.startsWith('fe80')
  ) {
    return true;
  }
  return false;
}

async function isSafeUrl(rawUrl) {
  try {
    const parsed = new URL(rawUrl);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return false;
    }
    const hostname = parsed.hostname.toLowerCase();

    // Block localhost, local/internal domains
    if (
      hostname === 'localhost' ||
      hostname.endsWith('.localhost') ||
      hostname.endsWith('.local') ||
      hostname.endsWith('.internal')
    ) {
      return false;
    }

    const cleanHost = hostname.replace(/^\[|\]$/g, '');
    if (isPrivateIp(cleanHost)) {
      return false;
    }

    // Resolve DNS to verify domain does not resolve to a private/loopback/metadata IP
    try {
      const records = await dns.lookup(cleanHost, { all: true });
      for (const rec of records) {
        if (isPrivateIp(rec.address)) {
          return false;
        }
      }
    } catch {
      return false; // Cannot resolve DNS
    }

    return true;
  } catch {
    return false;
  }
}

// ─── CORS Proxy ───────────────────────────────────────────────────────────────
// Lets the browser fetch any URL server-side, avoiding CORS restrictions.
// Automatically solves HCDN JS challenges before returning content.
app.get('/api/proxy', rateLimitApi, async (req, res) => {
  const url = req.query.url;
  if (typeof url !== 'string' || !(await isSafeUrl(url))) {
    return res.status(400).send('Invalid or restricted URL');
  }
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 12000);
    const headers = {
      'User-Agent':
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
        '(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
      Accept:
        'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
      'Accept-Language': 'en-US,en;q=0.9',
    };
    const resp = await fetch(url, { signal: ctrl.signal, headers });
    clearTimeout(timer);
    const text = await resp.text();

    // Auto-solve HCDN challenge if detected
    if (isHcdnPage(text)) {
      const solved = await solveHcdnChallenge(url, headers).catch(() => null);
      if (solved) {
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        return res.send(solved);
      }
    }

    if (isCloudflarePage(text)) {
      res.setHeader('X-Cloudflare-Detected', '1');
    }

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.status(resp.status).send(text);
  } catch (e) {
    if (e.name === 'AbortError') return res.status(504).send('Request timed out');
    res.status(502).send('Upstream request failed');
  }
});

// Image proxy — returns binary with correct Content-Type (used for cover caching)
app.get('/api/proxy-img', rateLimitApi, async (req, res) => {
  const url = req.query.url;
  if (typeof url !== 'string' || !(await isSafeUrl(url))) return res.status(400).send('Invalid or restricted URL');
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 15000);
    const resp = await fetch(url, {
      signal: ctrl.signal,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
        'Accept': 'image/avif,image/webp,image/apng,image/*,*/*;q=0.8',
        // MangaDex CDN checks Referer against mangadex.org, not uploads.mangadex.org
        // Hitomi CDN checks Referer against hitomi.la, not the CDN subdomain
        // Atsu.moe CDN checks Referer against atsu.moe, not cdn.atsu.moe
        'Referer': /uploads\.mangadex\.org/i.test(url) ? 'https://mangadex.org/'
                 : /gold-usergeneratedcontent\.net/i.test(url) ? 'https://hitomi.la/'
                 : /cdn\.atsu\.moe/i.test(url) ? 'https://atsu.moe/'
                 : new URL(url).origin + '/',
      },
    });
    clearTimeout(timer);
    if (!resp.ok) return res.status(resp.status).send('Upstream error');
    const ct = resp.headers.get('content-type') || 'application/octet-stream';
    res.setHeader('Content-Type', ct);
    res.setHeader('Cache-Control', 'public, max-age=86400');
    const buf = await resp.arrayBuffer();
    res.send(Buffer.from(buf));
  } catch (e) {
    if (e.name === 'AbortError') return res.status(504).send('Request timed out');
    res.status(502).send(e.message);
  }
});

// ─── Hitomi.la Gallery (SNI-bypass endpoint) ─────────────────────────────────
// GET /api/hitomi/:id — fetches ltn.gold-usergeneratedcontent.net/galleries/{id}.js server-side.
// hitomi.la moved its resource CDN to gold-usergeneratedcontent.net; SNI blocking
// requires https.request with servername:'' to bypass.  Returns normalised JSON.
app.get('/api/hitomi/:id', rateLimitApi, async (req, res) => {
  const { id } = req.params;
  if (!/^\d+$/.test(id)) return res.status(400).json({ error: 'Invalid ID' });
  const https = require('https');
  try {
    const raw = await new Promise((resolve, reject) => {
      const options = {
        hostname: 'ltn.gold-usergeneratedcontent.net',
        port: 443,
        path: `/galleries/${id}.js`,
        method: 'GET',
        servername: '',          // bypass SNI blocking
        rejectUnauthorized: false,
        headers: {
          'Referer': 'https://hitomi.la/',
          'User-Agent': 'Mozilla/5.0 (compatible)',
        },
        timeout: 15000,
      };
      const request = https.request(options, r => {
        let data = '';
        r.on('data', c => data += c);
        r.on('end', () => {
          if (r.statusCode === 404) return reject(Object.assign(new Error('not found'), { status: 404 }));
          if (r.statusCode !== 200) return reject(new Error(`HTTP ${r.statusCode}`));
          resolve(data);
        });
      });
      request.on('error', reject);
      request.on('timeout', () => { request.destroy(); reject(new Error('timeout')); });
      request.end();
    });

    // Response is: `var galleryinfo = {...};`  (18-char prefix, per node-hitomi)
    const info = JSON.parse(raw.slice(18));

    const rawTitle = info.title || info.japanese_title || '';
    const altSet = new Set();
    if (info.title) altSet.add(info.title);
    if (info.japanese_title) altSet.add(info.japanese_title);
    const altTitles = [...altSet].filter(t => t !== rawTitle);

    const author = (info.artists || [])
      .map(a => (a.artist || '').trim()).filter(Boolean).join(', ');

    const tags = (info.tags || [])
      .map(t => (t.tag || '').trim()).filter(Boolean);

    // Thumbnail from first file hash — route through proxy-img so browser loads it
    // with Referer: https://hitomi.la/ (required by the CDN)
    let image = '';
    try {
      const hash = info.files?.[0]?.hash || '';
      if (hash) {
        const b = hash.slice(-3);
        const cdnUrl = `https://tn.gold-usergeneratedcontent.net/webpsmalltn/${b.slice(-1)}/${b.slice(-3, -1)}/${hash}.webp`;
        image = `/api/proxy-img?url=${encodeURIComponent(cdnUrl)}`;
      }
    } catch (_) {}

    res.json({ title: rawTitle, altTitles, author, tags, image, _hitomi: true });
  } catch (e) {
    if (e.status === 404) return res.status(404).json({ error: 'Gallery not found (404)' });
    res.status(502).json({ error: e.message });
  }
});

// ─── Atsu.moe Manga Endpoint ────────────────────────────────────────────────
// GET /api/atsu/:id — fetches https://atsu.moe/manga/{id} server-side.
// Extracts window.mangaPage JSON, formats cover image to WebP with proper referer.
app.get('/api/atsu/:id', rateLimitApi, async (req, res) => {
  const { id } = req.params;
  if (!/^[a-zA-Z0-9_-]+$/.test(id)) return res.status(400).json({ error: 'Invalid ID' });
  const targetUrl = `https://atsu.moe/manga/${id}`;
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 12000);
    const resp = await fetch(targetUrl, {
      signal: ctrl.signal,
      headers: {
        'User-Agent':
          'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
          '(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
        Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
      },
    });
    clearTimeout(timer);
    if (resp.status === 404) return res.status(404).json({ error: 'Manga not found (404)' });
    if (!resp.ok) return res.status(resp.status).json({ error: `Upstream HTTP ${resp.status}` });

    const html = await resp.text();
    const m = html.match(/window\.mangaPage\s*=\s*(\{[\s\S]*?\});\s*(?:window\.|<\/script>)/);
    if (!m) {
      // Fallback: parse minimal meta tags if window.mangaPage is absent
      const titleMatch = html.match(/<meta[^>]*property=["']og:title["'][^>]*content=["']([^"']*)["']/i);
      const title = titleMatch ? titleMatch[1].trim() : '';
      if (!title || title.toLowerCase() === 'atsumaru') return res.status(404).json({ error: 'Manga not found (404)' });
      const authMatch = html.match(/<meta[^>]*name=["']author["'][^>]*content=["']([^"']*)["']/i);
      const imgMatch = html.match(/<meta[^>]*property=["']og:image["'][^>]*content=["']([^"']*)["']/i);
      const descMatch = html.match(/<meta[^>]*name=["']description["'][^>]*content=["']([^"']*)["']/i);
      let img = imgMatch ? imgMatch[1] : '';
      if (img && !img.startsWith('/api/proxy-img')) {
        img = `/api/proxy-img?url=${encodeURIComponent(img)}`;
      }
      return res.json({
        title,
        author: authMatch ? authMatch[1] : '',
        image: img,
        description: descMatch ? descMatch[1] : '',
        tags: [],
        altTitles: [],
        chaptersTotal: null,
        isAdult: false,
        url: targetUrl,
        _atsu: true,
      });
    }

    const data = JSON.parse(m[1]).mangaPage || {};
    const prefLang = req.query.lang || 'en';
    const rawTitle = (prefLang === 'en' && data.englishTitle) ? data.englishTitle : (data.title || data.englishTitle || '');
    const title = rawTitle.split(/[|｜]/)[0].trim();

    // Deduplicate author / artist names
    const authorNames = (data.authors || [])
      .map(a => (a.name || '').trim())
      .filter(Boolean);
    const author = [...new Set(authorNames)].join(', ');

    // Tags & genres
    const genreNames = (data.genres || []).map(g => (g.name || '').trim()).filter(Boolean);
    const tagNames = (data.tags || []).map(t => (t.name || '').trim()).filter(Boolean);
    const tags = [...new Set([...genreNames, ...tagNames])];

    // Alt titles
    const otherNames = (data.otherNames || []).map(t => (t || '').trim()).filter(Boolean);
    const altSet = new Set(otherNames);
    if (data.englishTitle && data.englishTitle.trim() !== title) altSet.add(data.englishTitle.trim());
    if (data.title && data.title.trim() !== title) altSet.add(data.title.trim());
    const altTitles = [...altSet].filter(t => t !== title).slice(0, 25);

    // Cover image — convert .avif to .webp for universal compatibility
    const p = data.poster || {};
    const relPoster = (p.largeImage || p.mediumImage || p.image || '').replace(/\.avif$/i, '.webp');
    let image = '';
    if (relPoster) {
      const cdnUrl = relPoster.startsWith('http')
        ? relPoster
        : `https://cdn.atsu.moe/static/${relPoster.replace(/^\/+/, '')}`;
      image = `/api/proxy-img?url=${encodeURIComponent(cdnUrl)}`;
    }

    const description = data.synopsis || '';
    const chaptersTotal = data.totalChapterCount != null
      ? data.totalChapterCount
      : (Array.isArray(data.chapters) ? data.chapters.length : null);
    const isAdult = !!data.isAdult;

    res.json({
      title,
      author,
      image,
      description,
      tags,
      altTitles,
      chaptersTotal,
      isAdult,
      url: targetUrl,
      _atsu: true,
    });
  } catch (e) {
    if (e.name === 'AbortError') return res.status(504).json({ error: 'Request timed out' });
    res.status(502).json({ error: e.message });
  }
});

// ─── MangaUpdates Endpoints (server-side proxy to bypass CORS) ─────────────────
app.all('/api/mangaupdates/search', rateLimitApi, async (req, res) => {
  const query = req.method === 'POST' ? req.body?.search : req.query?.q;
  if (!query || typeof query !== 'string' || !query.trim()) {
    return res.status(400).json({ error: 'Search query required' });
  }
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 10000);
    const resp = await fetch('https://api.mangaupdates.com/v1/series/search', {
      method: 'POST',
      signal: ctrl.signal,
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'User-Agent': 'VLT-Tracker/2.0.0 (https://github.com/jt-ito/vlt-tracker)',
      },
      body: JSON.stringify({ search: query.trim(), perpage: 1 }),
    });
    clearTimeout(timer);
    if (!resp.ok) return res.status(resp.status).json({ error: `MangaUpdates HTTP ${resp.status}` });
    const json = await resp.json();
    res.json(json);
  } catch (e) {
    if (e.name === 'AbortError') return res.status(504).json({ error: 'MangaUpdates request timed out' });
    res.status(502).json({ error: e.message });
  }
});

app.get(['/api/mangaupdates/series/:id', '/api/mangaupdates/series/:id/categories'], rateLimitApi, async (req, res) => {
  const { id } = req.params;
  if (!/^\d+$/.test(id)) return res.status(400).json({ error: 'Invalid Series ID' });
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 8000);
    const resp = await fetch(`https://api.mangaupdates.com/v1/series/${id}`, {
      signal: ctrl.signal,
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'VLT-Tracker/2.0.0 (https://github.com/jt-ito/vlt-tracker)',
      },
    });
    clearTimeout(timer);
    if (!resp.ok) return res.status(resp.status).json({ error: `MangaUpdates HTTP ${resp.status}` });
    const json = await resp.json();
    if (req.path.endsWith('/categories')) {
      return res.json({ categories: json.categories || [] });
    }
    res.json(json);
  } catch (e) {
    if (e.name === 'AbortError') return res.status(504).json({ error: 'MangaUpdates request timed out' });
    res.status(502).json({ error: e.message });
  }
});

// ─── NH Gallery (official v2 API with API key) ──────────────────────────────
// GET /api/nh/:id — call nhentai v2 API server-side using the user's stored API key.
// Returns normalised metadata so the client doesn't need to know the v2 schema.
app.get('/api/nh/:id', rateLimitApi, async (req, res) => {
  const { id } = req.params;
  if (!/^\d+$/.test(id)) return res.status(400).json({ error: 'Invalid ID' });
  const nhKey = getSecretValue(req.session?.userId, 'nh-key');
  if (!nhKey) return res.status(401).json({ error: 'No NH API key saved' });
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 15000);
    const headers = {
      'Authorization': `Key ${nhKey}`,
      'User-Agent': 'VLT-Tracker/1.0.4 (https://github.com/jt-ito/vlt-tracker)',
      'Accept': 'application/json',
    };
    // Fetch gallery first; don't let a slow CDN endpoint block it
    const galleryResp = await fetch(`https://nhentai.net/api/v2/galleries/${id}`, { signal: ctrl.signal, headers });
    clearTimeout(timer);
    if (!galleryResp.ok) {
      const body = await galleryResp.text().catch(() => '');
      return res.status(galleryResp.status).json({ error: `NH API ${galleryResp.status}`, detail: body });
    }
    const gallery = await galleryResp.json();
    // Fetch CDN config with a short independent timeout; fall back to known-good host
    let coverBase = 'https://t2.nhentai.net';
    try {
      const cdnCtrl = new AbortController();
      const cdnTimer = setTimeout(() => cdnCtrl.abort(), 4000);
      const cdnResp = await fetch('https://nhentai.net/api/v2/cdn', { signal: cdnCtrl.signal, headers });
      clearTimeout(cdnTimer);
      if (cdnResp.ok) {
        const cdn = await cdnResp.json().catch(() => ({}));
        const base = cdn.thumb_servers?.[0] || cdn.image_servers?.[0] || '';
        if (base) coverBase = base.replace(/\/$/, '');
      }
    } catch (_) { /* CDN fetch failed — use fallback base */ }
    // Normalise to the shape tryNH() already expects
    const t = gallery.title || {};
    const prettyTitle = t.pretty || t.english || t.japanese || '';
    const author = (gallery.tags || []).filter(tg => tg.type === 'artist').map(tg => tg.name).join(', ');
    const tags = (gallery.tags || []).filter(tg => tg.type === 'tag').map(tg => tg.name);
    const image = (coverBase && gallery.cover?.path) ? `${coverBase}/${gallery.cover.path.replace(/^\//, '')}` : '';
    const allTitles = [t.english, t.japanese, t.pretty].filter(Boolean);
    const altTitles = [...new Set(allTitles.filter(x => x !== prettyTitle))];
    res.json({ title: prettyTitle, author, image, tags, altTitles, _v2: true });
  } catch (e) {
    if (e.name === 'AbortError') return res.status(504).json({ error: 'Request timed out' });
    res.status(502).json({ error: e.message });
  }
});

// GET /api/nh/search — search nhentai v2 API using the user's stored API key
app.get('/api/nh/search', rateLimitApi, async (req, res) => {
  const { q } = req.query;
  if (!q || typeof q !== 'string') return res.status(400).json({ error: 'Missing query' });
  const nhKey = getSecretValue(req.session?.userId, 'nh-key');
  if (!nhKey) return res.status(401).json({ error: 'No NH API key saved' });
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 15000);
    const headers = {
      'Authorization': `Key ${nhKey}`,
      'User-Agent': 'VLT-Tracker/1.0.4 (https://github.com/jt-ito/vlt-tracker)',
      'Accept': 'application/json',
    };
    
    const searchUrl = `https://nhentai.net/api/v2/galleries/search?query=${encodeURIComponent(q)}&page=1`;
    const searchResp = await fetch(searchUrl, { signal: ctrl.signal, headers });
    clearTimeout(timer);
    
    if (!searchResp.ok) {
      const body = await searchResp.text().catch(() => '');
      return res.status(searchResp.status).json({ error: `NH API ${searchResp.status}`, detail: body });
    }
    
    const json = await searchResp.json();
    // V2 search returns results in json.data
    const results = json.data || json.result || [];
    if (!results || results.length === 0) {
      return res.json({ results: [] });
    }
    
    const gallery = results[0];
    let coverBase = 'https://t2.nhentai.net';
    
    const t = gallery.title || {};
    const prettyTitle = t.pretty || t.english || t.japanese || '';
    const author = (gallery.tags || []).filter(tg => tg.type === 'artist').map(tg => tg.name).join(', ');
    const tags = (gallery.tags || []).filter(tg => tg.type === 'tag').map(tg => tg.name);
    const image = (coverBase && gallery.cover?.path) ? `${coverBase}/${gallery.cover.path.replace(/^\//, '')}` : '';
    const allTitles = [t.english, t.japanese, t.pretty].filter(Boolean);
    const altTitles = [...new Set(allTitles.filter(x => x !== prettyTitle))];
    
    res.json({ results: [{ id: gallery.id, title: prettyTitle, author, image, tags, altTitles, _v2: true, url: `https://nhentai.net/g/${gallery.id}/` }] });
  } catch (e) {
    if (e.name === 'AbortError') return res.status(504).json({ error: 'Request timed out' });
    res.status(502).json({ error: e.message });
  }
});

// ─── Cloudflare Bypass via Chromium ───────────────────────────────────────────
// In Electron: opens a visible Chrome window the user interacts with.
// In Docker / headless: runs Chromium headlessly — auto-passes most JS challenges.
const cfSessions = new Map();

// True when running inside a container or any environment without a display.
const IS_HEADLESS = fs.existsSync('/.dockerenv') ||
                    process.env.DOCKER === '1' ||
                    (!process.env.DISPLAY && process.platform === 'linux');

function findChrome() {
  // Allow an explicit override (e.g. CHROME_PATH=/usr/bin/chromium)
  if (process.env.CHROME_PATH && fs.existsSync(process.env.CHROME_PATH)) {
    return process.env.CHROME_PATH;
  }

  // Chrome auto-downloaded to the data dir on first CF bypass use.
  // Structure: data/.chromium/chrome/<platform-version>/<chrome-folder>/chrome[.exe]
  const chromeName = process.platform === 'win32' ? 'chrome.exe' : 'chrome';
  const chromiumDataDir = path.join(DATA_DIR, '.chromium', 'chrome');
  if (fs.existsSync(chromiumDataDir)) {
    try {
      for (const ver of fs.readdirSync(chromiumDataDir)) {
        const verDir = path.join(chromiumDataDir, ver);
        if (!fs.statSync(verDir).isDirectory()) continue;
        for (const sub of fs.readdirSync(verDir)) {
          const candidate = path.join(verDir, sub, chromeName);
          if (fs.existsSync(candidate)) return candidate;
        }
      }
    } catch {}
  }

  const local = process.env.LOCALAPPDATA || '';
  const prog86 = 'C:\\Program Files (x86)';
  const prog   = 'C:\\Program Files';
  const candidates = [
    // Windows – Chrome
    path.join(local, 'Google', 'Chrome', 'Application', 'chrome.exe'),
    path.join(prog,  'Google', 'Chrome', 'Application', 'chrome.exe'),
    path.join(prog86,'Google', 'Chrome', 'Application', 'chrome.exe'),
    // Windows – Chromium
    path.join(local, 'Chromium', 'Application', 'chrome.exe'),
    // Windows – Edge
    path.join(prog86,'Microsoft', 'Edge', 'Application', 'msedge.exe'),
    path.join(prog,  'Microsoft', 'Edge', 'Application', 'msedge.exe'),
    // macOS
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
    // Linux / Alpine Docker
    '/usr/bin/chromium-browser',
    '/usr/bin/chromium',
    '/usr/bin/google-chrome',
  ];
  return candidates.find(p => p && fs.existsSync(p)) || null;
}

// Downloads Chrome to DATA_DIR/.chromium/ via @puppeteer/browsers (ESM).
// Updates cfSessions[sessionId].message with download progress.
async function downloadChrome(sessionId) {
  const { install, resolveBuildId, detectBrowserPlatform } = await import('@puppeteer/browsers');
  const cacheDir = path.join(DATA_DIR, '.chromium');
  const platform = detectBrowserPlatform();
  if (!platform) throw new Error('Unsupported platform for Chrome download');

  const buildId = await resolveBuildId('chrome', platform, 'stable');

  // Remove any partial extraction left from a previous failed download
  const versionDir = path.join(cacheDir, 'chrome', `${platform}-${buildId}`);
  if (fs.existsSync(versionDir)) {
    const exeName = process.platform === 'win32' ? 'chrome.exe' : 'chrome';
    let hasExe = false;
    try {
      for (const sub of fs.readdirSync(versionDir)) {
        if (fs.existsSync(path.join(versionDir, sub, exeName))) { hasExe = true; break; }
      }
    } catch {}
    if (!hasExe) {
      fs.rmSync(versionDir, { recursive: true, force: true });
    } else {
      // Already downloaded
      const result = await install({ browser: 'chrome', buildId, cacheDir, platform });
      return result.executablePath;
    }
  }

  const setStatus = (msg) => {
    if (sessionId && cfSessions.has(sessionId)) {
      cfSessions.set(sessionId, { status: 'downloading', message: msg });
    }
  };

  setStatus('Downloading browser (0%)…');
  const result = await install({
    browser: 'chrome',
    buildId,
    cacheDir,
    platform,
    downloadProgressCallback: (downloaded, total) => {
      const pct = total ? Math.round(downloaded / total * 100) : 0;
      setStatus(`Downloading browser (${pct}%)…`);
    },
  });
  return result.executablePath;
}

app.post('/api/cf-open', rateLimitApi, async (req, res) => {
  const { url } = req.body ?? {};
  if (typeof url !== 'string' || !(await isSafeUrl(url))) {
    return res.status(400).json({ error: 'Invalid or restricted URL' });
  }

  // Prevent DoS via concurrent browser instances per user
  let activeSessions = 0;
  for (const s of cfSessions.values()) {
    if (s.userId === req.session.userId && (s.status === 'open' || s.status === 'downloading')) {
      activeSessions++;
    }
  }
  if (activeSessions >= 2) {
    return res.status(429).json({ error: 'Too many concurrent browser sessions. Please wait.' });
  }

  const sessionId = crypto.randomUUID();
  cfSessions.set(sessionId, { userId: req.session.userId, status: 'open' });
  res.json({ sessionId, headless: IS_HEADLESS }); // respond immediately so client starts polling

  try {
    const puppeteer = require('puppeteer-core');
    let executablePath = findChrome();
    if (!executablePath) {
      // First use — auto-download Chrome to the data dir (persisted across restarts)
      cfSessions.set(sessionId, { status: 'downloading', message: 'Downloading browser (first time only)…' });
      try {
        executablePath = await downloadChrome(sessionId);
      } catch (dlErr) {
        cfSessions.set(sessionId, {
          status: 'error',
          error: 'Could not download browser automatically: ' + dlErr.message,
        });
        return;
      }
    }
    cfSessions.set(sessionId, { status: 'open' });

    // Container / headless: run silently, auto-bypasses most JS challenges.
    // Desktop: open a visible window so the user can solve CAPTCHA-style challenges.
    const launchArgs = IS_HEADLESS
      ? [
          '--no-sandbox',
          '--disable-setuid-sandbox',
          '--disable-dev-shm-usage',
          '--disable-gpu',
          '--disable-blink-features=AutomationControlled',
          '--window-size=1280,800',
        ]
      : ['--window-size=1100,800', '--window-position=80,80'];

    const browser = await puppeteer.launch({
      executablePath,
      headless: IS_HEADLESS ? 'new' : false,
      defaultViewport: IS_HEADLESS ? { width: 1280, height: 800 } : null,
      args: launchArgs,
    });

    const [page] = await browser.pages();

    // Mask automation signals to improve CF bypass success rate
    await page.evaluateOnNewDocument(() => {
      Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
    });

    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 90000 });

    // In headless mode, give CF's JS challenge a moment to run and auto-resolve
    const maxTries = IS_HEADLESS ? 30 : 150; // 1 min headless, 5 min interactive
    let tries = 0;
    const poll = setInterval(async () => {
      tries++;
      if (tries > maxTries) {
        clearInterval(poll);
        cfSessions.set(sessionId, { status: 'error', error: IS_HEADLESS
          ? 'Cloudflare challenge could not be bypassed automatically. This site may require a CAPTCHA — try importing via the regular URL import instead.'
          : 'Timed out waiting for Cloudflare bypass' });
        await browser.close().catch(() => {});
        return;
      }
      try {
        const title = await page.title().catch(() => '');
        if (/just a moment/i.test(title)) return; // still on challenge page
        const html = await page.content();
        cfSessions.set(sessionId, { status: 'done', html });
        clearInterval(poll);
        setTimeout(() => browser.close().catch(() => {}), 1000);
      } catch (e) {
        clearInterval(poll);
        cfSessions.set(sessionId, { status: 'error', error: e.message });
        await browser.close().catch(() => {});
      }
    }, 2000);

  } catch (e) {
    cfSessions.set(sessionId, { status: 'error', error: e.message });
  }
});

app.get('/api/cf-result/:id', (req, res) => {
  const s = cfSessions.get(req.params.id);
  if (!s) return res.json({ status: 'notfound' });
  if (s.userId && s.userId !== req.session?.userId) {
    return res.status(403).json({ error: 'Unauthorized access to session.' });
  }
  res.json(s);
  // Clean up session a few seconds after delivering the final state
  if (s.status === 'done' || s.status === 'error') {
    setTimeout(() => cfSessions.delete(req.params.id), 10000);
  }
});

// ─── Start ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || process.env.VLT_INTERNAL_PORT || 3000;
app.listen(PORT, () => {
  const url = `http://localhost:${PORT}`;
  console.log(`\n📚 MangaList running at ${url}\n`);
  const cmd =
    process.platform === 'win32' ? `start "" "${url}"` :
    process.platform === 'darwin' ? `open "${url}"` :
    `xdg-open "${url}"`;
  exec(cmd, err => { if (err) console.log(`Open ${url} in your browser`); });
});
