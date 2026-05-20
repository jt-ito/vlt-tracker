'use strict';

const express  = require('express');
const path     = require('path');
const fs       = require('fs');
const crypto   = require('crypto');
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

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT    UNIQUE NOT NULL COLLATE NOCASE,
    hash       TEXT    NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
  );
  CREATE TABLE IF NOT EXISTS sessions (
    sid    TEXT    PRIMARY KEY,
    data   TEXT    NOT NULL,
    expire INTEGER NOT NULL
  );
`);

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

const SESSION_TTL_MS = 15 * 60 * 1000; // 15 minutes
const BCRYPT_ROUNDS  = 12;
const isProd         = process.env.NODE_ENV === 'production';
const secureCookie   = process.env.VLT_HTTPS === 'true';

// ─── Login rate limiter — 10 attempts per 15 min per IP ───────────────────────
const loginLimiter = new RateLimiterMemory({
  points: 10,
  duration: 15 * 60,
});

// ─── Express app ─────────────────────────────────────────────────────────────
const app = express();

// Security headers
app.use(helmet({
  contentSecurityPolicy: false, // app uses inline scripts; tighten if desired
}));

// Body parsing
app.use(express.json({ limit: '1mb' }));

// Session middleware
app.use(session({
  secret: SESSION_SECRET,
  name: 'vlt.sid',
  resave: false,
  saveUninitialized: false,
  rolling: true,              // reset 15-min window on every request
  store: new SQLiteStore(),
  cookie: {
    httpOnly: true,           // JS cannot read the cookie
    sameSite: 'strict',       // blocks CSRF via cross-site requests
      secure: secureCookie,      // set VLT_HTTPS=true when behind an HTTPS reverse proxy
    maxAge: SESSION_TTL_MS,
  },
}));

// ─── Auth helpers ─────────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (req.session?.userId) return next();
  if (req.accepts('html')) return res.redirect('/login');
  res.status(401).json({ error: 'Unauthenticated' });
}

function setupRequired() {
  return db.prepare('SELECT COUNT(*) AS c FROM users').get().c === 0;
}

// ─── Auth API ─────────────────────────────────────────────────────────────────

// Status check — used by login.html to detect setup mode and auth state
app.get('/api/auth/status', (req, res) => {
  res.json({
    authenticated: !!req.session?.userId,
    username: req.session?.username ?? null,
    setupRequired: setupRequired(),
  });
});

// First-run setup — only works while no users exist
app.post('/api/auth/setup', async (req, res) => {
  if (!setupRequired()) {
    return res.status(403).json({ error: 'Setup already complete.' });
  }
  const { username, password } = req.body ?? {};
  if (
    typeof username !== 'string' || username.trim().length < 1 || username.trim().length > 64 ||
    typeof password !== 'string' || password.length < 8 || password.length > 128
  ) {
    return res.status(400).json({ error: 'Invalid username or password (min 8 chars).' });
  }
  const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
  try {
    const row = db.prepare(
      'INSERT INTO users (username, hash) VALUES (?, ?) RETURNING id, username'
    ).get(username.trim(), hash);
    req.session.regenerate((err) => {
      if (err) return res.status(500).json({ error: 'Session error.' });
      req.session.userId   = row.id;
      req.session.username = row.username;
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
  if (typeof username !== 'string' || typeof password !== 'string') {
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
    req.session.userId   = user.id;
    req.session.username = user.username;
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

// ─── Serve login page (public) ────────────────────────────────────────────────
app.get('/login', (req, res) => {
  if (req.session?.userId) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'login.html'));
});

// ─── All subsequent routes require authentication ─────────────────────────────
app.use(requireAuth);

// Serve the main app
app.use(express.static(path.join(__dirname), {
  index: 'index.html',
}));

// ─── CORS Proxy ───────────────────────────────────────────────────────────────
// Lets the browser fetch any URL server-side, avoiding CORS restrictions.
app.get('/api/proxy', async (req, res) => {
  const url = req.query.url;
  if (!url || !/^https?:\/\//.test(url)) {
    return res.status(400).send('Invalid URL');
  }
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 12000);
    const resp = await fetch(url, {
      signal: ctrl.signal,
      headers: {
        'User-Agent':
          'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
          '(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
        Accept:
          'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
      },
    });
    clearTimeout(timer);
    const text = await resp.text();
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.status(resp.status).send(text);
  } catch (e) {
    if (e.name === 'AbortError') return res.status(504).send('Request timed out');
    res.status(502).send(e.message);
  }
});

// ─── Cloudflare Bypass via visible Chrome window ───────────────────────────────
const cfSessions = new Map();

function findChrome() {
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
    // Linux
    '/usr/bin/google-chrome',
    '/usr/bin/chromium-browser',
    '/usr/bin/chromium',
  ];
  return candidates.find(p => p && fs.existsSync(p)) || null;
}

app.post('/api/cf-open', async (req, res) => {
  const { url } = req.body;
  if (!url || !/^https?:\/\//.test(url)) {
    return res.status(400).json({ error: 'Invalid URL' });
  }

  const sessionId = Date.now().toString();
  cfSessions.set(sessionId, { status: 'open' });
  res.json({ sessionId }); // respond immediately so client starts polling

  try {
    const puppeteer = require('puppeteer-core');
    const executablePath = findChrome();
    if (!executablePath) {
      cfSessions.set(sessionId, {
        status: 'error',
        error: 'Google Chrome or Microsoft Edge not found. Please install Chrome.',
      });
      return;
    }

    const browser = await puppeteer.launch({
      executablePath,
      headless: false,
      defaultViewport: null,
      args: ['--window-size=1100,800', '--window-position=80,80'],
    });

    const [page] = await browser.pages();
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 90000 });

    let tries = 0;
    const poll = setInterval(async () => {
      tries++;
      if (tries > 150) { // ~5 minutes max
        clearInterval(poll);
        cfSessions.set(sessionId, { status: 'error', error: 'Timed out waiting for Cloudflare bypass' });
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
