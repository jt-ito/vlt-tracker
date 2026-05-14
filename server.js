'use strict';

const express = require('express');
const path = require('path');
const fs = require('fs');
const { exec } = require('child_process');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname)));

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
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  const url = `http://localhost:${PORT}`;
  console.log(`\n📚 MangaList running at ${url}\n`);
  const cmd =
    process.platform === 'win32' ? `start "" "${url}"` :
    process.platform === 'darwin' ? `open "${url}"` :
    `xdg-open "${url}"`;
  exec(cmd, err => { if (err) console.log(`Open ${url} in your browser`); });
});
