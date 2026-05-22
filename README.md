# 📚 VLT Tracker

[![Release](https://img.shields.io/github/v/release/jt-ito/vlt-tracker?style=flat-square)](https://github.com/jt-ito/vlt-tracker/releases/latest)
[![Docker Pulls](https://img.shields.io/docker/pulls/jteaito/vlt-tracker?style=flat-square)](https://hub.docker.com/r/jteaito/vlt-tracker)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)

Your personal manga and doujin library — because a browser bookmark folder named `manga stuff (2)` just isn't cutting it anymore.

VLT Tracker runs either as a **desktop app** (Electron) or a **self-hosted web server** (Docker / Node). Paste a URL, let it scrape the metadata, slap some tags on it, and track your reading progress. No cloud. No subscription. No one judging your taste.

---

## Features

### 📥 Import & Metadata
- **Import from any URL** — paste a manga or doujin page link and the app fetches the title, author, cover image, and tags automatically via a server-side CORS proxy
- **"Sauce" quick-import** — drop an NH ID or URL directly into the dedicated import dialog for fast lookups
- **AniList & MangaUpdates integration** — one-click lookups enrich entries with canonical titles, authors, cover art, and genre tags
- **Cloudflare bypass** — a built-in Puppeteer window handles CF-protected sites; the app detects when the challenge is solved and grabs the data automatically
- **Bulk import queue** — feed it a list of URLs, set a cooldown, walk away

### 🗂️ Organisation
- **Status tracking** — Reading, Planning, Completed, Paused, Re-reading, Dropped
- **Chapter & volume progress** — track either or both; updates in one click
- **Tag system** — pill-style tags sourced from scraping and APIs; filter by including or excluding any combination
- **Full-text search** — searches titles and authors simultaneously
- **Multiple views** — List, Compact, Grid, and Links — pick what works for your screen
- **Sort** — alphabetical, date added, status, progress, and more

### 🔒 Security & Privacy
- **Authentication** — bcrypt-hashed accounts with rolling 15-minute sessions; brute-force protection via rate limiting (10 attempts per 15 min per IP)
- **Multi-account support** — the first account you create is the admin; admins can create and delete additional accounts so different lists can have different logins
- **Per-account isolated data** — each account's library is stored independently in `localStorage` (namespaced by user ID), so accounts don't bleed into each other
- **Server-side API key storage** — NH and MangaDex keys are encrypted with AES-256-GCM server-side using a per-user derived key; the plaintext *never* leaves the server after saving, and never touches `localStorage`
- **Helmet & HTTPS-first** — security headers out of the box; HTTP requests are redirected to HTTPS by default (`VLT_HTTPS=false` to disable for local dev)
- **Session cookies** — `HttpOnly`, `SameSite=Strict`, optional `Secure` flag

### 🖼️ Other
- **Cover image caching** — download and store covers locally for offline browsing
- **JSON export / import** — full backup and restore of your library
- **uBlock Origin** — bundled and active in the import webview so ads don't break metadata scraping
- **Dark theme** — it's a manga tracker, obviously it's dark

---

## Installation

### 🪟 Windows Desktop App (recommended)

Grab the latest release from the [Releases page](https://github.com/jt-ito/vlt-tracker/releases/latest):

| File | Description |
|------|-------------|
| `VLT-Tracker-Setup-x.x.x.exe` | NSIS installer — installs to Program Files, adds a Start Menu shortcut |
| `VLT-Tracker-Portable-x.x.x.exe` | No installation needed — just run it |

The desktop app includes the full Cloudflare bypass window and runs fully offline after setup.

---

### 🐳 Docker (self-hosted web server)

The fastest way to get the web mode running:

```bash
docker run -d \
  -p 3000:3000 \
  -v vlt-data:/app/data \
  --name vlt-tracker \
  jteaito/vlt-tracker
```

Then open [http://localhost:3000](http://localhost:3000) and create your admin account.

The `/app/data` volume holds your user database and session secret — mount it so your accounts survive container restarts.

#### Docker Compose

```yaml
services:
  vlt-tracker:
    image: jteaito/vlt-tracker:latest
    ports:
      - "3000:3000"
    volumes:
      - vlt-data:/app/data
    environment:
      - VLT_HTTPS=false   # set to true (or remove) when behind a TLS reverse proxy
    restart: unless-stopped

volumes:
  vlt-data:
```

> **Note:** The Cloudflare bypass (Puppeteer popup window) requires a display and is unavailable in Docker. The standard CORS proxy waterfall still works for most sites.

---

### 🛠️ Run from Source

Requires Node 20+.

```bash
git clone https://github.com/jt-ito/vlt-tracker.git
cd vlt-tracker
npm install

# Electron desktop app
npm start

# Express web server only (browser at http://localhost:3000)
npm run web
```

---

## First Run

Whether you're using Docker or running from source, the first time you open the app you'll land on a setup screen asking you to create your admin account. That's it — no config files to edit, no environment variables required.

After logging in:
1. Open **⚙️ Settings** (top-right corner)
2. Optionally add your NH or MangaDex API keys under **API Keys** — they're encrypted before being saved
3. If you want additional accounts (e.g. a separate list for light novels), head to the **Accounts** section — it's only visible when you're logged in as an admin

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3000` | Port the web server listens on |
| `VLT_INTERNAL_PORT` | `3000` | Alternative port variable (useful in compose) |
| `VLT_HTTPS` | `true` | Set to `false` to disable HTTP→HTTPS redirect and `Secure` cookie flag |
| `NODE_ENV` | — | Set to `production` for production hardening |

---

## Building from Source

Requires Node 20+, npm, and Windows (for Windows targets).

```bash
npm install
npm run dist        # Windows installer + portable .exe → dist_out/
```

---

## Settings Reference

Open **⚙️ Settings** from the header.

| Setting | Description |
|---------|-------------|
| **Title Language** | Preferred language when a title is pipe-separated (e.g. `English \| 日本語`) |
| **Show Links in List View** | Toggle the source URL display on list-view cards |
| **Cache Cover Images** | Download and store cover images locally for offline use |
| **NH API Key** | Encrypted server-side with AES-256-GCM; never returned to the browser |
| **MangaDex API Key** | Same deal — paste once, never seen again |
| **Accounts** *(admin only)* | Create additional user accounts; each gets its own isolated library |

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Desktop shell | Electron 31 |
| Web server | Express 4 + Helmet |
| Authentication | bcrypt (cost 12), express-session (SQLite-backed), rate-limiter-flexible |
| Database | better-sqlite3 (users, sessions, encrypted secrets) |
| CF bypass | puppeteer-core 22 |
| Frontend | Vanilla HTML / CSS / JS — no build step, no framework |
| Data storage | `localStorage` (per-user namespaced) |
| API key storage | AES-256-GCM, server-side, per-user derived key |
| Ad blocking | uBlock Origin (bundled extension) |

---

## Security Notes

- **Passwords** are hashed with bcrypt (cost factor 12) and never stored in plaintext
- **API keys** are encrypted with AES-256-GCM on the server; the key material is derived from `HMAC-SHA256(session_secret, user_id)` and never stored — only ever derived at runtime
- **Session cookies** are `HttpOnly`, `SameSite=Strict`; the `Secure` flag is on by default and only disabled when `VLT_HTTPS=false`
- **Rate limiting** blocks brute-force login attempts: 10 failures per IP per 15 minutes
- The session secret is auto-generated as 64 bytes of random hex on first start and stored in `data/session.secret`

---

## License

[MIT](LICENSE)
