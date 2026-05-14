# VLT Tracker

[![Release](https://img.shields.io/github/v/release/jt-ito/vlt-tracker?style=flat-square)](https://github.com/jt-ito/vlt-tracker/releases/latest)
[![Docker Pulls](https://img.shields.io/docker/pulls/jteaito/vlt-tracker?style=flat-square)](https://hub.docker.com/r/jteaito/vlt-tracker)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)

A local manga and doujin library tracker. Import entries from any URL, fetch metadata automatically, organise with tags, and track your reading progress — all stored in your browser's local storage with no account required.

---

## Features

- **Import from URL** — paste any manga/doujin page link and metadata (title, author, cover, tags) is scraped automatically
- **Cloudflare bypass** — a built-in puppeteer window handles CF-protected sites
- **AniList & MangaUpdates** — one-click lookups to enrich entries with titles, authors, cover art, and genre tags
- **Tag system** — pill-based read-only tags sourced from scraping and APIs; include/exclude tag filtering
- **Multiple views** — list, compact, grid, and links views with search and status filters
- **Reading progress** — track chapters and/or volumes; mark as Reading, Planning, Completed, Paused, Re-reading, or Dropped
- **Bulk import / export** — JSON export for backup; bulk URL queue import with cooldown
- **Cover image caching** — download and store covers locally for offline access
- **Encrypted API keys** — NH and MangaDex keys stored with AES-256-GCM, never as plaintext
- **uBlock Origin** — bundled extension active in the import webview
- **Dark / light theme** — follows your OS preference

---

## Installation

### Windows (recommended)

Download the latest release from the [Releases page](https://github.com/jt-ito/vlt-tracker/releases/latest):

| File | Description |
|------|-------------|
| `VLT-Tracker-Setup-x.x.x.exe` | NSIS installer — installs to Program Files with Start Menu shortcut |
| `VLT-Tracker-Portable-x.x.x.exe` | No installation needed — run from anywhere |

### Docker (web mode)

```bash
docker run -p 3000:3000 jteaito/vlt-tracker
```

Then open [http://localhost:3000](http://localhost:3000) in your browser.

> **Note:** The Cloudflare bypass (puppeteer popup window) is unavailable in Docker — the standard CORS proxy waterfall still works for most sites.

### Run from source

```bash
git clone https://github.com/jt-ito/vlt-tracker.git
cd vlt-tracker
npm install

# Electron desktop app
npm start

# Express web server (browser at http://localhost:3000)
npm run web
```

---

## Building

Requires Node 20+ and npm.

```bash
npm install
npm run dist        # Windows installer + portable → dist/
```

---

## Settings

Open ⚙️ Settings from the top-right corner.

| Setting | Description |
|---------|-------------|
| **Title Language** | Preferred language when a title is pipe-separated (e.g. `English \| 日本語`) |
| **Show Links in List View** | Toggle source URL display on list cards |
| **Cache Cover Images** | Download and store covers locally for offline use |
| **NH API Key** | API key for the NH API — encrypted with AES-256-GCM |
| **MangaDex API Key** | Personal client token for MangaDex — encrypted with AES-256-GCM |

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Desktop shell | Electron 31 |
| Web server | Express 4 |
| CF bypass | puppeteer-core 22 |
| Frontend | Vanilla HTML / CSS / JS (no build step) |
| Storage | `localStorage` |
| Ad blocking | uBlock Origin (bundled extension) |

---

## License

[MIT](LICENSE)
