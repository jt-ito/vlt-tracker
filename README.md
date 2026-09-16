# 📚 VLT Tracker

[![Release](https://img.shields.io/github/v/release/jt-ito/vlt-tracker?style=flat-square)](https://github.com/jt-ito/vlt-tracker/releases/latest)
[![Docker Pulls](https://img.shields.io/docker/pulls/jteaito/vlt-tracker?style=flat-square)](https://hub.docker.com/r/jteaito/vlt-tracker)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)

A self-hosted library manager for tracking manga, doujinshi, and light novels across devices. Features automated metadata scraping, chapter and volume progress tracking, multi-user accounts, and an embedded SQLite database engine.

> **Disclaimer:** VLT Tracker is a **tracking tool only**. It does not host, store, distribute, or stream copyrighted reading material. All metadata (titles, covers, tags) is fetched from public third-party endpoints for personal library management. This project is unaffiliated with the external services it integrates with.

VLT Tracker runs as a standalone desktop application on Windows, macOS, and Linux (via Electron), or as a lightweight containerized web application (via Docker / Node.js). Paste a link from any supported source to extract titles, authors, tags, and covers, organize your library with custom filters, and sync reading progress across your devices.

---

## Architecture & Data Storage

VLT Tracker pairs an embedded SQLite database on the server with an optimistic local cache in the browser. You get instantaneous UI rendering with persistent, multi-user storage on disk.

```
┌─────────────────────────────────────────────────────────────┐
│                       Client Browser                        │
│  • Instant UI rendering via localStorage cache              │
│  • Cover image binary blob storage via IndexedDB            │
│  • Fast client-side search, tag filtering, & badge counts   │
│  • Debounced background sync queue to server API            │
└──────────────────────────────┬──────────────────────────────┘
                               │ HTTPS / JSON API
┌──────────────────────────────▼──────────────────────────────┐
│                    VLT Tracker Server (Node.js)             │
│  • Express HTTP server with Helmet security headers         │
│  • SSRF-protected scraper proxy & referer spoofing engine   │
│  • AES-256-GCM authenticated encryption for API keys        │
│  • In-tab session heartbeat & rolling expiration            │
└──────────────────────────────┬──────────────────────────────┘
                               │ WAL Mode (In-Process C++)
┌──────────────────────────────▼──────────────────────────────┐
│                    SQLite Database (data/users.db)          │
│  • users: bcrypt password hashes & admin flags              │
│  • user_data: per-user library entries, views & settings    │
│  • secrets: per-user AES-256-GCM encrypted API credentials  │
│  • sessions: persistent web sessions with automatic purging │
└─────────────────────────────────────────────────────────────┘
```

### The Database Engine (`data/users.db`)
- **Embedded SQLite via `better-sqlite3`**: Database queries execute directly in-process via native C++ bindings, removing the need to configure or maintain an external database server like PostgreSQL or MySQL.
- **Write-Ahead Logging (WAL)**: Enabled by default (`PRAGMA journal_mode = WAL;`). Reads and writes execute concurrently without blocking one another.
- **Foreign Key Integrity**: Enforced at the engine level (`PRAGMA foreign_keys = ON;`). When an administrator deletes a user account, their library data, encrypted credentials, and active sessions cascade and delete automatically.
- **Persistent Sessions**: Web sessions live inside the SQLite `sessions` table rather than process memory. Restarting the server or updating the Docker container keeps active user sessions intact until their idle timer expires.

### Client Sync Engine
- **Optimistic Local Cache**: The frontend loads your library directly from browser `localStorage` on page open, rendering hundreds of titles instantly without waiting on network round-trips.
- **Debounced Server Sync**: As you edit entries, change statuses, or adjust chapter counts, changes sync to the server in the background through debounced `PUT /api/data` requests.
- **Offline Cover Cache (IndexedDB)**: Cover thumbnails can be cached locally inside the browser's IndexedDB database (`manga-image-cache`). Image data is stored as binary Blobs and rendered into the DOM using object URLs (`blob:...`), keeping your browser responsive without bumping into `localStorage` storage limits.

---

## Core Capabilities

### 📥 Automated Scraping & Source Integrations
- **Single-Link Scraping**: Paste a link to pull titles, alternate titles, authors, artist credits, chapter counts, tags, and high-resolution cover artwork.
- **Supported Metadata Parsers**:
  - **Native API & Gallery Parsers**: Integrates with supported source APIs and gallery endpoints using optional stored credentials (such as an encrypted NH API key).
  - **Universal Web Scraper**: Automatically extracts OpenGraph tags, Twitter Cards, and schema.org JSON-LD structured metadata from arbitrary web pages.
  - **Asset Optimization & Proxy**: Proxies external cover assets with required headers and converts modern image formats (such as `.avif`) into browser-compatible `.webp` covers.
- **Metadata Enrichment**: Cross-reference any entry against **AniList** and **MangaUpdates** with one click to fetch canonical romanized titles, official English titles, and missing genre tags.
- **Cloudflare Challenge Engine**: Bundled with a managed Chromium instance (`puppeteer-core`). In desktop mode, an interactive solve window appears when an interstitial is hit; in Docker or headless mode, challenges are solved automatically in the background.
- **Batch Processing**: Paste multiple links into the bulk queue, configure request pacing, and let the crawler import your backlog in order.
- **Quick ID Import**: Enter a numeric ID directly into the quick-import dialog for instant lookup.

### 🗂️ Library Organization & Views
- **Reading Status Categories**: Organize titles across six states: *Reading*, *Plan to Read*, *Completed*, *Paused*, *Re-reading*, and *Dropped*.
- **Flexible Progress Tracking**: Track progress by **Chapters**, **Volumes**, or **Pages** with single-click increment and decrement controls.
- **Include & Exclude Tag Filtering**: Click tags to toggle them between *Include* (green) and *Exclude* (red) states to filter complex catalogs.
- **Four Layout Views**:
  - **Grid**: Visual poster board highlighting cover artwork.
  - **List**: Detailed layout showing full progress, notes, alternate titles, and external lookup shortcuts.
  - **Compact**: Dense spreadsheet-style row view ideal for large catalogs.
  - **Links**: Streamlined directory focusing on source URLs.
- **Duplicate Detection**: Flags matches immediately when adding a title or URL that already exists in your library.
- **Import & Export**: Export your entire collection to JSON format or restore an existing backup with full schema validation.

### 🛡️ Security Implementation
- **Password Hashing**: User passwords are saved using **bcrypt** at cost factor 12.
- **Encrypted Credential Vault**: Third-party API keys (such as an NH API key) are encrypted at rest using **AES-256-GCM** with authenticated data tags. Keys are derived per-user using `scrypt` from a persistent 64-byte random master secret stored with `0o600` filesystem permissions. Plaintext keys are never sent back to the browser.
- **SSRF Defense with DNS Pinning**: Scraper proxy requests validate incoming IP addresses against loopback (`127.0.0.0/8`, `::1`), private subnets (RFC 1918), link-local and cloud metadata endpoints (`169.254.169.254`), unique local IPv6 (`fc00::/7`), and IPv4-mapped IPv6 ranges (`::ffff:x.x.x.x`). All resolved DNS addresses are vetted before opening network sockets.
- **Session Lifecycle & Keep-Alive**: Web sessions run on rolling idle timeouts (configurable via `SESSION_IDLE_MINUTES`, default 60 minutes) coupled with an in-tab heartbeat that prevents session timeouts while you are actively reading. Expired sessions are caught by an absolute 7-day cutoff (OWASP ASVS 3.3) and cleanly prompt for re-authentication without corrupting metadata.
- **Injection Defense**: All SQLite queries use parameterized prepared statements. Dynamic templates use strict HTML entity escaping (`escHtml`), URL protocol whitelisting (`safeHref`), and image scheme validation (`safeImgSrc`).
- **HTTP Security Headers**: Uses Helmet for a strict Content Security Policy (`CSP`), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and automated HTTP-to-HTTPS redirects with HSTS preload headers.

---

## Deployment & Installation

### 🐳 Docker & Docker Compose (Recommended for Web / Server)

The official Docker image bundles Node.js 20, SQLite native dependencies, and the Debian runtime packages required for headless Chromium challenge solving.

#### Quick Start with Docker CLI

```bash
docker run -d \
  -p 3000:3000 \
  -v vlt-data:/app/data \
  --name vlt-tracker \
  --restart unless-stopped \
  jteaito/vlt-tracker:latest
```

Navigate to `http://localhost:3000` to register your administrator account.

#### Docker Compose

Save the following configuration as `docker-compose.yml`:

```yaml
services:
  vlt-tracker:
    image: jteaito/vlt-tracker:latest
    container_name: vlt-tracker
    restart: unless-stopped
    ports:
      - "3000:3000"
    volumes:
      - vlt-data:/app/data
    environment:
      - VLT_HTTPS=false              # Set to true if terminating TLS directly on the container
      - SESSION_IDLE_MINUTES=60       # Inactivity timeout for web sessions
      - PORT=3000
    healthcheck:
      test: ["CMD", "node", "-e", "fetch('http://localhost:3000/api/auth/status').then(r => r.ok ? process.exit(0) : process.exit(1))"]
      interval: 30s
      timeout: 5s
      retries: 3

volumes:
  vlt-data:
    name: vlt-tracker-data
```

Start the container:

```bash
docker compose up -d
```

> **Data Persistence:** The `/app/data` directory holds `users.db` (database containing all user accounts, libraries, and encrypted keys) and `session.secret`. Always mount this path to a persistent Docker volume or host directory.

---

### 💻 Desktop Applications

Official pre-built binaries are available on the [GitHub Releases page](https://github.com/jt-ito/vlt-tracker/releases/latest):

| Platform | Package | Description |
|:---|:---|:---|
| **Windows** | `VLT-Tracker-Setup-x.x.x.exe` | Standard Windows installer with Start Menu shortcuts and automatic updates |
| **Windows** | `VLT-Tracker-Portable-x.x.x.exe` | Standalone portable executable requiring no installation |
| **Linux** | `VLT-Tracker-x.x.x.AppImage` / `.deb` | Linux desktop packages |
| **Linux** | `vlt-tracker-linux-cli.tar.gz` | Headless Linux server bundle with embedded Node dependencies |
| **macOS** | `.dmg` / `.zip` | macOS desktop application builds |

Desktop releases run on Electron, embed the complete SQLite backend locally, and include an interactive window to manually solve Cloudflare verification prompts when required.

---

### 🛠️ Building & Running from Source

Requires **Node.js 20+** and a C++ compiler toolchain (for compiling the `better-sqlite3` native addon).

```bash
# 1. Clone the repository
git clone https://github.com/jt-ito/vlt-tracker.git
cd vlt-tracker

# 2. Install dependencies
npm install

# 3. Run in your preferred mode:
npm start       # Launches the Electron desktop application
npm run web     # Starts the Express web server at http://localhost:3000
```

---

## Configuration Reference

Configure the server using environment variables in your shell, `.env` file, or Docker Compose configuration:

| Variable | Default | Description |
|:---|:---|:---|
| `PORT` | `3000` | Port the HTTP application server listens on. |
| `VLT_INTERNAL_PORT` | `3000` | Secondary internal port override used in specific container environments. |
| `VLT_HTTPS` | `true` | When `true`, enables HSTS headers and forces 301 redirects from HTTP to HTTPS. Set to `false` when running locally or behind an external TLS reverse proxy (e.g. Nginx, Caddy, Traefik). |
| `SESSION_IDLE_MINUTES` | `60` | Duration of inactivity in minutes before a web session expires. |
| `HEADLESS` | Auto | Set to `true` to force Puppeteer into headless mode for Cloudflare challenge handling. Automatically detected in containers. |
| `CHROME_PATH` | Auto | Filesystem path to an existing system Chromium or Google Chrome binary. |
| `NODE_ENV` | `production` | Node execution environment (`production` enables strict error handling). |

---

## Initial Setup & Multi-User Management

1. **Admin Registration**:
   On a fresh installation, opening the web application presents an initial setup screen. The first registered account automatically becomes the instance **Administrator**.
2. **User Accounts**:
   Administrators can open **⚙️ Settings** → **Accounts** to create accounts for friends and family or set up isolated libraries for different collections. Each user has their own database records, layout settings, and encrypted credentials.
3. **Encrypted API Keys**:
   Navigate to **⚙️ Settings** → **API Keys** to store external credentials (such as a personal NH API key). Keys are encrypted with AES-256-GCM before writing to disk and are never exposed back to the client interface.
4. **Offline Cover Storage**:
   Toggle **Cache Cover Images** in Settings to store cover thumbnails in your browser's local IndexedDB storage. Covers will load offline and remain available if third-party image hosts experience downtime.

---

## Database Schema Reference

The database file is stored at `data/users.db` and uses the following relational structure:

```sql
-- User accounts and roles
CREATE TABLE users (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  username   TEXT UNIQUE NOT NULL COLLATE NOCASE,
  hash       TEXT NOT NULL,
  is_admin   INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);

-- Active web sessions (persistent across server restarts)
CREATE TABLE sessions (
  sid    TEXT PRIMARY KEY,
  data   TEXT NOT NULL,
  expire INTEGER NOT NULL
);

-- Per-user encrypted API keys (AES-256-GCM)
CREATE TABLE secrets (
  user_id    INTEGER NOT NULL,
  key_name   TEXT NOT NULL,
  ciphertext TEXT NOT NULL,
  iv         TEXT NOT NULL,
  PRIMARY KEY (user_id, key_name),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Library entries, display preferences, and UI settings
CREATE TABLE user_data (
  user_id    INTEGER PRIMARY KEY,
  entries    TEXT NOT NULL DEFAULT '[]',
  settings   TEXT NOT NULL DEFAULT '{}',
  view       TEXT NOT NULL DEFAULT 'grid',
  updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

To inspect or query your database directly:

```bash
sqlite3 data/users.db ".tables"
sqlite3 data/users.db "SELECT id, username, is_admin FROM users;"
```

---

## License

Distributed under the [MIT License](LICENSE).
