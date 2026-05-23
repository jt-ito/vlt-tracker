/**
 * setup-chromium.js
 * Downloads and extracts the bundled Chromium for Windows exe builds.
 * Run: node scripts/setup-chromium.js
 *
 * Uses @puppeteer/browsers to download Chrome to .puppeteer-cache/, then uses
 * the system unzip (via child_process) to reliably extract it on Windows.
 */
'use strict';

const { execSync, spawnSync } = require('child_process');
const fs   = require('fs');
const path = require('path');

const ROOT      = path.resolve(__dirname, '..');
const CACHE_DIR = path.join(ROOT, '.puppeteer-cache');
const CHROME_DIR = path.join(CACHE_DIR, 'chrome');

// ---- 1. Run puppeteer's own install (downloads the zip) -------------------
console.log('Downloading Chrome via puppeteer…');
const env = {
  ...process.env,
  PUPPETEER_CACHE_DIR: CACHE_DIR,
  PUPPETEER_SKIP_CHROME_HEADLESS_SHELL_DOWNLOAD: 'true',
};

// Delete any partial extraction so @puppeteer/browsers will not complain
if (fs.existsSync(CHROME_DIR)) {
  for (const entry of fs.readdirSync(CHROME_DIR)) {
    const full = path.join(CHROME_DIR, entry);
    if (fs.statSync(full).isDirectory()) {
      fs.rmSync(full, { recursive: true, force: true });
      console.log(`Removed partial extraction: ${full}`);
    }
  }
}

const installMjs = path.join(ROOT, 'node_modules', 'puppeteer', 'install.mjs');
const result = spawnSync(process.execPath, [installMjs], {
  env,
  stdio: 'inherit',
  cwd: ROOT,
});
if (result.status !== 0) {
  process.exit(result.status || 1);
}

// ---- 2. Find the downloaded zip and re-extract with Node's adm-zip --------
if (!fs.existsSync(CHROME_DIR)) {
  console.error('Chrome cache dir not found after download.');
  process.exit(1);
}

const zips = fs.readdirSync(CHROME_DIR).filter(f => f.endsWith('.zip'));
if (zips.length === 0) {
  console.log('No zip found — Chrome may have been extracted already.');
  process.exit(0);
}

for (const zipName of zips) {
  const zipPath = path.join(CHROME_DIR, zipName);
  // Determine extraction folder: <CHROME_DIR>/win64-VERSION
  const version = zipName.replace(/-chrome-win64\.zip$/, '');
  const extractDir = path.join(CHROME_DIR, `win64-${version}`);

  // Remove partial extraction
  if (fs.existsSync(extractDir)) {
    fs.rmSync(extractDir, { recursive: true, force: true });
  }
  fs.mkdirSync(extractDir, { recursive: true });

  console.log(`Extracting ${zipName} to ${extractDir} …`);
  if (process.platform === 'win32') {
    execSync(
      `powershell -NoProfile -Command "Expand-Archive -Path '${zipPath}' -DestinationPath '${extractDir}' -Force"`,
      { stdio: 'inherit', cwd: ROOT }
    );
  } else {
    execSync(`unzip -o "${zipPath}" -d "${extractDir}"`, { stdio: 'inherit', cwd: ROOT });
  }
  console.log(`Done: ${extractDir}`);
}

// ---- 3. Verify ---------------------------------------------------------------
const exe = process.platform === 'win32' ? 'chrome.exe' : 'chrome';
function findExe(dir) {
  if (!fs.existsSync(dir)) return null;
  for (const entry of fs.readdirSync(dir)) {
    const full = path.join(dir, entry);
    if (entry === exe) return full;
    try {
      if (fs.statSync(full).isDirectory()) {
        const found = findExe(full);
        if (found) return found;
      }
    } catch {}
  }
  return null;
}

const found = findExe(CACHE_DIR);
if (found) {
  console.log(`\nChrome ready: ${found}`);
} else {
  console.error('\nChrome executable not found after extraction!');
  process.exit(1);
}
