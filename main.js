const { app, BrowserWindow, session } = require('electron');
const path = require('path');
const fs = require('fs');

// Common ad/tracker domains to block natively (instant, no filter download needed)
const AD_HOSTS = [
  '*://*.doubleclick.net/*', '*://*.googlesyndication.com/*',
  '*://*.googleadservices.com/*', '*://*.adnxs.com/*',
  '*://*.adsrvr.org/*', '*://*.advertising.com/*',
  '*://*.moatads.com/*', '*://*.scorecardresearch.com/*',
  '*://*.outbrain.com/*', '*://*.taboola.com/*',
  '*://*.amazon-adsystem.com/*', '*://*.media.net/*',
  '*://*.pubmatic.com/*', '*://*.rubiconproject.com/*',
  '*://*.openx.net/*', '*://*.criteo.com/*',
  '*://*.exelator.com/*', '*://*.quantserve.com/*',
  '*://*.chartbeat.com/*', '*://*.hotjar.com/*',
  // Adult ad networks / trackers common on manga/doujin sites
  '*://*.juicyads.com/*', '*://*.trafficjunky.net/*',
  '*://*.traffichaus.com/*', '*://*.adspyglass.com/*',
  '*://*.plugrush.com/*', '*://*.ero-advertising.com/*',
  '*://*.exoclick.com/*', '*://*.exosrv.com/*',
  '*://*.hilltopads.net/*', '*://*.hilltopads.com/*',
  '*://*.adsterra.com/*', '*://*.adstera.com/*',
  '*://*.adtelligent.com/*', '*://*.adform.net/*',
  '*://*.revcontent.com/*', '*://*.propellerads.com/*',
  '*://*.popcash.net/*', '*://*.popads.net/*',
  '*://*.clickadu.com/*', '*://*.adcash.com/*',
  '*://*.mgid.com/*', '*://*.traffic-media.co/*',
  '*://*.etargetnet.com/*', '*://*.bidvertiser.com/*',
  '*://*.adskeeper.co.uk/*', '*://*.adskeeper.com/*',
  // Trackers
  '*://*.google-analytics.com/*', '*://*.googletagmanager.com/*',
  '*://*.googletagservices.com/*', '*://*.facebook.com/tr*',
  '*://*.connect.facebook.net/*',
];

function setupAdBlocking(ses) {
  ses.webRequest.onBeforeRequest({ urls: AD_HOSTS }, (details, callback) => {
    callback({ cancel: true });
  });
}

// Load any Chrome extensions that have a manifest.json in ./extensions/
// Skips sub-folders without a manifest (e.g. source-only repos).
async function loadExtensions() {
  const extDir = path.join(__dirname, 'extensions');
  if (!fs.existsSync(extDir)) return;
  const manga = session.fromPartition('persist:manga');
  for (const name of fs.readdirSync(extDir)) {
    const extPath = path.join(extDir, name);
    if (!fs.statSync(extPath).isDirectory()) continue;
    if (!fs.existsSync(path.join(extPath, 'manifest.json'))) continue;
    try {
      await manga.loadExtension(extPath, { allowFileAccess: true });
      console.log(`Loaded extension: ${name}`);
    } catch (e) {
      console.warn(`Failed to load extension ${name}:`, e.message);
    }
  }
}

function createWindow() {
  const win = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 900,
    minHeight: 600,
    title: 'Manga List',
    webPreferences: {
      webviewTag: true,
      contextIsolation: false,
      nodeIntegration: false,
    },
  });

  win.loadFile('index.html');
}

app.whenReady().then(async () => {
  // Block ads in both the main session and the webview session
  const manga = session.fromPartition('persist:manga');
  setupAdBlocking(session.defaultSession);
  setupAdBlocking(manga);

  await loadExtensions();
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

