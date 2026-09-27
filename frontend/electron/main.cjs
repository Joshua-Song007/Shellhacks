const { app, BrowserWindow, ipcMain } = require('electron');
const os = require('node:os');
const path = require('node:path');
const { startBackend } = require('./backend.cjs');

const DEV_URL = 'http://localhost:5174';
const dev = !!process.env.TCELL_DEV;
let genomeWin = null;
let backend = null;

// Packaged .app: binaries, trigger and traces ship in Contents/Resources (package.json build.extraResources).
// PoI committee keys are secrets, never bundled: they're read from ~/.tcell/keys/poi-{1..5}.json on this Mac.
function packagedPaths() {
  const res = (p) => path.join(process.resourcesPath, p);
  const keys = path.join(os.homedir(), '.tcell', 'keys');
  process.env.TCELL_POI_DIR = keys; // for the suppress bin
  return {
    scoutBin: res('bin/scout'),
    soldierBin: res('bin/soldier'),
    meshdBin: res('bin/meshd'),
    feedBin: res('bin/feed'),
    suppressBin: res('bin/suppress'),
    testThreatScript: res('scripts/test_threat.sh'),
    trace: res('traces/demo_ransomware.ndjson'),
    benignTrace: res('traces/benign_apps.ndjson'),
    poiKeys: [1, 2, 3, 4, 5].map((n) => path.join(keys, `poi-${n}.json`)),
    advisorUrl: process.env.TCELL_ADVISOR_URL || 'https://advisor-kr3vx.ondigitalocean.app', // no shell env when launched from Finder
  };
}

function load(win, page) {
  if (!dev) return win.loadFile(path.join(__dirname, '../dist', page));
  // Vite may still be booting when Electron starts; retry until it answers.
  win.webContents.on('did-fail-load', () => setTimeout(() => win.loadURL(`${DEV_URL}/${page}`), 400));
  win.loadURL(`${DEV_URL}/${page}`);
}

function makeWindow(opts, page) {
  const win = new BrowserWindow({
    backgroundColor: '#02040b',
    titleBarStyle: 'hiddenInset',
    trafficLightPosition: { x: 18, y: 20 },
    webPreferences: { preload: path.join(__dirname, 'preload.cjs'), contextIsolation: true, sandbox: true },
    ...opts,
  });
  load(win, page);
  return win;
}

ipcMain.on('open-genome', (_e, gene) => {
  const select = () => gene && genomeWin.webContents.send('genome-select', gene); // a cure to jump to, from a click in the main window
  if (genomeWin && !genomeWin.isDestroyed()) return genomeWin.focus(), select();
  genomeWin = makeWindow({ width: 1100, height: 760, minWidth: 640, minHeight: 480, title: 'Global genome' }, 'genome.html');
  genomeWin.webContents.once('did-finish-load', select);
});

ipcMain.handle('tcell:mesh-command', (_e, cmd) => backend?.sendMeshCommand(cmd));
ipcMain.handle('tcell:run-test-threat', () => backend?.runTestThreat());
ipcMain.handle('tcell:advisor-review', (_e, force) => backend?.getReview(force) ?? null);
ipcMain.handle('tcell:advisor-explain', (_e, block) => backend?.explainBlock(block) ?? null);
ipcMain.handle('tcell:signal-lineage', (_e, targets, sig) => backend?.signalLineage(targets, sig));
ipcMain.handle('tcell:escalate', (_e, schema, pid) => backend?.escalate(schema, pid));
ipcMain.handle('tcell:suppress-gene', (_e, threatIdHex) => backend?.suppressGene(threatIdHex));

app.whenReady().then(() => {
  if (!app.isPackaged) app.dock?.setIcon(path.join(__dirname, '../build/icon.png')); // packaged builds get it from the .icns
  backend = startBackend(app.isPackaged ? packagedPaths() : {});
  // Best-effort, real-time only -- a record emitted before a renderer's
  // listener attaches is lost, same as the Rust daemons themselves (no
  // history replay). Fine for non-critical startup lines.
  for (const channel of ['scout', 'soldier', 'mesh', 'ledger', 'wake', 'error', 'advisor', 'hoststats']) {
    backend.events.on(channel, (payload) => {
      for (const win of BrowserWindow.getAllWindows()) win.webContents.send('tcell:event', { channel, payload });
    });
  }

  makeWindow({ width: 1320, height: 860, minWidth: 1024, minHeight: 680, title: 'T-Cell' }, 'index.html');
  app.on('activate', () => BrowserWindow.getAllWindows().length || makeWindow({ width: 1320, height: 860 }, 'index.html'));
});
app.on('window-all-closed', () => process.platform === 'darwin' || app.quit());
app.on('before-quit', () => backend?.stop());
