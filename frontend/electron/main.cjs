const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('node:path');
const { startBackend } = require('./backend.cjs');

const DEV_URL = 'http://localhost:5174';
const dev = !!process.env.TCELL_DEV;
let genomeWin = null;
let backend = null;

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

ipcMain.on('open-genome', () => {
  if (genomeWin && !genomeWin.isDestroyed()) return genomeWin.focus();
  genomeWin = makeWindow({ width: 1100, height: 760, minWidth: 640, minHeight: 480, title: 'Global genome' }, 'genome.html');
});

ipcMain.handle('tcell:mesh-command', (_e, cmd) => backend?.sendMeshCommand(cmd));
ipcMain.handle('tcell:run-test-threat', () => backend?.runTestThreat());
ipcMain.handle('tcell:advisor-review', (_e, force) => backend?.getReview(force) ?? null);

app.whenReady().then(() => {
  backend = startBackend();
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
