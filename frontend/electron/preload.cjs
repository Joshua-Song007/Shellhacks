const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('tcell', {
  openGenome: () => ipcRenderer.send('open-genome'),
  onEvent: (cb) => {
    const listener = (_e, msg) => cb(msg);
    ipcRenderer.on('tcell:event', listener);
    return () => ipcRenderer.removeListener('tcell:event', listener);
  },
  sendMeshCommand: (cmd) => ipcRenderer.invoke('tcell:mesh-command', cmd),
  runTestThreat: () => ipcRenderer.invoke('tcell:run-test-threat'),
});
