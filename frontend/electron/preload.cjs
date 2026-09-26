const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('tcell', {
  openGenome: () => ipcRenderer.send('open-genome'),
});
