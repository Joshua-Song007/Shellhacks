const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('tcell', {
  openGenome: (gene) => ipcRenderer.send('open-genome', gene),
  onGenomeSelect: (cb) => ipcRenderer.on('genome-select', (_e, gene) => cb(gene)),
  onEvent: (cb) => {
    const listener = (_e, msg) => cb(msg);
    ipcRenderer.on('tcell:event', listener);
    return () => ipcRenderer.removeListener('tcell:event', listener);
  },
  sendMeshCommand: (cmd) => ipcRenderer.invoke('tcell:mesh-command', cmd),
  runTestThreat: () => ipcRenderer.invoke('tcell:run-test-threat'),
  getReview: (force) => ipcRenderer.invoke('tcell:advisor-review', force),
  explainBlock: (block) => ipcRenderer.invoke('tcell:advisor-explain', block),
  signalLineage: (targets, sig) => ipcRenderer.invoke('tcell:signal-lineage', targets, sig),
  escalate: (schema, pid) => ipcRenderer.invoke('tcell:escalate', schema, pid),
  suppressGene: (threatIdHex) => ipcRenderer.invoke('tcell:suppress-gene', threatIdHex),
});
