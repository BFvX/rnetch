const { contextBridge, ipcRenderer } = require('electron');

function subscribe(channel, callback) {
  const listener = (_event, payload) => callback(payload);
  ipcRenderer.on(channel, listener);
  return () => ipcRenderer.removeListener(channel, listener);
}

contextBridge.exposeInMainWorld('rnetch', {
  start: () => ipcRenderer.invoke('rnetch:start'),
  stop: () => ipcRenderer.invoke('rnetch:stop'),
  getState: () => ipcRenderer.invoke('rnetch:get-state'),
  getConfig: () => ipcRenderer.invoke('rnetch:get-config'),
  saveConfig: (config) => ipcRenderer.invoke('rnetch:save-config', config),
  scanExecutables: () => ipcRenderer.invoke('rnetch:scan-executables'),
  onStatus: (callback) => subscribe('rnetch:status', callback),
  onMetrics: (callback) => subscribe('rnetch:metrics', callback),
  onLogs: (callback) => subscribe('rnetch:logs', callback)
});
