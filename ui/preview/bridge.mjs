// Vite-only preview entry. Not imported by the production renderer or build.
// Every operation is in memory: no driver, network, filesystem or Electron IPC.
import './preview.css';
const subscribers = { status: new Set(), metrics: new Set(), logs: new Set() };
const clone = (value) => structuredClone(value);
let config = {
  backend: 'netfilter', udpTransport: 'socks5',
  socks5: { host: '127.0.0.1', port: '1080', user: '', pass: '' },
  gpux: {
    host: '127.0.0.1', port: '40000', token: '', encryption: 'chacha20-poly1305',
    mtu_payload: '1200', deadline_ms: '8', batch_window_us: '0', pacing_interval_us: '0',
    queue_limit: '512', fec_uplink: '0', fec_group_max_us: '2000'
  },
  rules: [
    { name: 'chrome.exe', tcp: true, udp: false },
    { name: 'Discord.exe', tcp: true, udp: true },
    { name: 'steam.exe', tcp: true, udp: true },
    { name: 'game.exe', tcp: false, udp: true }
  ]
};
let status = { state: 'running', active: true, message: 'Preview proxy is running.' };
let tick = 0;
const metrics = {
  tcpUpBps: 0, tcpDownBps: 0, udpUpBps: 0, udpDownBps: 0, totalUpBps: 0, totalDownBps: 0,
  tcpUpBytes: 86 * 1024 ** 2, tcpDownBytes: 324 * 1024 ** 2,
  udpUpBytes: 21 * 1024 ** 2, udpDownBytes: 67 * 1024 ** 2
};
let logs = [
  { level: 'info', line: 'Design preview — all traffic and operations are simulated.', time: new Date(Date.now() - 6000).toISOString() },
  { level: 'info', line: 'NetFilter selected · SOCKS5 endpoint 127.0.0.1:1080', time: new Date(Date.now() - 5000).toISOString() },
  { level: 'info', line: 'Loaded 4 process rules. Unmatched traffic stays direct.', time: new Date(Date.now() - 3000).toISOString() },
  { level: 'info', line: 'Preview session ready. Waiting for traffic samples.', time: new Date().toISOString() }
];
const emit = (channel, value) => subscribers[channel].forEach((callback) => callback(clone(value)));
const subscribe = (channel, callback) => {
  subscribers[channel].add(callback);
  return () => subscribers[channel].delete(callback);
};
const addLog = (line) => {
  logs = [...logs, { level: 'info', line, time: new Date().toISOString() }].slice(-80);
  emit('logs', logs);
};
function sample() {
  const moving = status.active;
  metrics.tcpUpBps = moving ? Math.round(160000 + 110000 * (1 + Math.sin(tick / 3))) : 0;
  metrics.tcpDownBps = moving ? Math.round(900000 + 580000 * (1 + Math.sin(tick / 4))) : 0;
  metrics.udpUpBps = moving ? Math.round(42000 + 19000 * (1 + Math.cos(tick / 2))) : 0;
  metrics.udpDownBps = moving ? Math.round(180000 + 87000 * (1 + Math.cos(tick / 3))) : 0;
  metrics.totalUpBps = metrics.tcpUpBps + metrics.udpUpBps;
  metrics.totalDownBps = metrics.tcpDownBps + metrics.udpDownBps;
  for (const protocol of ['tcp', 'udp']) {
    for (const direction of ['Up', 'Down']) {
      metrics[`${protocol}${direction}Bytes`] += metrics[`${protocol}${direction}Bps`];
    }
  }
  tick += 1;
  emit('metrics', metrics);
}
sample();
window.rnetch = {
  getState: async () => clone({ status, metrics, logs, paths: { configPath: 'Preview workspace / config.xml' } }),
  getConfig: async () => ({ config: clone(config) }),
  saveConfig: async (next) => {
    config = clone(next);
    addLog('Preview configuration saved in memory.');
    return { ok: true, config: clone(config) };
  },
  start: async () => {
    status = { state: 'running', active: true, message: 'Preview proxy is running.' };
    emit('status', status);
    addLog('Simulated proxy started.');
  },
  stop: async () => {
    status = { state: 'stopped', active: false, message: 'Preview proxy is stopped.' };
    emit('status', status);
    sample();
    addLog('Simulated proxy stopped.');
  },
  scanExecutables: async () => ({
    ok: true, canceled: false, directory: 'Preview folder',
    executables: ['chrome.exe', 'Discord.exe', 'steam.exe', 'game.exe', 'example.exe'],
    skippedDirectories: [], skippedExecutables: []
  }),
  onStatus: (callback) => subscribe('status', callback),
  onMetrics: (callback) => subscribe('metrics', callback),
  onLogs: (callback) => subscribe('logs', callback)
};
setInterval(sample, 1000);
await import('../src/main.jsx');
