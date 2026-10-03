const { app, BrowserWindow, dialog, ipcMain } = require('electron');
const { spawn } = require('node:child_process');
const fsSync = require('node:fs');
const fs = require('node:fs/promises');
const path = require('node:path');
const readline = require('node:readline');
const { parseConfigXml, validateConfig, buildConfigXml } = require('./config');
const { scanExecutableDirectory } = require('./executable-scanner');
const { decodeNativeLine } = require('./native-events');
const { createDiagnosticLog } = require('./diagnostic-log');
const { getConfigPaths, ensureConfigFile } = require('./config-file');

const repoRoot = path.resolve(__dirname, '..', '..');
const devUserDataPath = path.join(repoRoot, '.cache', 'rnetch-ui-electron');

if (!app.isPackaged) {
  app.setPath('userData', devUserDataPath);
}

const userDataPath = app.getPath('userData');
const diagnosticLog = createDiagnosticLog(path.join(userDataPath, 'logs'));
const nativeExePath = app.isPackaged
  ? path.join(process.resourcesPath, 'native', 'rnetch.exe')
  : path.join(repoRoot, 'target', 'release', 'rnetch.exe');
const { defaultConfigPath, configPath } = getConfigPaths({
  isPackaged: app.isPackaged,
  repoRoot,
  resourcesPath: process.resourcesPath,
  userDataPath
});

let mainWindow = null;
let activeProcess = null;
let stopTimer = null;
let flushingOnQuit = false;
let quitAfterFlush = false;
let currentStatus = {
  state: 'stopped',
  message: 'Rnetch is stopped.',
  active: false
};
let latestMetrics = emptyMetrics();
const logs = [];

function emptyMetrics() {
  return {
    tcpUpBps: 0,
    tcpDownBps: 0,
    udpUpBps: 0,
    udpDownBps: 0,
    totalUpBps: 0,
    totalDownBps: 0,
    tcpUpBytes: 0,
    tcpDownBytes: 0,
    udpUpBytes: 0,
    udpDownBytes: 0
  };
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1180,
    height: 780,
    minWidth: 980,
    minHeight: 680,
    backgroundColor: '#f4f6f8',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false
    }
  });

  const devServerUrl = process.env.VITE_DEV_SERVER_URL;
  if (devServerUrl) {
    mainWindow.loadURL(devServerUrl);
  } else {
    mainWindow.loadFile(path.join(__dirname, '..', 'dist', 'index.html'));
  }
}

function send(channel, payload) {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send(channel, payload);
  }
}

function setStatus(state, message) {
  currentStatus = { state, message, active: Boolean(activeProcess) };
  send('rnetch:status', currentStatus);
}

function addLog(level, line) {
  const entry = {
    level,
    line,
    time: new Date().toISOString()
  };
  logs.push(entry);
  diagnosticLog.append(entry);
  if (logs.length > 300) {
    logs.shift();
  }
  send('rnetch:logs', logs);
}

function handleNativeLine(line) {
  const update = decodeNativeLine(line);
  if (update.status) {
    setStatus(update.status.state, update.status.message);
  }
  if (update.metrics) {
    latestMetrics = { ...emptyMetrics(), ...update.metrics };
    send('rnetch:metrics', latestMetrics);
  }
  update.logs.forEach((entry) => addLog(entry.level, entry.line));
}

async function readConfig() {
  await ensureConfigFile(configPath, defaultConfigPath);
  const xml = await fs.readFile(configPath, 'utf8');
  return parseConfigXml(xml);
}

async function startNative() {
  if (activeProcess) {
    return { ok: true, status: currentStatus };
  }

  await ensureConfigFile(configPath, defaultConfigPath);
  if (!fsSync.existsSync(nativeExePath)) {
    const message = `Native executable was not found: ${nativeExePath}`;
    setStatus('error', message);
    addLog('error', message);
    return { ok: false, status: currentStatus, error: message };
  }

  setStatus('starting', 'Starting Rnetch...');
  latestMetrics = emptyMetrics();
  send('rnetch:metrics', latestMetrics);

  activeProcess = spawn(nativeExePath, [configPath], {
    cwd: path.dirname(nativeExePath),
    stdio: ['pipe', 'pipe', 'pipe'],
    windowsHide: true
  });

  const proc = activeProcess;
  addLog('info', `Started ${nativeExePath}`);

  readline.createInterface({ input: proc.stdout }).on('line', handleNativeLine);
  readline.createInterface({ input: proc.stderr }).on('line', (line) => {
    addLog('error', line);
  });

  proc.on('error', (error) => {
    if (activeProcess === proc) {
      activeProcess = null;
    }
    setStatus('error', error.message);
    addLog('error', error.message);
  });

  proc.on('exit', (code, signal) => {
    if (stopTimer) {
      clearTimeout(stopTimer);
      stopTimer = null;
    }
    if (activeProcess === proc) {
      activeProcess = null;
    }
    latestMetrics = emptyMetrics();
    send('rnetch:metrics', latestMetrics);

    if (code === 0) {
      setStatus('stopped', 'Rnetch stopped.');
    } else {
      setStatus('error', `Rnetch exited with code ${code ?? 'unknown'}${signal ? ` (${signal})` : ''}.`);
    }
  });

  return { ok: true, status: currentStatus };
}

function stopNative() {
  if (!activeProcess) {
    setStatus('stopped', 'Rnetch is stopped.');
    return { ok: true, status: currentStatus };
  }

  if (stopTimer) {
    return { ok: true, status: currentStatus };
  }

  setStatus('stopping', 'Stopping Rnetch...');
  activeProcess.stdin.write('\n');
  activeProcess.stdin.end();

  stopTimer = setTimeout(() => {
    if (activeProcess) {
      addLog('error', 'Rnetch did not stop after 15 seconds; terminating process.');
      activeProcess.kill();
    }
  }, 15000);

  return { ok: true, status: currentStatus };
}

async function selectAndScanExecutableDirectory() {
  try {
    const result = await dialog.showOpenDialog(mainWindow, {
      title: 'Select a folder to scan for executables',
      buttonLabel: 'Scan Folder',
      properties: ['openDirectory']
    });

    if (result.canceled || result.filePaths.length === 0) {
      return { ok: true, canceled: true };
    }

    const directory = result.filePaths[0];
    const scanResult = await scanExecutableDirectory(directory);
    const skippedDirectoryCount = scanResult.skippedDirectories.length;
    const skippedExecutableCount = scanResult.skippedExecutables.length;
    const hasWarnings = skippedDirectoryCount > 0 || skippedExecutableCount > 0;
    scanResult.skippedExecutables.forEach((entry) => {
      addLog('error', `Skipped ${entry.path}: ${entry.reason}.`);
    });
    addLog(
      hasWarnings ? 'error' : 'info',
      `Scanned ${directory}: found ${scanResult.executables.length} unique executable name(s)`
        + `${skippedDirectoryCount > 0 ? `; skipped ${skippedDirectoryCount} unreadable director${skippedDirectoryCount === 1 ? 'y' : 'ies'}` : ''}`
        + `${skippedExecutableCount > 0 ? `; skipped ${skippedExecutableCount} unsupported executable name(s)` : ''}.`
    );

    return {
      ok: true,
      canceled: false,
      directory,
      executables: scanResult.executables,
      skippedDirectories: scanResult.skippedDirectories,
      skippedExecutables: scanResult.skippedExecutables
    };
  } catch (error) {
    const message = `Failed to scan executable directory: ${error.message}`;
    addLog('error', message);
    return { ok: false, error: message };
  }
}

ipcMain.handle('rnetch:start', () => startNative());
ipcMain.handle('rnetch:stop', () => stopNative());
ipcMain.handle('rnetch:scan-executables', () => selectAndScanExecutableDirectory());
ipcMain.handle('rnetch:get-state', () => ({
  status: currentStatus,
  metrics: latestMetrics,
  logs,
  paths: {
    nativeExePath,
    configPath,
    userDataPath,
    logPath: diagnosticLog.filePath
  }
}));
ipcMain.handle('rnetch:get-config', async () => ({
  ok: true,
  config: await readConfig(),
  path: configPath
}));
ipcMain.handle('rnetch:save-config', async (_event, config) => {
  const { normalized, errors } = validateConfig(config);
  if (errors.length > 0) {
    return { ok: false, errors };
  }
  await fs.mkdir(path.dirname(configPath), { recursive: true });
  await fs.writeFile(configPath, buildConfigXml(normalized), 'utf8');
  addLog('info', `Saved ${configPath}`);
  return { ok: true, config: normalized };
});

const singleInstanceLock = app.requestSingleInstanceLock();

if (!singleInstanceLock) {
  app.quit();
} else {
  app.on('second-instance', () => {
    if (mainWindow) {
      if (mainWindow.isMinimized()) {
        mainWindow.restore();
      }
      mainWindow.focus();
    }
  });

  app.whenReady().then(() => {
    addLog('info', `Local diagnostic log: ${diagnosticLog.filePath}`);
    createWindow();
  });
}

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('before-quit', (event) => {
  if (quitAfterFlush) return;
  event.preventDefault();
  if (flushingOnQuit) return;
  flushingOnQuit = true;
  try {
    if (activeProcess) stopNative();
  } catch (error) {
    addLog('error', `Failed to request native shutdown: ${error.message}`);
  }
  // A stalled/unwritable log destination must never prevent app shutdown.
  diagnosticLog.flush(1000).finally(() => {
    quitAfterFlush = true;
    app.quit();
  });
});
