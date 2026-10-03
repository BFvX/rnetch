import { FolderSearch, Plus, Play, RefreshCw, Save, Square, Trash2 } from 'lucide-react';
import { useEffect, useMemo, useRef, useState } from 'react';
import TrafficChart from './TrafficChart.jsx';
import { appendTrafficSample, SPEED_BANDS, TRAFFIC_WINDOWS } from './traffic-history.mjs';

const emptyConfig = {
  backend: 'netfilter',
  udpTransport: 'socks5',
  gpux: {
    host: '127.0.0.1', port: '40000', token: '', encryption: 'chacha20-poly1305',
    mtu_payload: '1200', deadline_ms: '8', batch_window_us: '0', pacing_interval_us: '0',
    queue_limit: '512', fec_uplink: '0', fec_group_max_us: '2000'
  },
  socks5: {
    host: '127.0.0.1',
    port: '1080',
    user: '',
    pass: ''
  },
  rules: []
};

const emptyMetrics = {
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

function formatRate(value) {
  return `${formatBytes(value)}/s`;
}

function formatBytes(value) {
  const units = ['B', 'KB', 'MB', 'GB'];
  let size = Number(value) || 0;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${size >= 10 || unit === 0 ? size.toFixed(0) : size.toFixed(1)} ${units[unit]}`;
}

function App() {
  const api = window.rnetch;
  const [status, setStatus] = useState({ state: 'stopped', message: 'Rnetch is stopped.' });
  const [metrics, setMetrics] = useState(emptyMetrics);
  const [trafficHistory, setTrafficHistory] = useState([]);
  const [trafficWindow, setTrafficWindow] = useState(60);
  const [trafficTime, setTrafficTime] = useState(() => performance.now());
  const [config, setConfig] = useState(emptyConfig);
  const [logs, setLogs] = useState([]);
  const [paths, setPaths] = useState(null);
  const [errors, setErrors] = useState([]);
  const [scanSummary, setScanSummary] = useState(null);
  const [dirty, setDirty] = useState(false);
  const [busy, setBusy] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [initialLoading, setInitialLoading] = useState(true);
  const [logPinned, setLogPinned] = useState(true);
  const logListRef = useRef(null);

  const isRunning = status.active || ['running', 'started', 'starting', 'stopping'].includes(status.state);
  const socksActive = config.udpTransport === 'socks5' || config.rules.some((rule) => rule.tcp);
  const totals = useMemo(() => ({
    tcp: metrics.tcpUpBytes + metrics.tcpDownBytes,
    udp: metrics.udpUpBytes + metrics.udpDownBytes,
    all: metrics.tcpUpBytes + metrics.tcpDownBytes + metrics.udpUpBytes + metrics.udpDownBytes
  }), [metrics]);

  useEffect(() => {
    if (!api) {
      setErrors(['Electron bridge is unavailable. Start this UI with npm run dev from the ui directory.']);
      setInitialLoading(false);
      return undefined;
    }

    let mounted = true;
    let sawMetrics = false;
    let sawStatus = false;
    let previousStatus;
    const receiveStatus = (nextStatus) => {
      if (!mounted) return;
      sawStatus = true;
      if (nextStatus.state === 'starting' && previousStatus !== 'starting') {
        setTrafficHistory([]);
      }
      previousStatus = nextStatus.state;
      setStatus(nextStatus);
    };
    const receiveMetrics = (nextMetrics) => {
      if (!mounted) return;
      sawMetrics = true;
      const time = performance.now();
      setMetrics(nextMetrics);
      setTrafficTime(time);
      setTrafficHistory((history) => appendTrafficSample(history, nextMetrics, time));
    };
    const loadInitial = async () => {
      try {
        const state = await api.getState();
        const configResponse = await api.getConfig();
        if (!mounted) {
          return;
        }
        // IPC updates may arrive while configuration is loading; do not overwrite them.
        if (!sawStatus) receiveStatus(state.status);
        if (!sawMetrics) {
          setMetrics(state.metrics);
          if (state.status.active || ['started', 'running', 'stopping'].includes(state.status.state)) {
            receiveMetrics(state.metrics);
          }
        }
        setLogs(state.logs);
        setPaths(state.paths);
        setConfig(configResponse.config);
      } catch (error) {
        if (mounted) {
          setErrors([error.message]);
        }
      } finally {
        if (mounted) {
          setInitialLoading(false);
        }
      }
    };

    loadInitial();
    const unsubStatus = api.onStatus(receiveStatus);
    const unsubMetrics = api.onMetrics(receiveMetrics);
    const unsubLogs = api.onLogs(setLogs);

    return () => {
      mounted = false;
      unsubStatus();
      unsubMetrics();
      unsubLogs();
    };
  }, [api]);

  useEffect(() => {
    // Advance the time axis even when IPC is silent, without inventing rate samples.
    const timer = setInterval(() => setTrafficTime(performance.now()), 1000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    if (!logPinned || !logListRef.current) {
      return;
    }
    logListRef.current.scrollTop = logListRef.current.scrollHeight;
  }, [logs, logPinned]);

  const handleLogScroll = (event) => {
    const element = event.currentTarget;
    const distanceFromBottom = element.scrollHeight - element.scrollTop - element.clientHeight;
    setLogPinned(distanceFromBottom < 16);
  };

  const loadConfig = async () => {
    if (!api) {
      return;
    }
    setBusy(true);
    setErrors([]);
    try {
      const response = await api.getConfig();
      setConfig(response.config);
      setDirty(false);
    } catch (error) {
      setErrors([error.message]);
    } finally {
      setBusy(false);
    }
  };

  const saveConfig = async () => {
    setBusy(true);
    setErrors([]);
    try {
      const response = await api.saveConfig(config);
      if (!response.ok) {
        setErrors(response.errors);
        return;
      }
      setConfig(response.config);
      setDirty(false);
    } catch (error) {
      setErrors([error.message]);
    } finally {
      setBusy(false);
    }
  };

  const start = async () => {
    setBusy(true);
    setErrors([]);
    try {
      await api.start();
    } catch (error) {
      setErrors([error.message]);
    } finally {
      setBusy(false);
    }
  };

  const stop = async () => {
    setBusy(true);
    setErrors([]);
    try {
      await api.stop();
    } catch (error) {
      setErrors([error.message]);
    } finally {
      setBusy(false);
    }
  };

  const updateSocks = (field, value) => {
    setConfig((current) => ({
      ...current,
      socks5: {
        ...current.socks5,
        [field]: value
      }
    }));
    setDirty(true);
  };

  const updateGpux = (field, value) => {
    setConfig((current) => ({ ...current, gpux: { ...current.gpux, [field]: value } }));
    setDirty(true);
  };

  const updateRule = (index, patch) => {
    setConfig((current) => ({
      ...current,
      rules: current.rules.map((rule, ruleIndex) => (
        ruleIndex === index ? { ...rule, ...patch } : rule
      ))
    }));
    setDirty(true);
  };

  const addRule = () => {
    setConfig((current) => ({
      ...current,
      rules: [...current.rules, { name: 'process.exe', tcp: true, udp: true }]
    }));
    setDirty(true);
  };

  const scanDirectory = async () => {
    if (!api) {
      return;
    }

    setBusy(true);
    setScanning(true);
    setErrors([]);
    setScanSummary(null);
    try {
      const response = await api.scanExecutables();
      if (!response.ok) {
        setErrors([response.error]);
        return;
      }
      if (response.canceled) {
        return;
      }

      const existingNames = new Set(config.rules.map((rule) => rule.name.trim().toLocaleLowerCase('en-US')));
      const additions = response.executables.filter((name) => {
        const key = name.toLocaleLowerCase('en-US');
        if (existingNames.has(key)) {
          return false;
        }
        existingNames.add(key);
        return true;
      });

      if (additions.length > 0) {
        setConfig((current) => {
          const currentNames = new Set(current.rules.map((rule) => rule.name.trim().toLocaleLowerCase('en-US')));
          const newRules = additions
            .filter((name) => {
              const key = name.toLocaleLowerCase('en-US');
              if (currentNames.has(key)) {
                return false;
              }
              currentNames.add(key);
              return true;
            })
            .map((name) => ({ name, tcp: true, udp: true }));

          return newRules.length > 0
            ? { ...current, rules: [...current.rules, ...newRules] }
            : current;
        });
        setDirty(true);
      }

      const skippedDirectoryCount = response.skippedDirectories.length;
      const skippedExecutableCount = response.skippedExecutables.length;
      setScanSummary({
        warning: skippedDirectoryCount > 0 || skippedExecutableCount > 0,
        message: `Scanned ${response.directory}: found ${response.executables.length} unique executable name(s), added ${additions.length} new rule(s)`
          + `${skippedDirectoryCount > 0 ? `; ${skippedDirectoryCount} director${skippedDirectoryCount === 1 ? 'y was' : 'ies were'} unreadable` : ''}`
          + `${skippedExecutableCount > 0 ? `; ${skippedExecutableCount} executable name(s) could not be represented in config.xml` : ''}.`
      });
    } catch (error) {
      setErrors([error.message]);
    } finally {
      setScanning(false);
      setBusy(false);
    }
  };

  const deleteRule = (index) => {
    setConfig((current) => ({
      ...current,
      rules: current.rules.filter((_, ruleIndex) => ruleIndex !== index)
    }));
    setDirty(true);
  };

  return (
    <main className="app-shell" aria-busy={initialLoading || busy}>
      <header className="topbar">
        <div>
          <h1>Rnetch Control</h1>
          <p>{paths?.configPath ?? 'config.xml'}</p>
        </div>
        <div className={`status-pill status-${status.state}`}>
          <span />
          {status.message}
        </div>
      </header>

      <section className="control-strip">
        <button
          className="primary-button"
          onClick={start}
          disabled={!api || initialLoading || isRunning || busy}
          title="Start Rnetch"
        >
          <Play size={18} />
          Start
        </button>
        <button
          className="secondary-button"
          onClick={stop}
          disabled={!api || initialLoading || !isRunning || busy}
          title="Stop Rnetch"
        >
          <Square size={18} />
          Stop
        </button>
        <button
          className="secondary-button"
          onClick={loadConfig}
          disabled={!api || initialLoading || busy}
          title="Reload config.xml"
        >
          <RefreshCw size={18} />
          Reload
        </button>
        <button
          className="secondary-button"
          onClick={saveConfig}
          disabled={!api || initialLoading || busy || !dirty}
          title="Save config.xml"
        >
          <Save size={18} />
          Save
        </button>
        {dirty && <span className="change-note">{isRunning ? 'Changes apply after restart.' : 'Unsaved changes.'}</span>}
      </section>

      {errors.length > 0 && (
        <section className="error-panel" role="alert">
          {errors.map((error) => <p key={error}>{error}</p>)}
        </section>
      )}

      {scanSummary && (
        <section
          className={`scan-summary${scanSummary.warning ? ' scan-summary-warning' : ''}`}
          role="status"
          aria-live="polite"
        >
          <p>{scanSummary.message}</p>
        </section>
      )}

      <section className="traffic-section" aria-label="Live traffic">
        <div className="traffic-toolbar">
          <h2>Live traffic</h2>
          <div className="traffic-direction-legend" aria-label="Line styles">
            <span><i />Up</span>
            <span><i className="traffic-key-down" />Down</span>
          </div>
          <label className="traffic-window">
            Window
            <select value={trafficWindow} onChange={(event) => setTrafficWindow(Number(event.target.value))}>
              {TRAFFIC_WINDOWS.map((window) => <option key={window.seconds} value={window.seconds}>{window.label}</option>)}
            </select>
          </label>
        </div>
        <div className="metrics-grid">
          <MetricCard title="Total" protocol="total" up={metrics.totalUpBps} down={metrics.totalDownBps} total={totals.all} history={trafficHistory} windowSeconds={trafficWindow} now={trafficTime} />
          <MetricCard title="TCP" protocol="tcp" up={metrics.tcpUpBps} down={metrics.tcpDownBps} total={totals.tcp} history={trafficHistory} windowSeconds={trafficWindow} now={trafficTime} />
          <MetricCard title="UDP" protocol="udp" up={metrics.udpUpBps} down={metrics.udpDownBps} total={totals.udp} history={trafficHistory} windowSeconds={trafficWindow} now={trafficTime} />
        </div>
        <div className="traffic-speed-legend" aria-label="Speed colors">
          <span>Speed</span>
          {SPEED_BANDS.map((band) => <span key={band.label}><i style={{ backgroundColor: band.color }} />{band.label}</span>)}
        </div>
      </section>

      <section className="main-grid">
        <div className="panel config-panel">
          <div className="panel-heading">
            <h2>Connection</h2>
          </div>
          <div className="form-grid">
            <label>
              Capture driver
              <select
                disabled={initialLoading}
                value={config.backend}
                onChange={(event) => {
                  const backend = event.target.value;
                  setConfig((current) => ({ ...current, backend }));
                  setDirty(true);
                }}
              >
                <option value="netfilter">NetFilter</option>
                <option value="windivert">WinDivert</option>
              </select>
            </label>
            <label>
              UDP transport
              <select disabled={initialLoading} value={config.udpTransport} onChange={(event) => {
                const udpTransport = event.target.value;
                setConfig((current) => ({ ...current, udpTransport }));
                setDirty(true);
              }}>
                <option value="socks5">SOCKS5</option>
                <option value="gpux">GPUX</option>
              </select>
            </label>
            <p className="connection-note">
              {config.udpTransport === 'gpux'
                ? 'GPUX forwards selected UDP traffic to your GPUX server. TCP rules use SOCKS5.'
                : 'SOCKS5 forwards selected TCP and UDP traffic.'}
            </p>
            {config.udpTransport === 'gpux' && (
              <>
                <label>
                  GPUX host
                  <input disabled={initialLoading} value={config.gpux.host} onChange={(event) => updateGpux('host', event.target.value)} />
                </label>
                <label>
                  GPUX port
                  <input disabled={initialLoading} value={config.gpux.port} onChange={(event) => updateGpux('port', event.target.value)} inputMode="numeric" />
                </label>
                <label>
                  GPUX token
                  <input disabled={initialLoading} type="password" autoComplete="off" value={config.gpux.token} onChange={(event) => updateGpux('token', event.target.value)} />
                </label>
                <label>
                  GPUX encryption
                  <select disabled={initialLoading} value={config.gpux.encryption} onChange={(event) => updateGpux('encryption', event.target.value)}>
                    <option value="chacha20-poly1305">ChaCha20-Poly1305</option>
                    <option value="plaintext">Plaintext (local validation)</option>
                  </select>
                </label>
                <details className="transport-settings">
                  <summary>GPUX advanced settings</summary>
                  <div className="form-grid">
                    {[
                      ['mtu_payload', 'Tunnel payload limit (bytes)'],
                      ['deadline_ms', 'Packet deadline (ms)'],
                      ['batch_window_us', 'Batch window (µs)'],
                      ['pacing_interval_us', 'Pacing interval (µs)'],
                      ['queue_limit', 'Queue limit (datagrams)'],
                      ['fec_group_max_us', 'FEC group window (µs)']
                    ].map(([field, label]) => (
                      <label key={field}>{label}
                        <input disabled={initialLoading} value={config.gpux[field]} onChange={(event) => updateGpux(field, event.target.value)} inputMode="numeric" />
                      </label>
                    ))}
                    <label>
                      Uplink FEC
                      <select disabled={initialLoading} value={config.gpux.fec_uplink} onChange={(event) => updateGpux('fec_uplink', event.target.value)}>
                        <option value="0">Off</option>
                        <option value="1">On (up to 4+1)</option>
                      </select>
                    </label>
                  </div>
                </details>
              </>
            )}
            <p className="connection-note">
              {config.udpTransport === 'gpux'
                ? (socksActive ? 'SOCKS5 connection for TCP rules.' : 'SOCKS5 is optional until a TCP rule is enabled.')
                : 'SOCKS5 connection'}
            </p>
            <label>
              SOCKS5 host
              <input disabled={initialLoading || !socksActive} value={config.socks5.host} onChange={(event) => updateSocks('host', event.target.value)} />
            </label>
            <label>
              Port
              <input disabled={initialLoading || !socksActive} value={config.socks5.port} onChange={(event) => updateSocks('port', event.target.value)} inputMode="numeric" />
            </label>
            <label>
              Username
              <input disabled={initialLoading || !socksActive} value={config.socks5.user} onChange={(event) => updateSocks('user', event.target.value)} />
            </label>
            <label>
              Password
              <input disabled={initialLoading || !socksActive} type="password" value={config.socks5.pass} onChange={(event) => updateSocks('pass', event.target.value)} />
            </label>
          </div>
        </div>

        <div className="panel log-panel">
          <div className="panel-heading">
            <h2>Runtime Log</h2>
          </div>
          <div className="log-list" ref={logListRef} onScroll={handleLogScroll}>
            {logs.slice(-80).map((entry, index) => (
              <div className={`log-line log-${entry.level}`} key={`${entry.time}-${index}`}>
                <time>{new Date(entry.time).toLocaleTimeString()}</time>
                <span>{entry.line}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="panel rules-panel" aria-busy={scanning}>
        <div className="panel-heading">
          <h2>Process Rules</h2>
          <div className="panel-actions">
            <button
              className="secondary-button"
              onClick={scanDirectory}
              disabled={!api || initialLoading || busy}
              title="Recursively scan a folder for executable files"
            >
              <FolderSearch size={17} />
              {scanning ? 'Scanning...' : 'Scan Folder'}
            </button>
            <button className="icon-button" onClick={addRule} disabled={initialLoading || busy} title="Add process rule">
              <Plus size={18} />
            </button>
          </div>
        </div>
        <div className="rules-table">
          <div className="rules-header">
            <span>Executable</span>
            <span>TCP</span>
            <span>UDP</span>
            <span />
          </div>
          {config.rules.map((rule, index) => (
            <div className="rules-row" key={`${rule.name}-${index}`}>
              <input
                value={rule.name}
                disabled={initialLoading || scanning}
                onChange={(event) => updateRule(index, { name: event.target.value })}
              />
              <input
                type="checkbox"
                checked={rule.tcp}
                disabled={initialLoading || scanning}
                onChange={(event) => updateRule(index, { tcp: event.target.checked })}
                title="Accelerate TCP"
              />
              <input
                type="checkbox"
                checked={rule.udp}
                disabled={initialLoading || scanning}
                onChange={(event) => updateRule(index, { udp: event.target.checked })}
                title="Accelerate UDP"
              />
              <button
                className="icon-button danger"
                onClick={() => deleteRule(index)}
                disabled={initialLoading || scanning}
                title="Delete rule"
              >
                <Trash2 size={17} />
              </button>
            </div>
          ))}
        </div>
      </section>
    </main>
  );
}

function MetricCard({ title, protocol, up, down, total, history, windowSeconds, now }) {
  return (
    <article className="metric-card">
      <div>
        <h2>{title}</h2>
        <p>{formatBytes(total)} total</p>
      </div>
      <dl>
        <div>
          <dt>Up</dt>
          <dd>{formatRate(up)}</dd>
        </div>
        <div>
          <dt>Down</dt>
          <dd>{formatRate(down)}</dd>
        </div>
      </dl>
      <TrafficChart title={title} protocol={protocol} history={history} windowSeconds={windowSeconds} now={now} formatRate={formatRate} />
    </article>
  );
}

export default App;
