import { Activity, AppWindow, ArrowDown, ArrowUp, ChevronRight, FileCode2, FolderSearch, LayoutDashboard, Monitor, Network, Plus, Play, RefreshCw, Save, Search, Settings2, Square, Terminal, Trash2 } from 'lucide-react';
import { useEffect, useMemo, useRef, useState } from 'react';
import TrafficChart from './TrafficChart.jsx';
import { appendTrafficSample, SPEED_BANDS, TRAFFIC_WINDOWS } from './traffic-history.mjs';
import rnetchMark from '../assets/rnetch-mark.png';

const NAVIGATION_ITEMS = [
  ['overview', 'Overview', LayoutDashboard],
  ['connection', 'Connection', Settings2],
  ['rules', 'Process rules', AppWindow],
  ['logs', 'Runtime log', Terminal]
];

function currentSection() {
  const section = window.location.hash.slice(1);
  return NAVIGATION_ITEMS.some(([id]) => id === section) ? section : 'overview';
}

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
  const [activeSection, setActiveSection] = useState(currentSection);
  const [ruleFilter, setRuleFilter] = useState('');
  const logListRef = useRef(null);

  const isRunning = status.active || ['running', 'started', 'starting', 'stopping'].includes(status.state);
  const socksActive = config.udpTransport === 'socks5' || config.rules.some((rule) => rule.tcp);
  const visibleRules = config.rules
    .map((rule, index) => ({ rule, index }))
    .filter(({ rule }) => rule.name.toLocaleLowerCase('en-US').includes(ruleFilter.trim().toLocaleLowerCase('en-US')));
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
    const updateSection = () => setActiveSection(currentSection());
    window.addEventListener('hashchange', updateSection);
    return () => window.removeEventListener('hashchange', updateSection);
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
    setRuleFilter('');
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
    <div className="app-shell" aria-busy={initialLoading || busy}>
      <a className="skip-link" href="#overview" onClick={() => setActiveSection('overview')}>Skip to overview</a>
      <aside className="sidebar" aria-label="Workspace">
        <a className="brand" href="#overview" aria-label="Rnetch Control overview" onClick={() => setActiveSection('overview')}>
          <span className="brand-mark"><img src={rnetchMark} alt="" width="40" height="40" /></span>
          <span>rnetch<span className="brand-caption">CONTROL</span></span>
        </a>
        <span className="nav-caption">WORKSPACE</span>
        <nav aria-label="Main navigation">
          {NAVIGATION_ITEMS.map(([id, label, Icon]) => (
            <a key={id} href={`#${id}`} className={`nav-link${activeSection === id ? ' active' : ''}`}
              aria-label={label} title={label}
              aria-current={activeSection === id ? 'location' : undefined} onClick={() => setActiveSection(id)}>
              <Icon aria-hidden="true" size={18} /><span>{label}</span>
              {id === 'rules' && <span className="nav-count">{config.rules.length}</span>}
            </a>
          ))}
        </nav>
        <div className="sidebar-footer">
          <div className="local-workspace"><Monitor aria-hidden="true" size={17} /><span>Local workspace<small>Windows · x64</small></span></div>
          <span className="sidebar-footnote">Process-selective proxy</span>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar" id="overview">
          <div>
            <div className="breadcrumb">Workspace <ChevronRight aria-hidden="true" size={13} /><span>Overview</span></div>
            <h1>Network overview</h1>
            <p>Monitor traffic and route selected processes.</p>
          </div>
          <div className={`status-pill status-${status.state}`} role="status" title={status.message}>
            <span className="status-dot" />
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
            <Play aria-hidden="true" size={18} />
            Start proxy
          </button>
          <button
            className="secondary-button quiet-button"
            onClick={stop}
            disabled={!api || initialLoading || !isRunning || busy}
            title="Stop Rnetch"
          >
            <Square aria-hidden="true" size={18} />
            Stop
          </button>
          <span className="control-divider" aria-hidden="true" />
          <button
            className="secondary-button"
            onClick={loadConfig}
            disabled={!api || initialLoading || busy}
            title="Reload config.xml"
          >
            <RefreshCw aria-hidden="true" size={18} />
            Reload
          </button>
          <button
            className="secondary-button"
            onClick={saveConfig}
            disabled={!api || initialLoading || busy || !dirty}
            title="Save config.xml"
          >
            <Save aria-hidden="true" size={18} />
            Save config
          </button>
          <span className={`config-state${dirty ? ' config-state-dirty' : ''}`}>
            <span />{dirty ? (isRunning ? 'Unsaved · restart to apply' : 'Unsaved changes') : 'No pending changes'}
          </span>
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
            <div className="section-title"><Activity aria-hidden="true" size={17} /><h2>Live traffic</h2></div>
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
            <MetricCard title="Total traffic" protocol="total" up={metrics.totalUpBps} down={metrics.totalDownBps} total={totals.all} history={trafficHistory} windowSeconds={trafficWindow} now={trafficTime} />
            <MetricCard title="TCP" protocol="tcp" up={metrics.tcpUpBps} down={metrics.tcpDownBps} total={totals.tcp} history={trafficHistory} windowSeconds={trafficWindow} now={trafficTime} />
            <MetricCard title="UDP" protocol="udp" up={metrics.udpUpBps} down={metrics.udpDownBps} total={totals.udp} history={trafficHistory} windowSeconds={trafficWindow} now={trafficTime} />
          </div>
          <div className="traffic-speed-legend" aria-label="Speed colors">
            <span>Speed</span>
            {SPEED_BANDS.map((band) => <span key={band.label}><i style={{ backgroundColor: band.color }} />{band.label}</span>)}
          </div>
        </section>

        <section className="main-grid">
          <section className="panel config-panel" id="connection" aria-labelledby="connection-title">
            <div className="panel-heading">
              <div className="panel-title"><span className="panel-icon"><Settings2 aria-hidden="true" size={18} /></span><div><h2 id="connection-title">Connection</h2><p>Your proxy endpoint & transport</p></div></div>
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
                    <input disabled={initialLoading} spellCheck={false} value={config.gpux.host} onChange={(event) => updateGpux('host', event.target.value)} />
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
                <input disabled={initialLoading || !socksActive} spellCheck={false} value={config.socks5.host} onChange={(event) => updateSocks('host', event.target.value)} />
              </label>
              <label>
                Port
                <input disabled={initialLoading || !socksActive} value={config.socks5.port} onChange={(event) => updateSocks('port', event.target.value)} inputMode="numeric" />
              </label>
              <label>
                Username
                <input disabled={initialLoading || !socksActive} autoComplete="off" placeholder="Optional" value={config.socks5.user} onChange={(event) => updateSocks('user', event.target.value)} />
              </label>
              <label>
                Password
                <input disabled={initialLoading || !socksActive} type="password" autoComplete="off" placeholder="Optional" value={config.socks5.pass} onChange={(event) => updateSocks('pass', event.target.value)} />
              </label>
            </div>
            <div className="panel-footnote"><Network aria-hidden="true" size={14} />Only matched processes use this connection.</div>
          </section>

          <section className="panel rules-panel" id="rules" aria-labelledby="rules-title" aria-busy={scanning}>
            <div className="panel-heading">
              <div className="panel-title"><span className="panel-icon"><AppWindow aria-hidden="true" size={18} /></span><div><h2 id="rules-title">Process rules <span className="count-badge">{config.rules.length}</span></h2><p>Choose what goes through the proxy</p></div></div>
              <button className="icon-button add-button" onClick={addRule} disabled={initialLoading || busy} title="Add process rule" aria-label="Add process rule">
                <Plus aria-hidden="true" size={18} />
              </button>
            </div>
            <div className="rules-toolbar">
              <label className="rule-search"><Search aria-hidden="true" size={16} /><input type="search" aria-label="Filter process rules" placeholder="Find a process…" value={ruleFilter} onChange={(event) => setRuleFilter(event.target.value)} /></label>
              <div className="panel-actions">
                <button
                  className="secondary-button"
                  onClick={scanDirectory}
                  disabled={!api || initialLoading || busy}
                  title="Recursively scan a folder for executable files"
                >
                  <FolderSearch aria-hidden="true" size={17} />
                  {scanning ? 'Scanning...' : 'Scan folder'}
                </button>
              </div>
            </div>
            <div className="rules-table">
              <div className="rules-header">
                <span>PROCESS NAME</span>
                <span>TCP</span>
                <span>UDP</span>
                <span />
              </div>
              {visibleRules.map(({ rule, index }) => (
                <div className="rules-row" key={index}>
                  <div className="process-name"><AppWindow aria-hidden="true" size={16} /><input
                    value={rule.name}
                    aria-label={`Process name ${index + 1}`}
                    spellCheck={false}
                    disabled={initialLoading || scanning}
                    onChange={(event) => updateRule(index, { name: event.target.value })}
                  /></div>
                  <input
                    type="checkbox"
                    checked={rule.tcp}
                    disabled={initialLoading || scanning}
                    onChange={(event) => updateRule(index, { tcp: event.target.checked })}
                    title="Accelerate TCP"
                    aria-label={`TCP for process ${index + 1}`}
                  />
                  <input
                    type="checkbox"
                    checked={rule.udp}
                    disabled={initialLoading || scanning}
                    onChange={(event) => updateRule(index, { udp: event.target.checked })}
                    title="Accelerate UDP"
                    aria-label={`UDP for process ${index + 1}`}
                  />
                  <button
                    className="icon-button danger"
                    onClick={() => deleteRule(index)}
                    disabled={initialLoading || scanning}
                    title="Delete rule"
                    aria-label={`Delete process rule ${index + 1}`}
                  >
                    <Trash2 aria-hidden="true" size={17} />
                  </button>
                </div>
              ))}
              {visibleRules.length === 0 && (
                <div className="empty-state">
                  <AppWindow aria-hidden="true" size={28} strokeWidth={1.5} />
                  <h3>{config.rules.length === 0 ? 'No process rules yet' : 'No matching processes'}</h3>
                  <p>{config.rules.length === 0 ? 'Add an executable to route its TCP or UDP traffic.' : 'Try a different process name.'}</p>
                  {config.rules.length === 0 && <button className="secondary-button" onClick={addRule} disabled={initialLoading || busy}><Plus aria-hidden="true" size={16} />Add your first process</button>}
                </div>
              )}
            </div>
            <div className="rules-footer"><span>{ruleFilter ? `${visibleRules.length} of ${config.rules.length}` : config.rules.length} process{config.rules.length === 1 ? '' : 'es'}</span><span>Unmatched traffic stays direct</span></div>
          </section>
        </section>

        <section className="panel log-panel" id="logs" aria-labelledby="logs-title">
          <div className="panel-heading">
            <div className="panel-title"><span className="panel-icon"><Terminal aria-hidden="true" size={18} /></span><div><h2 id="logs-title">Runtime log</h2><p>What’s happening behind the connection</p></div></div>
            <button className={`secondary-button quiet-button${logPinned ? ' is-following' : ''}`} onClick={() => setLogPinned((value) => !value)} aria-pressed={logPinned}>
              <ArrowDown aria-hidden="true" size={15} />{logPinned ? 'Following latest' : 'Auto-scroll paused'}
            </button>
          </div>
          <div className="log-list" ref={logListRef} onScroll={handleLogScroll} tabIndex={0} aria-label="Runtime log entries">
            {logs.length === 0 && <div className="log-empty"><Terminal aria-hidden="true" size={23} /><div><strong>Quiet for now.</strong><p>Runtime events will appear here when the proxy starts.</p></div></div>}
            {logs.slice(-80).map((entry, index) => (
              <div className={`log-line log-${entry.level}`} key={`${entry.time}-${index}`}>
                <time>{new Date(entry.time).toLocaleTimeString()}</time>
                <span className="log-level">{entry.level}</span>
                <span>{entry.line}</span>
              </div>
            ))}
          </div>
        </section>
        <footer className="workspace-footer"><span title={paths?.configPath ?? 'config.xml'}><FileCode2 aria-hidden="true" size={14} />{paths?.configPath ?? 'config.xml'}</span><span>{config.backend === 'windivert' ? 'WinDivert' : 'NetFilter'}<span className="footer-dot">·</span>{config.udpTransport.toUpperCase()}</span></footer>
      </main>
    </div>
  );
}

function MetricCard({ title, protocol, up, down, total, history, windowSeconds, now }) {
  return (
    <article className={`metric-card metric-card-${protocol}`}>
      <div className="metric-heading">
        <h3>{protocol === 'total' ? <Activity aria-hidden="true" size={16} /> : <Network aria-hidden="true" size={16} />}{title}</h3>
        <span className="metric-total" title="Total transferred">{formatBytes(total)}</span>
      </div>
      <dl>
        <div>
          <dt><ArrowUp aria-hidden="true" size={13} />Upload</dt>
          <dd title={formatRate(up)}>{formatRate(up)}</dd>
        </div>
        <div>
          <dt><ArrowDown aria-hidden="true" size={13} />Download</dt>
          <dd title={formatRate(down)}>{formatRate(down)}</dd>
        </div>
      </dl>
      <TrafficChart title={title} protocol={protocol} history={history} windowSeconds={windowSeconds} now={now} formatRate={formatRate} />
    </article>
  );
}

export default App;
