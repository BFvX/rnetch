const { XMLBuilder, XMLParser, XMLValidator } = require('fast-xml-parser');

const BACKENDS = ['netfilter', 'windivert'];
const UDP_TRANSPORTS = ['socks5', 'gpux'];
const GPUX_ENCRYPTIONS = ['plaintext', 'chacha20-poly1305'];
const SOCKS5_DEFAULTS = { host: '127.0.0.1', port: '1080', user: '', pass: '' };
const GPUX_DEFAULTS = {
  host: '127.0.0.1', port: '40000', token: '', encryption: 'chacha20-poly1305',
  mtu_payload: '1200', deadline_ms: '8', batch_window_us: '0', pacing_interval_us: '0',
  queue_limit: '512', fec_uplink: '0', fec_group_max_us: '2000'
};
const GPUX_RANGES = {
  port: [1, 65535], mtu_payload: [128, 65507], deadline_ms: [1, 1000],
  batch_window_us: [0, 1000000], pacing_interval_us: [0, 1000000],
  queue_limit: [1, 65536], fec_uplink: [0, 1], fec_group_max_us: [1, 1000000]
};
const GPUX_INTEGER_LIMITS = {
  port: 65535, mtu_payload: 65535, deadline_ms: 4294967295, batch_window_us: 4294967295,
  pacing_interval_us: 4294967295, queue_limit: Number.MAX_SAFE_INTEGER, fec_uplink: 255,
  fec_group_max_us: 4294967295
};

function checkElements(node, allowed, repeated = []) {
  if (!node || typeof node !== 'object') return;
  for (const [name, value] of Object.entries(node || {})) {
    if (name.startsWith('@_') || name.startsWith('?') || name === '#text') continue;
    if (!allowed.includes(name)) throw new Error(`Unknown <${name}> element.`);
    if (Array.isArray(value) && !repeated.includes(name)) {
      throw new Error(`Duplicate <${name}> element.${name === 'backend' ? ' Unsupported backend selection.' : ''}`);
    }
  }
}

function gpuxErrors(gpux, active) {
  const errors = [];
  if (!GPUX_ENCRYPTIONS.includes(gpux.encryption)) {
    errors.push('GPUX encryption must be plaintext or chacha20-poly1305.');
  }
  for (const [field, limit] of Object.entries(GPUX_INTEGER_LIMITS)) {
    const value = Number(gpux[field]);
    if (!/^\d+$/.test(gpux[field]) || !Number.isSafeInteger(value) || value > limit) {
      errors.push(`GPUX ${field} must be an unsigned integer within its integer range.`);
    } else if (active && (value < GPUX_RANGES[field][0] || value > GPUX_RANGES[field][1])) {
      const [min, max] = GPUX_RANGES[field];
      errors.push(`GPUX ${field} must be ${min}..${max}.`);
    }
  }
  if (active) {
    if (!gpux.host || gpux.host.includes('\0')) errors.push('GPUX host is required and cannot contain NUL.');
    const bytes = Buffer.byteLength(gpux.token, 'utf8');
    if (bytes < 1 || bytes > 255 || gpux.token.includes('\0')) {
      errors.push('GPUX token must contain 1..255 UTF-8 bytes without NUL.');
    }
    if (Number(gpux.mtu_payload) < 80 + bytes) {
      errors.push(`GPUX mtu_payload must fit CHLO: at least ${80 + bytes} bytes for this token.`);
    }
  }
  return errors;
}

function needsSocks5(config) {
  return config.udpTransport === 'socks5' || config.rules.some((rule) => rule.tcp);
}

function coerceBool(value) {
  const normalized = String(value ?? 'false').trim().toLowerCase();
  if (!['true', 'false', '1', '0'].includes(normalized)) {
    throw new Error('Rule TCP/UDP must be true, false, 1 or 0.');
  }
  return normalized === 'true' || normalized === '1';
}

function parseConfigXml(xml) {
  const validation = XMLValidator.validate(xml);
  if (validation !== true) {
    throw new Error(`Invalid config.xml: ${validation.err.msg}`);
  }
  const parser = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: '@_', trimValues: false });
  const doc = parser.parse(xml);
  if (!doc.config || typeof doc.config !== 'object') {
    throw new Error('config.xml must contain a <config> root element.');
  }
  const root = doc.config;
  checkElements(doc, ['config']);
  checkElements(root, ['backend', 'socks5', 'udp_transport', 'gpux', 'rules']);
  for (const name of ['backend', 'socks5', 'udp_transport', 'gpux']) {
    checkElements(root[name], []);
  }
  checkElements(root.rules, ['rule'], ['rule']);
  const socks5 = root.socks5;
  const backend = root.backend === undefined ? 'netfilter' : String(root.backend?.['@_type'] ?? '').trim().toLowerCase();
  if (!BACKENDS.includes(backend)) {
    throw new Error(`Unsupported backend "${backend}"; choose netfilter or windivert.`);
  }
  const udpTransport = root.udp_transport === undefined ? 'socks5' : String(root.udp_transport?.['@_type'] ?? '').trim().toLowerCase();
  if (!UDP_TRANSPORTS.includes(udpTransport)) throw new Error('UDP transport must be socks5 or gpux.');
  if (udpTransport === 'gpux' && root.gpux === undefined) throw new Error('Missing <gpux> element.');
  const gpux = root.gpux === undefined ? { ...GPUX_DEFAULTS } : Object.fromEntries(
    Object.entries(GPUX_DEFAULTS).map(([field, fallback]) => [field,
      String(root.gpux?.[`@_${field}`] ?? (field === 'host' ? '' : fallback))])
  );
  gpux.host = gpux.host.trim();
  gpux.encryption = gpux.encryption.trim().toLowerCase();
  const transportErrors = gpuxErrors(gpux, udpTransport === 'gpux');
  if (transportErrors.length) throw new Error(transportErrors.join(' '));
  const rawRules = root.rules?.rule ? [].concat(root.rules.rule) : [];
  const rules = rawRules.flatMap((rule) => {
    checkElements(rule, []);
    const names = String(rule['@_names'] ?? '');
    const source = names.trim() ? names : String(rule['@_name'] ?? '');
    return source
      .split(',')
      .map((name) => name.trim())
      .filter(Boolean)
      .map((name) => ({ name, tcp: coerceBool(rule['@_tcp']), udp: coerceBool(rule['@_udp']) }));
  });
  if (socks5 === undefined && needsSocks5({ udpTransport, rules })) {
    throw new Error('Missing <socks5> element: TCP and SOCKS5 UDP require it.');
  }

  return {
    backend,
    udpTransport,
    gpux,
    socks5: socks5 === undefined ? { ...SOCKS5_DEFAULTS } : {
      host: String(socks5['@_host'] ?? ''),
      port: String(socks5['@_port'] ?? ''),
      user: String(socks5['@_user'] ?? ''),
      pass: String(socks5['@_pass'] ?? '')
    },
    rules
  };
}

function normalizeConfig(config) {
  const gpux = Object.fromEntries(Object.entries(GPUX_DEFAULTS).map(([field, fallback]) => [
    field, String(config?.gpux?.[field] ?? fallback)
  ]));
  gpux.host = gpux.host.trim();
  gpux.encryption = gpux.encryption.trim().toLowerCase();
  return {
    backend: config?.backend === undefined ? 'netfilter' : String(config.backend).trim().toLowerCase(),
    udpTransport: config?.udpTransport === undefined ? 'socks5' : String(config.udpTransport).trim().toLowerCase(),
    gpux,
    socks5: {
      host: String(config?.socks5?.host ?? SOCKS5_DEFAULTS.host).trim(),
      port: String(config?.socks5?.port ?? SOCKS5_DEFAULTS.port).trim(),
      user: String(config?.socks5?.user ?? ''),
      pass: String(config?.socks5?.pass ?? '')
    },
    rules: (Array.isArray(config?.rules) ? config.rules : []).map((rule) => ({
      name: String(rule?.name ?? '').trim(),
      tcp: Boolean(rule?.tcp),
      udp: Boolean(rule?.udp)
    }))
  };
}

function validateConfig(config) {
  const errors = [];
  const rawRules = config?.rules ?? [];
  const normalized = normalizeConfig(config);
  const port = Number(normalized.socks5.port);

  if (!BACKENDS.includes(normalized.backend)) {
    errors.push('Backend must be netfilter or windivert.');
  }
  if (!UDP_TRANSPORTS.includes(normalized.udpTransport)) errors.push('UDP transport must be socks5 or gpux.');
  errors.push(...gpuxErrors(normalized.gpux, normalized.udpTransport === 'gpux'));
  if (!normalized.socks5.host || normalized.socks5.host.includes('\0')) {
    errors.push('SOCKS5 host is required and cannot contain NUL.');
  }
  if (!/^\d+$/.test(normalized.socks5.port) || !Number.isInteger(port) || port < 1 || port > 65535) {
    errors.push('SOCKS5 port must be a number from 1 to 65535.');
  }
  if (Boolean(normalized.socks5.user) !== Boolean(normalized.socks5.pass)) {
    errors.push('SOCKS5 username and password must both be set or both empty.');
  }
  if (Buffer.byteLength(normalized.socks5.user, 'utf8') > 255 || Buffer.byteLength(normalized.socks5.pass, 'utf8') > 255) {
    errors.push('SOCKS5 credentials cannot exceed 255 UTF-8 bytes.');
  }
  if (normalized.socks5.user.includes('\0') || normalized.socks5.pass.includes('\0')) {
    errors.push('SOCKS5 credentials cannot contain NUL.');
  }
  if (normalized.rules.length === 0) {
    errors.push('At least one process rule is required.');
  }

  normalized.rules.forEach((rule, index) => {
    const label = `Rule ${index + 1}`;
    const rawName = String(rawRules[index]?.name ?? '');
    if (!rule.name) {
      errors.push(`${label}: executable name is required.`);
    }
    if (rule.name.includes('\0') || rule.name.length >= 260) {
      errors.push(`${label}: executable names must contain 1 to 259 UTF-16 code units without NUL.`);
    }
    if (rawName !== rawName.trim()) {
      errors.push(`${label}: executable names cannot have leading or trailing whitespace.`);
    }
    if (rawName.includes(',')) {
      errors.push(`${label}: commas are not supported in executable names.`);
    }
    if (/[\\/]/.test(rule.name) || !/\.exe$/i.test(rule.name)) {
      errors.push(`${label}: use an .exe basename such as game.exe.`);
    }
    if (!rule.tcp && !rule.udp) {
      errors.push(`${label}: enable TCP, UDP, or both.`);
    }
  });

  return { normalized, errors };
}

function buildConfigXml(config) {
  const { normalized, errors } = validateConfig(config);
  if (errors.length > 0) {
    throw new Error(errors.join(' '));
  }
  const builder = new XMLBuilder({
    ignoreAttributes: false,
    attributeNamePrefix: '@_',
    format: true,
    suppressEmptyNode: true
  });
  const doc = {
    config: {
      backend: { '@_type': normalized.backend },
      udp_transport: { '@_type': normalized.udpTransport },
      gpux: Object.fromEntries(Object.entries(normalized.gpux).map(([field, value]) => [`@_${field}`, value])),
      socks5: {
        '@_host': normalized.socks5.host,
        '@_port': normalized.socks5.port,
        '@_user': normalized.socks5.user,
        '@_pass': normalized.socks5.pass
      },
      rules: {
        rule: normalized.rules.map((rule) => ({
          '@_name': rule.name,
          '@_tcp': rule.tcp ? '1' : '0',
          '@_udp': rule.udp ? '1' : '0'
        }))
      }
    }
  };
  return `<?xml version="1.0" encoding="UTF-8"?>\n${builder.build(doc)}\n`;
}

module.exports = { parseConfigXml, normalizeConfig, validateConfig, buildConfigXml, needsSocks5 };
