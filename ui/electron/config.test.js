const assert = require('node:assert/strict');
const test = require('node:test');
const { parseConfigXml, validateConfig, buildConfigXml } = require('./config');

const legacyXml = '<config><socks5 host="127.0.0.1" port="1080" user="" pass=""/><rules><rule names="game.exe,helper.exe" tcp="1" udp="0"/></rules></config>';

test('legacy configs default to NetFilter and retain grouped process rules', () => {
  const config = parseConfigXml(legacyXml);
  assert.equal(config.backend, 'netfilter');
  assert.equal(config.udpTransport, 'socks5');
  assert.equal(config.gpux.encryption, 'chacha20-poly1305');
  assert.deepEqual(config.rules, [
    { name: 'game.exe', tcp: true, udp: false },
    { name: 'helper.exe', tcp: true, udp: false }
  ]);
  assert.deepEqual(parseConfigXml(buildConfigXml(config)), config);
});

test('Windivert choice survives save, reload, and unrelated credential edits', () => {
  const config = parseConfigXml(legacyXml.replace('<config>', '<config><backend type="windivert"/>'));
  config.socks5.user = 'a&b';
  config.socks5.pass = 'quote"<tag>';
  config.rules[0].udp = true;
  const xml = buildConfigXml(config);
  assert.match(xml, /<backend type="windivert"\s*\/>/);
  assert.deepEqual(parseConfigXml(xml), config);
});

test('unknown, missing, and duplicate backend types fail visibly', () => {
  for (const element of ['<backend type="unknown"/>', '<backend/>', '<backend type=""/>', '<backend type="netfilter"/><backend type="windivert"/>']) {
    assert.throws(() => parseConfigXml(legacyXml.replace('<config>', `<config>${element}`)), /Unsupported backend/);
  }
  const config = parseConfigXml(legacyXml);
  config.backend = 'unknown';
  assert.ok(validateConfig(config).errors.some((error) => error.includes('Backend')));
  assert.throws(() => buildConfigXml(config), /Backend/);
});

test('malformed XML cannot replace an existing configuration', () => {
  assert.throws(() => parseConfigXml('<config><backend></config>'), /Invalid config.xml/);
  assert.throws(() => parseConfigXml('<other/>'), /root element/);
});

test('names takes precedence over name while an empty names attribute falls back', () => {
  const xml = legacyXml.replace('names="game.exe,helper.exe"', 'name="fallback.exe" names="preferred.exe"');
  assert.equal(parseConfigXml(xml).rules[0].name, 'preferred.exe');
  assert.equal(parseConfigXml(xml.replace('names="preferred.exe"', 'names=" "')).rules[0].name, 'fallback.exe');
});

test('backend and rule booleans follow the native case-insensitive parser', () => {
  const xml = legacyXml.replace('<config>', '<config><backend type=" WinDivert "/>').replace('tcp="1"', 'tcp=" TRUE "');
  assert.equal(parseConfigXml(xml).backend, 'windivert');
  assert.equal(parseConfigXml(xml).rules[0].tcp, true);
  assert.throws(() => parseConfigXml(legacyXml.replace('tcp="1"', 'tcp="yes"')), /TCP\/UDP/);
});

test('partial credentials, UTF-8 length overflow, and NUL cannot be saved', () => {
  const config = parseConfigXml(legacyXml);
  config.socks5.user = 'username';
  assert.throws(() => buildConfigXml(config), /both be set/);
  config.socks5.pass = '密'.repeat(85);
  assert.deepEqual(validateConfig(config).errors, []);
  config.socks5.pass += 'a';
  assert.throws(() => buildConfigXml(config), /255 UTF-8 bytes/);
  config.socks5.pass = 'pass\0word';
  assert.throws(() => buildConfigXml(config), /NUL/);
  config.socks5.pass = 'password';
  config.socks5.host = 'localhost\0';
  assert.throws(() => buildConfigXml(config), /NUL/);
});

test('process name size is limited in UTF-16 code units', () => {
  const config = parseConfigXml(legacyXml);
  config.rules[0].name = `${'a'.repeat(255)}.exe`;
  assert.deepEqual(validateConfig(config).errors, []);
  config.rules[0].name = `${'a'.repeat(256)}.exe`;
  assert.throws(() => buildConfigXml(config), /259 UTF-16/);
  config.rules[0].name = 'game\0.exe';
  assert.throws(() => buildConfigXml(config), /NUL/);
});

const gpuxXml = '<config><backend type="windivert"/><udp_transport type="gpux"/><gpux host="example.invalid" port="40000" token="test-token"/><rules><rule name="game.exe" udp="1"/></rules></config>';

test('UDP-only GPUX can omit SOCKS5 and retains encrypted defaults on roundtrip', () => {
  const config = parseConfigXml(gpuxXml);
  assert.equal(config.backend, 'windivert');
  assert.equal(config.udpTransport, 'gpux');
  assert.equal(config.gpux.deadline_ms, '8');
  assert.equal(config.gpux.mtu_payload, '1200');
  assert.equal(config.gpux.encryption, 'chacha20-poly1305');
  assert.deepEqual(config.socks5, { host: '127.0.0.1', port: '1080', user: '', pass: '' });
  assert.deepEqual(parseConfigXml(buildConfigXml(config)), config);
  assert.throws(() => parseConfigXml(gpuxXml.replace('udp="1"', 'udp="1" tcp="1"')), /Missing <socks5>/);
  assert.throws(() => parseConfigXml(gpuxXml.replace('type="gpux"', 'type="socks5"')), /Missing <socks5>/);
});

test('capture choice, GPUX credentials, and all tunables survive editing and reload', () => {
  const config = parseConfigXml(gpuxXml);
  Object.assign(config.gpux, {
    token: 'a&b"<token>', encryption: 'plaintext', mtu_payload: '1400', deadline_ms: '20',
    batch_window_us: '300', pacing_interval_us: '200', queue_limit: '32', fec_uplink: '1',
    fec_group_max_us: '1000'
  });
  const saved = buildConfigXml(config);
  assert.match(saved, /<udp_transport type="gpux"\s*\/>/);
  assert.deepEqual(parseConfigXml(saved), config);
  config.backend = 'netfilter';
  assert.equal(parseConfigXml(buildConfigXml(config)).udpTransport, 'gpux');
  config.udpTransport = 'socks5';
  assert.deepEqual(parseConfigXml(buildConfigXml(config)).gpux, config.gpux);
});

test('GPUX tokens and SOCKS5 credentials preserve significant whitespace', () => {
  const config = parseConfigXml(gpuxXml.replace('token="test-token"', 'token="  test-token  "'));
  assert.equal(config.gpux.token, '  test-token  ');
  config.socks5.user = ' user ';
  config.socks5.pass = '\t password \n';
  const xml = buildConfigXml(config);
  const reloaded = parseConfigXml(xml);
  assert.equal(reloaded.gpux.token, config.gpux.token);
  assert.equal(reloaded.socks5.user, config.socks5.user);
  assert.equal(reloaded.socks5.pass, config.socks5.pass);
});

test('active GPUX rejects invalid token bytes, encryption, and tunable limits', () => {
  for (const [field, value] of [
    ['host', ''], ['port', '0'], ['port', '65536'], ['token', ''], ['token', '密'.repeat(86)],
    ['token', 'nul\0token'], ['encryption', 'unknown'], ['mtu_payload', '127'], ['mtu_payload', '65508'],
    ['deadline_ms', '0'], ['deadline_ms', '1001'], ['batch_window_us', '1000001'],
    ['pacing_interval_us', '-1'], ['queue_limit', '0'], ['queue_limit', '65537'],
    ['fec_uplink', '2'], ['fec_group_max_us', '0'], ['fec_group_max_us', '1000001']
  ]) {
    const config = parseConfigXml(gpuxXml);
    config.gpux[field] = value;
    assert.ok(validateConfig(config).errors.some((error) => error.includes('GPUX')), `${field}: ${value}`);
    assert.throws(() => buildConfigXml(config), /GPUX/);
  }
  const config = parseConfigXml(gpuxXml);
  config.gpux.token = '密'.repeat(85);
  assert.deepEqual(validateConfig(config).errors, []);
  config.gpux.mtu_payload = '128';
  config.gpux.token = 'a'.repeat(48);
  assert.deepEqual(validateConfig(config).errors, []);
  config.gpux.token += 'a';
  assert.throws(() => buildConfigXml(config), /must fit CHLO/);
  assert.throws(() => parseConfigXml(gpuxXml.replace('token="test-token"', 'token=""')), /GPUX token/);
  assert.throws(() => parseConfigXml(gpuxXml.replace('port="40000"', 'port="0"')), /GPUX port/);
});

test('unknown and duplicate configuration elements fail before save', () => {
  for (const extra of [
    '<unknown/>', '<socks5 host="127.0.0.1" port="1080"/>',
    '<udp_transport type="socks5"/><udp_transport type="gpux"/>', '<gpux/><gpux/>',
    '<rules><rule name="other.exe" tcp="1"/></rules>', '<backend type="netfilter"><unknown/></backend>'
  ]) {
    assert.throws(() => parseConfigXml(legacyXml.replace('<config>', `<config>${extra}`)), /Unknown|Duplicate/);
  }
  assert.throws(() => parseConfigXml(legacyXml.replace('<rules>', '<rules><unknown/>')), /Unknown/);
  assert.throws(() => parseConfigXml(gpuxXml.replace('<udp_transport type="gpux"/>', '<udp_transport type="other"/>')), /UDP transport/);
  assert.throws(() => parseConfigXml(gpuxXml.replace('<gpux host="example.invalid" port="40000" token="test-token"/>', '')), /Missing <gpux>/);
});
