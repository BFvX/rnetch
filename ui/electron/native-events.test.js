const assert = require('node:assert/strict');
const test = require('node:test');
const { decodeNativeLine } = require('./native-events');

test('per-flow warnings log without changing a running lifecycle', () => {
  let state = { state: 'running', message: 'Started' };
  const update = decodeNativeLine(JSON.stringify({ type: 'status', state: 'warning', message: 'SOCKS5 connection failed for one flow' }));
  if (update.status) state = update.status;
  assert.equal(state.state, 'running');
  assert.deepEqual(update.logs, [{ level: 'warning', line: 'SOCKS5 connection failed for one flow' }]);
});

test('running, terminal errors, and shutdown events retain their lifecycle', () => {
  for (const state of ['starting', 'running', 'started', 'stopping', 'stopped', 'error']) {
    const update = decodeNativeLine(JSON.stringify({ type: 'status', state, message: state }));
    assert.deepEqual(update.status, { state, message: state });
    assert.equal(update.logs[0].level, state === 'error' ? 'error' : 'info');
  }
});

test('metrics and malformed output cannot overwrite lifecycle state', () => {
  const metrics = decodeNativeLine('{"type":"metrics","tcpUpBytes":42}');
  assert.equal(metrics.metrics.tcpUpBytes, 42);
  assert.equal(metrics.status, undefined);
  assert.deepEqual(metrics.logs, []);
  const malformed = decodeNativeLine('{invalid');
  assert.equal(malformed.status, undefined);
  assert.equal(malformed.logs[0].level, 'error');
});
