const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { createDiagnosticLog, MAX_FILE_BYTES } = require('./diagnostic-log');
const { decodeNativeLine } = require('./native-events');

const entry = (line) => ({ level: 'warning', time: '2026-10-03T00:00:00.000Z', line });

async function directory(context) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'rnetch-diagnostic-log-'));
  context.after(() => fs.rm(root, { recursive: true, force: true }));
  return root;
}

async function readEntries(filePath) {
  return (await fs.readFile(filePath, 'utf8')).trimEnd().split('\n').map(JSON.parse);
}

test('queues asynchronous appends in order and persists only visible fields', async (context) => {
  const log = createDiagnosticLog(await directory(context));
  assert.equal(MAX_FILE_BYTES, 5 * 1024 * 1024);
  for (let index = 0; index < 100; index += 1) {
    assert.equal(log.append({ ...entry(`event ${index}`), config: { pass: 'secret' }, metrics: { tcpUpBytes: 99 } }), true);
  }
  assert.equal(await log.flush(), true);
  const records = await readEntries(log.filePath);
  assert.deepEqual(records, Array.from({ length: 100 }, (_, index) => entry(`event ${index}`)));
  assert.ok(!(await fs.readFile(log.filePath, 'utf8')).includes('secret'));
  const metrics = decodeNativeLine('{"type":"metrics","tcpUpBytes":123}');
  metrics.logs.forEach((record) => log.append(record));
  await log.flush();
  assert.equal((await readEntries(log.filePath)).length, 100);
});

test('rotation accounts for existing UTF-8 bytes and keeps exactly one backup', async (context) => {
  const root = await directory(context);
  const log = createDiagnosticLog(root, { maxBytes: 256 });
  const first = entry('首'.repeat(40));
  const second = entry('二'.repeat(40));
  const third = entry('三'.repeat(40));
  await fs.writeFile(log.filePath, `${JSON.stringify(first)}\n`);
  assert.equal(log.append(second), true);
  await log.flush();
  assert.deepEqual(await readEntries(`${log.filePath}.1`), [first]);
  assert.deepEqual(await readEntries(log.filePath), [second]);
  assert.equal(log.append(third), true);
  await log.flush();
  assert.deepEqual(await readEntries(`${log.filePath}.1`), [second]);
  assert.deepEqual(await readEntries(log.filePath), [third]);
  assert.deepEqual((await fs.readdir(root)).sort(), ['rnetch.log', 'rnetch.log.1']);
  for (const name of await fs.readdir(root)) assert.ok((await fs.stat(path.join(root, name))).size <= 256);
});

test('an oversized event remains valid JSON and cannot exceed the file limit', async (context) => {
  const log = createDiagnosticLog(await directory(context), { maxBytes: 256 });
  log.append(entry('😀\n"'.repeat(1000)));
  await log.flush();
  assert.ok((await fs.stat(log.filePath)).size <= 256);
  const [record] = await readEntries(log.filePath);
  assert.equal(record.level, 'warning');
  assert.ok(record.line.endsWith(' [truncated]'));
  assert.ok(!/[\uD800-\uDBFF](?![\uDC00-\uDFFF])/.test(record.line));
});

test('an append failure is swallowed and later entries can still be written', async (context) => {
  let calls = 0;
  const log = createDiagnosticLog(await directory(context), { fileSystem: {
    ...fs,
    async appendFile(...args) {
      calls += 1;
      if (calls === 1) throw Object.assign(new Error('Disk full'), { code: 'ENOSPC' });
      return fs.appendFile(...args);
    }
  } });
  assert.doesNotThrow(() => log.append(entry('lost on disk failure')));
  assert.equal(await log.flush(), true);
  log.append(entry('recovered'));
  assert.equal(await log.flush(), true);
  assert.equal(calls, 2);
  assert.deepEqual(await readEntries(log.filePath), [entry('recovered')]);
});

test('an unwritable directory and malformed entry never throw into the caller', async () => {
  const log = createDiagnosticLog('unwritable', { fileSystem: {
    async mkdir() { throw Object.assign(new Error('Permission denied'), { code: 'EACCES' }); }
  } });
  assert.doesNotThrow(() => log.append(entry('cannot persist')));
  assert.equal(await log.flush(), true);
  assert.equal(log.append(null), false);
});

test('flush has a deadline and a stalled disk cannot create an unlimited queue', async (context) => {
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const log = createDiagnosticLog(await directory(context), { maxBytes: 256, fileSystem: {
    ...fs,
    async appendFile(...args) { await gate; return fs.appendFile(...args); }
  } });
  assert.equal(log.append(entry('a'.repeat(120))), true);
  assert.equal(log.append(entry('b'.repeat(120))), true);
  assert.equal(log.append(entry('c'.repeat(120))), false);
  const before = Date.now();
  assert.equal(await log.flush(20), false);
  assert.ok(Date.now() - before < 1000);
  release();
  assert.equal(await log.flush(), true);
  assert.deepEqual(await readEntries(`${log.filePath}.1`), [entry('a'.repeat(120))]);
  assert.deepEqual(await readEntries(log.filePath), [entry('b'.repeat(120))]);
});
