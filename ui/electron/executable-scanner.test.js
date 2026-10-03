const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { scanExecutableDirectory } = require('./executable-scanner');

test('recursively finds executable basenames and removes case-insensitive duplicates', async (context) => {
  const rootDirectory = await fs.mkdtemp(path.join(os.tmpdir(), 'rnetch-exe-scan-'));
  context.after(() => fs.rm(rootDirectory, { recursive: true, force: true }));

  await fs.mkdir(path.join(rootDirectory, 'games', 'bin'), { recursive: true });
  await fs.mkdir(path.join(rootDirectory, 'folder.exe'));
  await Promise.all([
    fs.writeFile(path.join(rootDirectory, 'Launcher.EXE'), ''),
    fs.writeFile(path.join(rootDirectory, 'readme.txt'), ''),
    fs.writeFile(path.join(rootDirectory, ' leading-space.exe'), ''),
    fs.writeFile(path.join(rootDirectory, 'comma,name.exe'), ''),
    fs.writeFile(path.join(rootDirectory, 'games', 'launcher.exe'), ''),
    fs.writeFile(path.join(rootDirectory, 'games', 'Game.exe'), ''),
    fs.writeFile(path.join(rootDirectory, 'games', 'bin', 'helper.ExE'), '')
  ]);

  const result = await scanExecutableDirectory(rootDirectory);

  assert.deepEqual(result.executables, ['Game.exe', 'helper.ExE', 'Launcher.EXE']);
  assert.deepEqual(result.skippedDirectories, []);
  assert.deepEqual(
    result.skippedExecutables.map((entry) => path.basename(entry.path)).sort(),
    [' leading-space.exe', 'comma,name.exe']
  );
});

test('returns an empty list when a directory contains no executable files', async (context) => {
  const rootDirectory = await fs.mkdtemp(path.join(os.tmpdir(), 'rnetch-exe-scan-empty-'));
  context.after(() => fs.rm(rootDirectory, { recursive: true, force: true }));
  await fs.writeFile(path.join(rootDirectory, 'notes.md'), 'not an executable');

  const result = await scanExecutableDirectory(rootDirectory);

  assert.deepEqual(result.executables, []);
  assert.deepEqual(result.skippedDirectories, []);
  assert.deepEqual(result.skippedExecutables, []);
});

test('rejects when the selected root directory cannot be read', async () => {
  const missingDirectory = path.join(os.tmpdir(), `rnetch-missing-${Date.now()}`);
  await assert.rejects(scanExecutableDirectory(missingDirectory), { code: 'ENOENT' });
});
