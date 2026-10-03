const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { getConfigPaths, ensureConfigFile } = require('./config-file');

async function directory(context) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'rnetch-config-file-'));
  context.after(() => fs.rm(root, { recursive: true, force: true }));
  return root;
}

test('a fresh development checkout initializes its local config from the public example', async (context) => {
  const repoRoot = await directory(context);
  const paths = getConfigPaths({ isPackaged: false, repoRoot });
  assert.equal(paths.defaultConfigPath, path.join(repoRoot, 'config.example.xml'));
  assert.equal(paths.configPath, path.join(repoRoot, 'config.xml'));
  const example = '<config><socks5 host="127.0.0.1" port="10808" user="" pass=""/></config>';
  await fs.writeFile(paths.defaultConfigPath, example);
  await Promise.all([
    ensureConfigFile(paths.configPath, paths.defaultConfigPath),
    ensureConfigFile(paths.configPath, paths.defaultConfigPath)
  ]);
  assert.equal(await fs.readFile(paths.configPath, 'utf8'), example);
  assert.equal(await fs.readFile(paths.defaultConfigPath, 'utf8'), example);
});

test('development startup preserves an existing local config without reading the example', async (context) => {
  const paths = getConfigPaths({ isPackaged: false, repoRoot: await directory(context) });
  const localConfig = '<config>local customization</config>';
  await fs.writeFile(paths.configPath, localConfig);
  await ensureConfigFile(paths.configPath, paths.defaultConfigPath);
  assert.equal(await fs.readFile(paths.configPath, 'utf8'), localConfig);
});

test('packaged startup still copies the resource config into userData and preserves later edits', async (context) => {
  const root = await directory(context);
  const resourcesPath = path.join(root, 'resources');
  const userDataPath = path.join(root, 'userData');
  const paths = getConfigPaths({ isPackaged: true, resourcesPath, userDataPath });
  assert.equal(paths.defaultConfigPath, path.join(resourcesPath, 'config.xml'));
  assert.equal(paths.configPath, path.join(userDataPath, 'config.xml'));
  await fs.mkdir(resourcesPath);
  await fs.writeFile(paths.defaultConfigPath, '<config>packaged default</config>');
  await ensureConfigFile(paths.configPath, paths.defaultConfigPath);
  assert.equal(await fs.readFile(paths.configPath, 'utf8'), '<config>packaged default</config>');
  await fs.writeFile(paths.configPath, '<config>user customization</config>');
  await ensureConfigFile(paths.configPath, paths.defaultConfigPath);
  assert.equal(await fs.readFile(paths.configPath, 'utf8'), '<config>user customization</config>');
});

test('initialization reports a missing example without creating a local config', async (context) => {
  const paths = getConfigPaths({ isPackaged: false, repoRoot: await directory(context) });
  await assert.rejects(ensureConfigFile(paths.configPath, paths.defaultConfigPath), { code: 'ENOENT' });
  await assert.rejects(fs.access(paths.configPath), { code: 'ENOENT' });
});
