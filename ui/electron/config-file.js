const { constants } = require('node:fs');
const fs = require('node:fs/promises');
const path = require('node:path');

function getConfigPaths({ isPackaged, repoRoot, resourcesPath, userDataPath }) {
  return {
    defaultConfigPath: isPackaged
      ? path.join(resourcesPath, 'config.xml')
      : path.join(repoRoot, 'config.example.xml'),
    configPath: path.join(isPackaged ? userDataPath : repoRoot, 'config.xml')
  };
}

async function ensureConfigFile(configPath, defaultConfigPath) {
  await fs.mkdir(path.dirname(configPath), { recursive: true });
  try {
    await fs.access(configPath);
    return;
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }

  try {
    await fs.copyFile(defaultConfigPath, configPath, constants.COPYFILE_EXCL);
  } catch (error) {
    // Another request may have initialized the same file while we were waiting.
    if (error.code !== 'EEXIST') throw error;
  }
}

module.exports = { getConfigPaths, ensureConfigFile };
