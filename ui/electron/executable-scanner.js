const fs = require('node:fs/promises');
const path = require('node:path');

function compareNames(left, right) {
  return left.localeCompare(right, 'en', { numeric: true, sensitivity: 'base' })
    || left.localeCompare(right, 'en', { numeric: true });
}

function getUnsupportedRuleNameReason(name) {
  if (name !== name.trim()) {
    return 'leading or trailing whitespace is not supported in process rules';
  }
  if (name.includes(',')) {
    return 'commas are reserved as process-name separators in config.xml';
  }
  return null;
}

async function scanExecutableDirectory(rootDirectory) {
  const rootPath = path.resolve(rootDirectory);
  const pendingDirectories = [rootPath];
  let pendingIndex = 0;
  const executablesByName = new Map();
  const skippedDirectories = [];
  const skippedExecutables = [];

  while (pendingIndex < pendingDirectories.length) {
    const currentDirectory = pendingDirectories[pendingIndex];
    pendingIndex += 1;

    try {
      const directory = await fs.opendir(currentDirectory);
      for await (const entry of directory) {
        const entryPath = path.join(currentDirectory, entry.name);

        if (entry.isDirectory()) {
          pendingDirectories.push(entryPath);
          continue;
        }
        if (!entry.isFile() || path.extname(entry.name).toLowerCase() !== '.exe') {
          continue;
        }

        const unsupportedReason = getUnsupportedRuleNameReason(entry.name);
        if (unsupportedReason) {
          skippedExecutables.push({
            name: entry.name,
            path: entryPath,
            reason: unsupportedReason
          });
          continue;
        }

        const key = entry.name.toLocaleLowerCase('en-US');
        if (!executablesByName.has(key)) {
          executablesByName.set(key, entry.name);
        }
      }
    } catch (error) {
      if (currentDirectory === rootPath) {
        throw error;
      }
      skippedDirectories.push({
        path: currentDirectory,
        error: error.message
      });
    }
  }

  return {
    executables: [...executablesByName.values()].sort(compareNames),
    skippedDirectories,
    skippedExecutables
  };
}

module.exports = {
  scanExecutableDirectory
};
