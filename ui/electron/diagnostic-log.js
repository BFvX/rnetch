const fs = require('node:fs/promises');
const path = require('node:path');

const MAX_FILE_BYTES = 5 * 1024 * 1024;

function serializeEntry(entry, maxBytes) {
  // Whitelist the displayed log fields. Never serialize the caller's config,
  // credentials, native metrics object, or other attached diagnostic state.
  const record = { level: String(entry.level), time: String(entry.time), line: String(entry.line) };
  const encode = () => `${JSON.stringify(record)}\n`;
  let encoded = encode();
  if (Buffer.byteLength(encoded) <= maxBytes) return encoded;

  const source = record.line;
  const suffix = ' [truncated]';
  record.line = suffix;
  if (Buffer.byteLength(encode()) > maxBytes) return null;
  let low = 0;
  let high = source.length;
  while (low < high) {
    const middle = Math.ceil((low + high) / 2);
    record.line = source.slice(0, middle) + suffix;
    if (Buffer.byteLength(encode()) <= maxBytes) low = middle;
    else high = middle - 1;
  }
  // Do not split an astral character at the truncation boundary.
  if (low > 0 && /[\uD800-\uDBFF]/.test(source[low - 1])) low -= 1;
  record.line = source.slice(0, low) + suffix;
  encoded = encode();
  return encoded;
}

function createDiagnosticLog(directory, { maxBytes = MAX_FILE_BYTES, fileSystem = fs } = {}) {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 128) {
    throw new Error('Diagnostic log maxBytes must be an integer of at least 128 bytes.');
  }
  const filePath = path.join(directory, 'rnetch.log');
  const rotatedPath = `${filePath}.1`;
  let pending = Promise.resolve();
  let currentBytes = null;
  let queuedBytes = 0;

  const ignoreMissing = async (operation) => {
    try { await operation(); } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
  };

  const write = async (encoded, size) => {
    if (currentBytes === null) {
      await fileSystem.mkdir(directory, { recursive: true });
      try { currentBytes = (await fileSystem.stat(filePath)).size; } catch (error) {
        if (error.code !== 'ENOENT') throw error;
        currentBytes = 0;
      }
    }
    if (currentBytes > 0 && currentBytes + size > maxBytes) {
      await ignoreMissing(() => fileSystem.unlink(rotatedPath));
      await ignoreMissing(() => fileSystem.rename(filePath, rotatedPath));
      currentBytes = 0;
    }
    await fileSystem.appendFile(filePath, encoded, 'utf8');
    currentBytes += size;
  };

  return {
    filePath,
    append(entry) {
      let encoded;
      try { encoded = serializeEntry(entry, maxBytes); } catch { return false; }
      if (encoded === null) return false;
      const size = Buffer.byteLength(encoded);
      // A blocked disk must not grow an unlimited promise/string backlog in the UI.
      if (queuedBytes + size > maxBytes * 2) return false;
      queuedBytes += size;
      pending = pending.then(() => write(encoded, size)).catch(() => {
        // Re-stat after an I/O error (including a partial append). Logging errors
        // are intentionally not sent back through addLog, avoiding recursion.
        currentBytes = null;
      }).finally(() => { queuedBytes -= size; });
      return true;
    },
    flush(timeoutMs = 1000) {
      const duration = Number.isFinite(timeoutMs) ? Math.max(0, Math.min(timeoutMs, 5000)) : 1000;
      return new Promise((resolve) => {
        const timer = setTimeout(() => resolve(false), duration);
        pending.then(() => {
          clearTimeout(timer);
          resolve(true);
        });
      });
    }
  };
}

module.exports = { createDiagnosticLog, MAX_FILE_BYTES };
