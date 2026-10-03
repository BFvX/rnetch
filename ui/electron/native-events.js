const LIFECYCLE_STATES = new Set(['starting', 'started', 'running', 'stopping', 'stopped', 'error']);

function decodeNativeLine(line) {
  const trimmed = line.trim();
  if (!trimmed.startsWith('{')) {
    return { logs: [{ level: 'out', line }] };
  }
  try {
    const event = JSON.parse(trimmed);
    if (event.type === 'status') {
      const level = event.state === 'error' ? 'error' : event.state === 'warning' ? 'warning' : 'info';
      const result = { logs: [{ level, line: String(event.message ?? '') }] };
      // A flow warning does not change the lifecycle of the native process.
      if (LIFECYCLE_STATES.has(event.state)) {
        result.status = { state: event.state, message: String(event.message ?? '') };
      }
      return result;
    }
    if (event.type === 'metrics') {
      return { metrics: event, logs: [] };
    }
    return { logs: [{ level: 'out', line }] };
  } catch (error) {
    return { logs: [
      { level: 'error', line: `Failed to parse native event: ${error.message}` },
      { level: 'out', line }
    ] };
  }
}

module.exports = { decodeNativeLine };
