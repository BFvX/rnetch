export const TRAFFIC_WINDOWS = [
  { seconds: 30, label: '30 seconds' },
  { seconds: 60, label: '1 minute' },
  { seconds: 300, label: '5 minutes' },
  { seconds: 900, label: '15 minutes' }
];

export const SPEED_BANDS = [
  { limit: 256 * 1024, color: '#6990f5', label: '<256 KB/s' },
  { limit: 1024 * 1024, color: '#3563e9', label: '256 KB–1 MB/s' },
  { limit: 5 * 1024 * 1024, color: '#9364d9', label: '1–5 MB/s' },
  { limit: Infinity, color: '#d28b42', label: '≥5 MB/s' }
];

export const PLOT = { width: 320, top: 6, bottom: 62, height: 68 };
const RETENTION_MS = 900 * 1000;
const MAX_SAMPLES = 1802;
const MAX_GAP_MS = 2500;
const RATE_KEYS = ['totalUpBps', 'totalDownBps', 'tcpUpBps', 'tcpDownBps', 'udpUpBps', 'udpDownBps'];

export function appendTrafficSample(history, metrics, time) {
  if (!Number.isFinite(time) || (history.length && time < history.at(-1).time)) {
    return history;
  }
  const sample = { time };
  for (const key of RATE_KEYS) {
    const value = Number(metrics[key]);
    sample[key] = Number.isFinite(value) ? Math.max(0, value) : 0;
  }
  const samples = history.at(-1)?.time === time ? history.slice(0, -1) : history;
  // Keep one predecessor so the left edge can be clipped between real samples.
  const firstInWindow = samples.findIndex((point) => point.time >= time - RETENTION_MS);
  const first = firstInWindow === -1 ? Math.max(0, samples.length - 1) : Math.max(0, firstInWindow - 1);
  return [...samples.slice(first), sample].slice(-MAX_SAMPLES);
}

export function buildTrafficPlot(history, protocol, windowSeconds, now) {
  const start = now - windowSeconds * 1000;
  const upKey = `${protocol}UpBps`;
  const downKey = `${protocol}DownBps`;
  const visible = history.filter((sample) => sample.time >= start && sample.time <= now);
  const firstIndex = history.findIndex((sample) => sample.time >= start);
  const previous = history[firstIndex - 1];
  const next = visible[0];
  if (previous && next && next.time > start && next.time - previous.time <= MAX_GAP_MS) {
    const ratio = (start - previous.time) / (next.time - previous.time);
    visible.unshift({
      time: start,
      [upKey]: previous[upKey] + (next[upKey] - previous[upKey]) * ratio,
      [downKey]: previous[downKey] + (next[downKey] - previous[downKey]) * ratio
    });
  }

  const peak = visible.reduce((max, sample) => Math.max(max, sample[upKey], sample[downKey]), 0);
  const maxRate = Math.max(1024, peak * 1.15);
  const x = (time) => ((time - start) / (windowSeconds * 1000)) * PLOT.width;
  const y = (rate) => PLOT.bottom - (rate / maxRate) * (PLOT.bottom - PLOT.top);
  const pathFor = (key) => visible.map((sample, index) => {
    const disconnected = index === 0 || sample.time - visible[index - 1].time > MAX_GAP_MS;
    return `${disconnected ? 'M' : 'L'}${x(sample.time).toFixed(2)},${y(sample[key]).toFixed(2)}`;
  }).join(' ');
  const last = visible.at(-1);

  return {
    upPath: pathFor(upKey),
    downPath: pathFor(downKey),
    peak,
    maxRate,
    hasSamples: visible.length > 0,
    lastPoints: last ? {
      x: x(last.time), upY: y(last[upKey]), downY: y(last[downKey]),
      upRate: last[upKey], downRate: last[downKey]
    } : null
  };
}

export function speedColor(rate) {
  return SPEED_BANDS.find((band) => rate < band.limit)?.color ?? SPEED_BANDS.at(-1).color;
}

export function speedGradientStops(maxRate) {
  const stops = [{ offset: 0, color: SPEED_BANDS[0].color }];
  SPEED_BANDS.slice(0, -1).forEach((band, index) => {
    if (band.limit < maxRate) {
      const offset = band.limit / maxRate;
      // A narrow blend softens color changes while keeping thresholds fixed in B/s.
      const previousLimit = SPEED_BANDS[index - 1]?.limit ?? 0;
      const blend = Math.min(0.015, (band.limit - previousLimit) / maxRate / 3);
      stops.push({ offset: offset - blend, color: band.color });
      stops.push({ offset, color: SPEED_BANDS[index + 1].color });
    }
  });
  stops.push({ offset: 1, color: speedColor(maxRate) });
  return stops;
}
