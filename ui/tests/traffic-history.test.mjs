import assert from 'node:assert/strict';
import test from 'node:test';
import {
  appendTrafficSample, buildTrafficPlot, PLOT, SPEED_BANDS,
  speedColor, speedGradientStops, TRAFFIC_WINDOWS
} from '../src/traffic-history.mjs';

const rates = (up = 0, down = up) => ({
  totalUpBps: up, totalDownBps: down,
  tcpUpBps: up, tcpDownBps: down,
  udpUpBps: up, udpDownBps: down
});

const points = (path) => Array.from(path.matchAll(/([ML])(-?\d+\.\d+),(-?\d+\.\d+)/g),
  ([, command, x, y]) => ({ command, x: Number(x), y: Number(y) }));

test('normalizes negative, missing, non-finite and numeric-string rates', () => {
  const history = appendTrafficSample([], {
    totalUpBps: -10, totalDownBps: NaN, tcpUpBps: Infinity,
    tcpDownBps: -Infinity, udpUpBps: '4096'
  }, 1000);
  assert.deepEqual(history, [{
    time: 1000, totalUpBps: 0, totalDownBps: 0,
    tcpUpBps: 0, tcpDownBps: 0, udpUpBps: 4096, udpDownBps: 0
  }]);
});

test('rejects invalid and out-of-order timestamps and replaces duplicate timestamps', () => {
  const original = appendTrafficSample([], rates(10), 1000);
  for (const time of [999, NaN, Infinity, -Infinity]) {
    assert.equal(appendTrafficSample(original, rates(20), time), original);
  }
  const replaced = appendTrafficSample(original, rates(20), 1000);
  assert.equal(replaced.length, 1);
  assert.equal(replaced[0].totalUpBps, 20);
  assert.equal(original[0].totalUpBps, 10);
});

test('retains fifteen minutes plus one predecessor for edge interpolation', () => {
  let history = [];
  for (const time of [0, 500, 1000, 901000]) {
    history = appendTrafficSample(history, rates(10), time);
  }
  assert.deepEqual(history.map((sample) => sample.time), [500, 1000, 901000]);
  history = appendTrafficSample(history, rates(10), 902000);
  assert.deepEqual(history.map((sample) => sample.time), [1000, 901000, 902000]);
});

test('bounds unusually frequent samples and retains only the newest predecessor after a long gap', () => {
  let history = [];
  for (let time = 0; time < 2000; time += 1) {
    history = appendTrafficSample(history, rates(10), time);
  }
  assert.equal(history.length, 1802);
  assert.equal(history[0].time, 198);
  assert.equal(history.at(-1).time, 1999);
  history = appendTrafficSample(history, rates(20), 2000000);
  assert.deepEqual(history.map((sample) => sample.time), [1999, 2000000]);
});

test('clips all selectable windows without discarding retained history', () => {
  assert.deepEqual(TRAFFIC_WINDOWS.map((window) => window.seconds), [30, 60, 300, 900]);
  let history = [];
  for (let second = 0; second <= 900; second += 1) {
    history = appendTrafficSample(history, rates(second), second * 1000);
  }
  const snapshot = structuredClone(history);
  for (const seconds of [30, 60, 300, 900, 30, 900]) {
    const plot = buildTrafficPlot(history, 'total', seconds, 900000);
    const plotted = points(plot.upPath);
    assert.equal(plotted.length, seconds + 1);
    assert.equal(plotted[0].x, 0);
    assert.equal(plotted.at(-1).x, PLOT.width);
    assert.equal(plot.peak, 900);
  }
  assert.deepEqual(history, snapshot);
});

test('interpolates both rates at the left boundary between adjacent samples', () => {
  const history = [
    { time: 0, ...rates(0, 400) },
    { time: 2000, ...rates(200, 0) }
  ];
  const plot = buildTrafficPlot(history, 'total', 1, 2000);
  const up = points(plot.upPath);
  const down = points(plot.downPath);
  const y = (rate) => Number((PLOT.bottom - rate / 1024 * (PLOT.bottom - PLOT.top)).toFixed(2));
  assert.equal(up.length, 2);
  assert.deepEqual(up[0], { command: 'M', x: 0, y: y(100) });
  assert.deepEqual(down[0], { command: 'M', x: 0, y: y(200) });
  assert.equal(plot.peak, 200);
});

test('does not duplicate a sample already at the left boundary', () => {
  const history = [0, 1000, 2000].map((time) => ({ time, ...rates(100) }));
  const plot = buildTrafficPlot(history, 'tcp', 1, 2000);
  assert.deepEqual(points(plot.upPath).map((point) => point.x), [0, PLOT.width]);
});

test('disconnects gaps longer than 2.5 seconds and does not interpolate across them', () => {
  const history = [0, 1000, 4000, 5000].map((time) => ({ time, ...rates(100) }));
  const plot = buildTrafficPlot(history, 'udp', 5, 5000);
  assert.deepEqual(points(plot.upPath).map((point) => point.command), ['M', 'L', 'M', 'L']);
  assert.deepEqual(points(plot.downPath).map((point) => point.command), ['M', 'L', 'M', 'L']);
  const clipped = buildTrafficPlot(history, 'udp', 3, 5000);
  assert.equal(points(clipped.upPath)[0].x, Number((2 / 3 * PLOT.width).toFixed(2)));
  assert.equal(points(clipped.upPath).length, 2);
  const boundaryGap = buildTrafficPlot([
    { time: 0, ...rates(100) }, { time: 2500, ...rates(200) }
  ], 'total', 2.5, 2500);
  assert.deepEqual(points(boundaryGap.upPath).map((point) => point.command), ['M', 'L']);
});

test('excludes future and expired samples and selects rates for the requested protocol', () => {
  const history = [
    { time: 0, ...rates(9999999) },
    { time: 4000, ...rates(20), tcpUpBps: 400, tcpDownBps: 600 },
    { time: 5000, ...rates(9999999) }
  ];
  const total = buildTrafficPlot(history, 'total', 1, 4000);
  const tcp = buildTrafficPlot(history, 'tcp', 1, 4000);
  assert.equal(total.peak, 20);
  assert.equal(tcp.peak, 600);
  assert.equal(tcp.lastPoints.upRate, 400);
  assert.equal(tcp.lastPoints.downRate, 600);
  assert.equal(points(tcp.upPath).length, 1);
});

test('handles empty, expired and zero-rate windows with a usable scale', () => {
  for (const history of [[], [{ time: 0, ...rates(100) }]]) {
    const plot = buildTrafficPlot(history, 'total', 30, 60000);
    assert.equal(plot.hasSamples, false);
    assert.equal(plot.upPath, '');
    assert.equal(plot.downPath, '');
    assert.equal(plot.peak, 0);
    assert.equal(plot.maxRate, 1024);
    assert.equal(plot.lastPoints, null);
  }
  const zero = buildTrafficPlot([{ time: 60000, ...rates() }], 'total', 30, 60000);
  assert.equal(zero.hasSamples, true);
  assert.equal(zero.peak, 0);
  assert.equal(zero.maxRate, 1024);
  assert.equal(zero.lastPoints.upY, PLOT.bottom);
  assert.equal(zero.lastPoints.downY, PLOT.bottom);
});

test('uses fixed speed thresholds independent of the plot peak', () => {
  assert.deepEqual(SPEED_BANDS.map((band) => band.limit), [256 * 1024, 1024 * 1024, 5 * 1024 * 1024, Infinity]);
  assert.equal(speedColor(0), SPEED_BANDS[0].color);
  SPEED_BANDS.slice(0, -1).forEach((band, index) => {
    assert.equal(speedColor(band.limit - 1), band.color);
    assert.equal(speedColor(band.limit), SPEED_BANDS[index + 1].color);
  });
  assert.equal(speedColor(Number.MAX_VALUE), SPEED_BANDS.at(-1).color);
});

test('gradient stops stay ordered and bounded even for extreme peaks', () => {
  for (const maxRate of [1024, 256 * 1024, 1024 * 1024, 5 * 1024 * 1024, 1024 ** 3, Number.MAX_VALUE]) {
    const stops = speedGradientStops(maxRate);
    assert.equal(stops[0].offset, 0);
    assert.equal(stops.at(-1).offset, 1);
    assert.equal(stops.at(-1).color, speedColor(maxRate));
    stops.forEach((stop, index) => {
      assert.ok(Number.isFinite(stop.offset));
      assert.ok(stop.offset >= 0 && stop.offset <= 1);
      assert.ok(index === 0 || stop.offset >= stops[index - 1].offset,
        `gradient stops are ordered at maxRate ${maxRate}: ${stops.map((item) => item.offset)}`);
    });
  }
});
