import { useId, useMemo } from 'react';
import { buildTrafficPlot, PLOT, speedColor, speedGradientStops } from './traffic-history.mjs';

export default function TrafficChart({ title, protocol, history, windowSeconds, now, formatRate }) {
  const gradientId = `traffic-${useId().replace(/:/g, '')}`;
  const plot = useMemo(() => buildTrafficPlot(history, protocol, windowSeconds, now), [history, protocol, windowSeconds, now]);
  const windowLabel = windowSeconds < 60 ? `${windowSeconds}s` : `${windowSeconds / 60}m`;

  return (
    <div className="traffic-chart">
      <svg
        viewBox={`0 0 ${PLOT.width} ${PLOT.height}`}
        preserveAspectRatio="none"
        role="img"
        aria-label={`${title} upload and download over the last ${windowLabel}. ${plot.hasSamples ? `Peak ${formatRate(plot.peak)}.` : 'Waiting for samples.'}`}
      >
        <defs>
          <linearGradient id={gradientId} x1="0" x2="0" y1={PLOT.bottom} y2={PLOT.top} gradientUnits="userSpaceOnUse">
            {speedGradientStops(plot.maxRate).map((stop, index) => (
              <stop key={index} offset={stop.offset} stopColor={stop.color} />
            ))}
          </linearGradient>
        </defs>
        {[PLOT.top, (PLOT.top + PLOT.bottom) / 2, PLOT.bottom].map((y) => (
          <line className="traffic-grid-line" key={y} x1="0" x2={PLOT.width} y1={y} y2={y} vectorEffect="non-scaling-stroke" />
        ))}
        <path className="traffic-line" d={plot.upPath} stroke={`url(#${gradientId})`} vectorEffect="non-scaling-stroke" />
        <path className="traffic-line traffic-line-down" d={plot.downPath} stroke={`url(#${gradientId})`} vectorEffect="non-scaling-stroke" />
        {plot.lastPoints && (
          <>
            <circle cx={plot.lastPoints.x} cy={plot.lastPoints.upY} r="2" fill={speedColor(plot.lastPoints.upRate)} />
            <circle cx={plot.lastPoints.x} cy={plot.lastPoints.downY} r="2" fill={speedColor(plot.lastPoints.downRate)} />
          </>
        )}
      </svg>
      {!plot.hasSamples && <span className="traffic-chart-empty">Waiting for samples</span>}
      <div className="traffic-chart-caption">
        <span>−{windowLabel}</span>
        <span>Peak {formatRate(plot.peak)}</span>
        <span>Now</span>
      </div>
    </div>
  );
}
