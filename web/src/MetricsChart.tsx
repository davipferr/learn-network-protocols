import { useEffect, useMemo, useRef, useState } from "react";
import type { NetEvent } from "./types";

// Metric events that carry a "t" (ms since the series started) form time
// series; the concurrency demo emits them to chart open connections.
export function hasTimeSeries(events: NetEvent[]) {
  return events.some((e) => e.kind === "metric" && e.metrics && "t" in e.metrics);
}

// Color follows the entity, never its order of appearance.
const SERIES_COLOR: Record<string, string> = {
  sequential: "var(--series-1)",
  concurrent: "var(--series-2)",
};

interface Point {
  t: number;
  v: number;
}

export function MetricsChart({ events }: { events: NetEvent[] }) {
  const metric = "served";
  const series = useMemo(() => {
    const m = new Map<string, Point[]>();
    for (const e of events) {
      if (e.kind !== "metric" || !e.metrics || !("t" in e.metrics)) continue;
      const list = m.get(e.title) ?? [];
      list.push({ t: e.metrics.t, v: e.metrics[metric] ?? 0 });
      m.set(e.title, list);
    }
    return [...m.entries()];
  }, [events]);

  const box = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(600);
  useEffect(() => {
    if (!box.current) return;
    const ro = new ResizeObserver(([entry]) => setWidth(entry.contentRect.width));
    ro.observe(box.current);
    return () => ro.disconnect();
  }, []);

  const [hoverT, setHoverT] = useState<number | null>(null);

  const H = 190;
  const pad = { l: 36, r: 92, t: 12, b: 26 };
  const maxT = Math.max(100, ...series.flatMap(([, p]) => p.map((q) => q.t)));
  const maxV = Math.max(1, ...series.flatMap(([, p]) => p.map((q) => q.v)));
  const sx = (t: number) => pad.l + (t / maxT) * (width - pad.l - pad.r);
  const sy = (v: number) => H - pad.b - (v / maxV) * (H - pad.t - pad.b);
  const yTicks = niceTicks(maxV);
  const xTicks = niceTicks(maxT);

  const valueAt = (pts: Point[], t: number) => {
    let best = pts[0];
    for (const p of pts) if (Math.abs(p.t - t) < Math.abs(best.t - t)) best = p;
    return best;
  };

  return (
    <figure className="chart viz-root" ref={box}>
      <figcaption>
        <strong>Requests completed over time</strong>
        <span className="legend">
          {series.map(([name]) => (
            <span key={name} className="legend-item">
              <span className="legend-swatch" style={{ background: SERIES_COLOR[name] ?? "var(--series-1)" }} />
              {name}
            </span>
          ))}
        </span>
      </figcaption>
      <svg
        width={width}
        height={H}
        role="img"
        aria-label="Completed requests over time for each server mode"
        onMouseMove={(ev) => {
          const r = (ev.currentTarget as SVGSVGElement).getBoundingClientRect();
          const px = ev.clientX - r.left;
          if (px < pad.l || px > width - pad.r) return setHoverT(null);
          setHoverT(((px - pad.l) / (width - pad.l - pad.r)) * maxT);
        }}
        onMouseLeave={() => setHoverT(null)}
      >
        {yTicks.map((v) => (
          <g key={v}>
            <line className="grid" x1={pad.l} x2={width - pad.r} y1={sy(v)} y2={sy(v)} />
            <text className="tick" x={pad.l - 6} y={sy(v) + 4} textAnchor="end">
              {v}
            </text>
          </g>
        ))}
        {xTicks.map((t) => (
          <text key={t} className="tick" x={sx(t)} y={H - 8} textAnchor="middle">
            {t >= 1000 ? `${t / 1000}s` : `${t}ms`}
          </text>
        ))}
        <line className="axis" x1={pad.l} x2={width - pad.r} y1={sy(0)} y2={sy(0)} />
        {series.map(([name, pts]) => {
          const d = pts.map((p, i) => `${i ? "L" : "M"}${sx(p.t).toFixed(1)},${sy(p.v).toFixed(1)}`).join("");
          const last = pts[pts.length - 1];
          const color = SERIES_COLOR[name] ?? "var(--series-1)";
          const peak = pts.reduce((a, b) => (b.v > a.v ? b : a), pts[0]);
          return (
            <g key={name}>
              <path d={d} fill="none" stroke={color} strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />
              <text className="direct-label" x={sx(last.t) + 8} y={sy(peak.v) + 4}>
                {name}
              </text>
            </g>
          );
        })}
        {hoverT !== null && series.length > 0 && (
          <g>
            <line className="crosshair" x1={sx(hoverT)} x2={sx(hoverT)} y1={pad.t} y2={H - pad.b} />
            {series.map(([name, pts]) => {
              const p = valueAt(pts, hoverT);
              return <circle key={name} cx={sx(p.t)} cy={sy(p.v)} r={4} fill={SERIES_COLOR[name] ?? "var(--series-1)"} stroke="var(--surface-1)" strokeWidth={2} />;
            })}
          </g>
        )}
      </svg>
      {hoverT !== null && series.length > 0 && (
        <div className="tooltip" style={{ left: Math.min(sx(hoverT) + 12, width - 170) }}>
          <div className="muted">t ≈ {Math.round(hoverT)} ms</div>
          {series.map(([name, pts]) => {
            const p = valueAt(pts, hoverT);
            return (
              <div key={name}>
                <span className="legend-swatch" style={{ background: SERIES_COLOR[name] ?? "var(--series-1)" }} /> {name}: <b>{p.v}</b> done
              </div>
            );
          })}
        </div>
      )}
    </figure>
  );
}

function niceTicks(max: number): number[] {
  const raw = max / 4;
  const mag = 10 ** Math.floor(Math.log10(raw));
  const step = [1, 2, 5, 10].map((m) => m * mag).find((s) => s >= raw) ?? raw;
  const out: number[] = [];
  for (let v = 0; v <= max + 1e-9; v += step) out.push(Math.round(v));
  return out;
}
