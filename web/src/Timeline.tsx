import { useEffect, useMemo, useRef } from "react";
import type { Demo, NetEvent } from "./types";

interface Props {
  demo: Demo;
  events: NetEvent[];
  selectedSeq: number | null;
  onSelect: (seq: number) => void;
  running: boolean;
}

// A sequence diagram: one vertical lane per actor, arrows for bytes on the
// wire, notes for what each actor did, and full-width bands for lesson steps.
export function Timeline({ demo, events, selectedSeq, onSelect, running }: Props) {
  const lanes = useMemo(() => {
    const l = [...demo.actors];
    for (const e of events) {
      for (const a of [e.actor, e.from, e.to]) if (a && !l.includes(a)) l.push(a);
    }
    return l;
  }, [demo.actors, events]);

  const x = (actor?: string) => {
    const i = Math.max(0, lanes.indexOf(actor ?? ""));
    return ((i + 0.5) / lanes.length) * 100;
  };

  const bottom = useRef<HTMLDivElement>(null);
  const follow = useRef(true);
  useEffect(() => {
    if (running && follow.current) bottom.current?.scrollIntoView({ block: "nearest" });
  }, [events.length, running]);

  const visible = events.filter((e) => !(e.kind === "metric" && e.metrics && "t" in e.metrics));

  return (
    <div
      className="timeline"
      style={{ "--lanes": lanes.length } as React.CSSProperties}
      onWheel={() => (follow.current = false)}
    >
      <div className="lane-heads">
        {lanes.map((l) => (
          <div key={l} className="lane-head" style={{ left: `${x(l)}%` }}>
            {l}
          </div>
        ))}
      </div>
      <div className="rows">
        {lanes.map((l) => (
          <div key={l} className="lane-line" style={{ left: `${x(l)}%` }} />
        ))}
        {visible.map((e) => {
          const sel = e.seq === selectedSeq;
          switch (e.kind) {
            case "start":
              return null;
            case "end":
              return (
                <div key={e.seq} className={`row band end ${e.title === "Finished" ? "" : "failed"}`}>
                  <strong>{e.title}</strong> <span className="muted">{e.detail}</span> <span className="ms">{fmtMs(e.elapsedMs)}</span>
                </div>
              );
            case "step":
              return (
                <div key={e.seq} className="row band step">
                  <h3>{e.title}</h3>
                  {e.detail && <p className="prewrap">{e.detail}</p>}
                </div>
              );
            case "send":
              return <Arrow key={e.seq} e={e} x1={x(e.from)} x2={x(e.to)} selected={sel} onSelect={onSelect} />;
            case "metric":
              return (
                <div key={e.seq} className="row band metric">
                  <strong>{e.title}</strong>{" "}
                  {Object.entries(e.metrics ?? {}).map(([k, v]) => (
                    <span key={k} className="chip">
                      {k} <b>{v}</b>
                    </span>
                  ))}
                </div>
              );
            default:
              return <Note key={e.seq} e={e} x={x(e.actor)} selected={sel} onSelect={onSelect} />;
          }
        })}
        {running && (
          <div className="row band waiting">
            <span className="pulse" /> waiting for the next event…
          </div>
        )}
        <div ref={bottom} />
      </div>
    </div>
  );
}

function Arrow({ e, x1, x2, selected, onSelect }: { e: NetEvent; x1: number; x2: number; selected: boolean; onSelect: (s: number) => void }) {
  const left = Math.min(x1, x2);
  const width = Math.max(Math.abs(x2 - x1), 4);
  const rightward = x2 >= x1;
  const cls = ["arrow", rightward ? "right" : "left", e.simulated ? "simulated" : "", e.dropped ? "dropped" : "", selected ? "selected" : ""].join(" ");
  return (
    <button className={`row send ${selected ? "selected" : ""}`} onClick={() => onSelect(e.seq)} aria-label={`${e.from} to ${e.to}: ${e.title}`}>
      <span className="label" style={{ left: `${left}%`, width: `${width}%` }}>
        {e.layer && <span className="layer">{e.layer}</span>}
        <span className="title">{e.title}</span>
        {e.size ? <span className="size">{e.size} B</span> : null}
      </span>
      <span className={cls} style={{ left: `${left}%`, width: `${width}%` }} />
      <span className="ms">{fmtMs(e.elapsedMs)}</span>
    </button>
  );
}

function Note({ e, x, selected, onSelect }: { e: NetEvent; x: number; selected: boolean; onSelect: (s: number) => void }) {
  const onRight = x > 50;
  return (
    <button className={`row note ${e.kind} ${selected ? "selected" : ""}`} onClick={() => onSelect(e.seq)}>
      <span className="dot" style={{ left: `${x}%` }} />
      <span className={`bubble ${onRight ? "to-left" : "to-right"}`} style={onRight ? { right: `${100 - x + 1.5}%` } : { left: `${x + 1.5}%` }}>
        <span className="kind">{e.kind}</span> {e.title}
      </span>
      <span className="ms">{fmtMs(e.elapsedMs)}</span>
    </button>
  );
}

function fmtMs(ms: number) {
  return ms < 1000 ? `${ms.toFixed(1)} ms` : `${(ms / 1000).toFixed(2)} s`;
}
