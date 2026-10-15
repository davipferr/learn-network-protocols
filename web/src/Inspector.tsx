import { useMemo, useState } from "react";
import { decodeBytes, type Field, type NetEvent } from "./types";

// The right-hand panel: everything about the selected event, including a
// hex viewer where each annotated field is highlighted.
export function Inspector({ event, onClose }: { event: NetEvent | null; onClose: () => void }) {
  const [hover, setHover] = useState<number | null>(null);
  const bytes = useMemo(() => decodeBytes(event?.bytes), [event]);
  const fields = event?.fields ?? [];

  // For every byte, the narrowest field that covers it (fields can nest,
  // e.g. "FIN bit" and "opcode" share byte 0 of a WebSocket frame).
  const owner = useMemo(() => {
    const o = new Array<number>(bytes.length).fill(-1);
    fields.forEach((f, i) => {
      for (let b = f.start; b < Math.min(f.end, bytes.length); b++) {
        const cur = o[b];
        if (cur === -1 || span(fields[cur]) >= span(f)) o[b] = i;
      }
    });
    return o;
  }, [bytes, fields]);

  if (!event) {
    return (
      <aside className="inspector placeholder">
        <h2>Inspector</h2>
        <p>Click any arrow or note in the diagram to see its details here.</p>
        <p>
          Arrows carry the <strong>real bytes</strong> that crossed the connection. Hover a field to find its bytes, or hover a byte to find its field.
        </p>
        <p className="muted">Dashed arrows are things that happen but that a normal program cannot observe (e.g. the kernel's TCP handshake).</p>
      </aside>
    );
  }

  return (
    <aside className="inspector">
      <div className="insp-head">
        <span className={`badge ${event.kind}`}>{event.kind}</span>
        <button className="close" onClick={onClose} aria-label="Close inspector">
          ×
        </button>
      </div>
      <h2>{event.title}</h2>
      <dl className="meta">
        {event.from && (
          <>
            <dt>direction</dt>
            <dd>
              {event.from} → {event.to}
              {event.dropped ? " (lost)" : ""}
              {event.simulated ? " (not observable from user space)" : ""}
            </dd>
          </>
        )}
        {event.actor && (
          <>
            <dt>actor</dt>
            <dd>{event.actor}</dd>
          </>
        )}
        {event.layer && (
          <>
            <dt>layer</dt>
            <dd>{event.layer}</dd>
          </>
        )}
        <dt>time</dt>
        <dd>+{event.elapsedMs.toFixed(3)} ms</dd>
        {event.size ? (
          <>
            <dt>size</dt>
            <dd>
              {event.size} bytes{event.size > bytes.length ? ` (showing first ${bytes.length})` : ""}
            </dd>
          </>
        ) : null}
      </dl>
      {event.detail && <p className="detail prewrap">{event.detail}</p>}

      {fields.length > 0 && (
        <table className="fields">
          <thead>
            <tr>
              <th>bytes</th>
              <th>field</th>
              <th>value</th>
            </tr>
          </thead>
          <tbody>
            {fields.map((f, i) => (
              <tr key={i} className={hover === i ? "hot" : ""} onMouseEnter={() => setHover(i)} onMouseLeave={() => setHover(null)}>
                <td className="mono range">
                  <span className={`swatch c${i % 6}`} />
                  {f.start}–{f.end - 1}
                </td>
                <td>{f.name}</td>
                <td className="mono value">{f.value}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {bytes.length > 0 && <HexView bytes={bytes} owner={owner} fields={fields} hover={hover} setHover={setHover} />}
    </aside>
  );
}

function span(f: Field) {
  return f.end - f.start;
}

function HexView({ bytes, owner, fields, hover, setHover }: { bytes: Uint8Array; owner: number[]; fields: Field[]; hover: number | null; setHover: (i: number | null) => void }) {
  const rows: number[] = [];
  for (let off = 0; off < bytes.length; off += 16) rows.push(off);
  const cls = (i: number) => {
    const o = owner[i];
    if (o === -1) return "";
    const f = fields[hover ?? -1];
    const hot = hover !== null && f && i >= f.start && i < f.end;
    return `c${o % 6} ${hot ? "hot" : ""} ${hover !== null && !hot ? "dim" : ""}`;
  };
  return (
    <div className="hex" onMouseLeave={() => setHover(null)}>
      {rows.map((off) => {
        const idx = Array.from({ length: Math.min(16, bytes.length - off) }, (_, k) => off + k);
        return (
          <div key={off} className="hex-row">
            <span className="off">{off.toString(16).padStart(4, "0")}</span>
            <span className="hx">
              {idx.map((i) => (
                <span key={i} className={`b ${cls(i)}`} onMouseEnter={() => setHover(owner[i] === -1 ? null : owner[i])} title={owner[i] >= 0 ? fields[owner[i]].name : undefined}>
                  {bytes[i].toString(16).padStart(2, "0")}
                </span>
              ))}
            </span>
            <span className="asc">
              {idx.map((i) => (
                <span key={i} className={`a ${cls(i)}`} onMouseEnter={() => setHover(owner[i] === -1 ? null : owner[i])}>
                  {bytes[i] >= 32 && bytes[i] < 127 ? String.fromCharCode(bytes[i]) : "·"}
                </span>
              ))}
            </span>
          </div>
        );
      })}
    </div>
  );
}
