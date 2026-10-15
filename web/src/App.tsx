import { useCallback, useEffect, useMemo, useState } from "react";
import type { Demo, NetEvent, Run } from "./types";
import { useEventStream } from "./useEventStream";
import { Timeline } from "./Timeline";
import { Inspector } from "./Inspector";
import { MetricsChart, hasTimeSeries } from "./MetricsChart";

export default function App() {
  const [demos, setDemos] = useState<Demo[]>([]);
  const [loadError, setLoadError] = useState("");
  const [selectedId, setSelectedId] = useState(() => location.hash.slice(1) || "tcp");
  const [params, setParams] = useState<Record<string, Record<string, string>>>({});
  const [runs, setRuns] = useState<Record<string, Run>>({});
  const [lastRunByDemo, setLastRunByDemo] = useState<Record<string, string>>({});
  const [selectedSeq, setSelectedSeq] = useState<number | null>(null);
  const [starting, setStarting] = useState(false);
  const [runError, setRunError] = useState("");

  useEffect(() => {
    fetch("/api/demos")
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
      .then((d: Demo[]) => setDemos(d))
      .catch((e: Error) => setLoadError(e.message));
  }, []);

  useEffect(() => {
    const onHash = () => {
      setSelectedId(location.hash.slice(1) || "tcp");
      setSelectedSeq(null);
    };
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  // Events of every run are kept, keyed by run id, so events that arrive
  // before the POST /api/runs response are not lost.
  const onEvent = useCallback((e: NetEvent) => {
    setRuns((prev) => {
      const run = prev[e.runId] ?? { id: e.runId, demo: e.demo, events: [], done: false, failed: false };
      return {
        ...prev,
        [e.runId]: {
          ...run,
          events: [...run.events, e],
          done: run.done || e.kind === "end",
          failed: run.failed || (e.kind === "end" && e.title !== "Finished"),
        },
      };
    });
  }, []);
  const status = useEventStream(onEvent);

  const demo = demos.find((d) => d.id === selectedId) ?? demos[0];
  const runId = demo ? lastRunByDemo[demo.id] : undefined;
  const run = runId ? runs[runId] : undefined;
  const events = run?.events ?? [];
  const selected = events.find((e) => e.seq === selectedSeq) ?? null;
  const values = demo ? { ...defaults(demo), ...params[demo.id] } : {};

  const grouped = useMemo(() => {
    const g: [string, Demo[]][] = [];
    for (const d of demos) {
      const last = g[g.length - 1];
      if (last && last[0] === d.group) last[1].push(d);
      else g.push([d.group, [d]]);
    }
    return g;
  }, [demos]);

  const choose = (id: string) => {
    setSelectedId(id);
    setSelectedSeq(null);
    setRunError("");
    history.replaceState(null, "", "#" + id);
  };

  const start = async () => {
    if (!demo) return;
    setStarting(true);
    setRunError("");
    setSelectedSeq(null);
    try {
      const r = await fetch("/api/runs", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ demo: demo.id, params: values }),
      });
      if (!r.ok) throw new Error((await r.text()) || `HTTP ${r.status}`);
      const { runId } = (await r.json()) as { runId: string };
      setLastRunByDemo((p) => ({ ...p, [demo.id]: runId }));
    } catch (e) {
      setRunError((e as Error).message);
    } finally {
      setStarting(false);
    }
  };

  const running = !!run && !run.done;

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <span className="logo" aria-hidden>⇄</span>
          <span>learn-network-protocols</span>
        </div>
        <span className={`status status-${status}`} title="Live event stream over our own WebSocket implementation">
          <span className="dot" /> {status === "open" ? "live" : status}
        </span>
      </header>

      <nav className="sidebar" aria-label="Demos">
        {loadError && <p className="error-text">Could not load demos: {loadError}. Is the Go server running?</p>}
        {grouped.map(([group, list]) => (
          <section key={group}>
            <h2>{group}</h2>
            {list.map((d) => (
              <button key={d.id} className={`demo-link ${d.id === demo?.id ? "active" : ""}`} onClick={() => choose(d.id)}>
                <span className="demo-id">{d.id}</span>
                <span className="demo-title">{d.title}</span>
              </button>
            ))}
          </section>
        ))}
      </nav>

      {demo && (
        <main className="main">
          <section className="demo-head">
            <div>
              <h1>{demo.title}</h1>
              <p className="summary">{demo.summary}</p>
            </div>
            <form
              className="params"
              onSubmit={(e) => {
                e.preventDefault();
                start();
              }}
            >
              {demo.params.map((p) => (
                <label key={p.name} title={p.help}>
                  <span>{p.name}</span>
                  {p.options ? (
                    <select value={values[p.name]} onChange={(e) => setParams((s) => ({ ...s, [demo.id]: { ...s[demo.id], [p.name]: e.target.value } }))}>
                      {p.options.map((o) => (
                        <option key={o}>{o}</option>
                      ))}
                    </select>
                  ) : (
                    <input value={values[p.name]} onChange={(e) => setParams((s) => ({ ...s, [demo.id]: { ...s[demo.id], [p.name]: e.target.value } }))} />
                  )}
                </label>
              ))}
              <button type="submit" className="run" disabled={starting || running || status !== "open"}>
                {running ? "Running…" : run ? "Run again" : "Run demo"}
              </button>
            </form>
            {runError && <p className="error-text">{runError}</p>}
          </section>

          <div className="workspace">
            <section className="timeline-panel" aria-label="Sequence diagram">
              {!run ? (
                <div className="empty">
                  <p>
                    Press <strong>Run demo</strong>. The Go server will start real clients and servers on your machine and stream every step here.
                  </p>
                  <Lesson demo={demo} />
                </div>
              ) : (
                <>
                  {hasTimeSeries(events) && <MetricsChart events={events} />}
                  <Timeline demo={demo} events={events} selectedSeq={selectedSeq} onSelect={setSelectedSeq} running={running} />
                  {run.done && <Lesson demo={demo} />}
                </>
              )}
            </section>
            <Inspector event={selected} onClose={() => setSelectedSeq(null)} />
          </div>
        </main>
      )}
    </div>
  );
}

function Lesson({ demo }: { demo: Demo }) {
  return (
    <div className="lesson">
      <h3>Key takeaways</h3>
      <ul>
        {demo.lesson.map((l) => (
          <li key={l}>{l}</li>
        ))}
      </ul>
    </div>
  );
}

function defaults(d: Demo): Record<string, string> {
  return Object.fromEntries(d.params.map((p) => [p.name, p.default]));
}
