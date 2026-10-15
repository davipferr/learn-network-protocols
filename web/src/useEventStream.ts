import { useEffect, useRef, useState } from "react";
import type { NetEvent } from "./types";

export type StreamStatus = "connecting" | "open" | "closed";

// Connects to /ws (served by our hand-written WebSocket server) and hands
// every event to onEvent. Reconnects with a small backoff.
export function useEventStream(onEvent: (e: NetEvent) => void): StreamStatus {
  const [status, setStatus] = useState<StreamStatus>("connecting");
  const handler = useRef(onEvent);
  handler.current = onEvent;

  useEffect(() => {
    let ws: WebSocket | null = null;
    let retry = 0;
    let timer: number | undefined;
    let stopped = false;

    const connect = () => {
      setStatus("connecting");
      const proto = location.protocol === "https:" ? "wss" : "ws";
      ws = new WebSocket(`${proto}://${location.host}/ws`);
      ws.onopen = () => {
        retry = 0;
        setStatus("open");
      };
      ws.onmessage = (m) => {
        try {
          handler.current(JSON.parse(m.data as string) as NetEvent);
        } catch {
          /* ignore malformed messages */
        }
      };
      ws.onclose = () => {
        setStatus("closed");
        if (stopped) return;
        timer = window.setTimeout(connect, Math.min(5000, 500 * 2 ** retry++));
      };
    };
    connect();
    return () => {
      stopped = true;
      window.clearTimeout(timer);
      ws?.close();
    };
  }, []);

  return status;
}
