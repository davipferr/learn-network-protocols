// Mirrors internal/demo and internal/events on the Go side.

export interface Param {
  name: string;
  default: string;
  help: string;
  options?: string[];
}

export interface Demo {
  id: string;
  title: string;
  group: string;
  summary: string;
  lesson: string[];
  actors: string[];
  params: Param[];
}

export interface Field {
  name: string;
  start: number;
  end: number;
  value?: string;
}

export type Kind = "start" | "step" | "info" | "state" | "send" | "metric" | "error" | "end";

export interface NetEvent {
  seq: number;
  runId: string;
  demo: string;
  time: string;
  elapsedMs: number;
  kind: Kind;
  actor?: string;
  from?: string;
  to?: string;
  layer?: string;
  title: string;
  detail?: string;
  bytes?: string; // base64 (Go encodes []byte that way)
  size?: number;
  fields?: Field[];
  metrics?: Record<string, number>;
  simulated?: boolean;
  dropped?: boolean;
}

export interface Run {
  id: string;
  demo: string;
  events: NetEvent[];
  done: boolean;
  failed: boolean;
}

export function decodeBytes(b64?: string): Uint8Array {
  if (!b64) return new Uint8Array();
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
