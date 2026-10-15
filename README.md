# learn-network-protocols

Learn how network protocols work **under the hood**, by running them.

Every demo starts real clients and servers on your machine using Go's standard library with very little abstraction. It then shows each step as it happens: the bytes on the wire, which field each byte belongs to, and why it is there. You can run the demos in the terminal or watch them in a browser UI that draws a live sequence diagram and a hex inspector.

| Demo          | What you see                                                                                              | Go API                                                        |
| ------------- | --------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| `tcp`         | 3-way handshake, a stream with no message boundaries, length-prefix framing, FIN / `io.EOF`               | `net.Listen`, `net.Dial`                                      |
| `udp`         | no handshake, one read = one datagram, simulated loss and reordering, sequence numbers                    | `net.ListenUDP`, `net.DialUDP`                                |
| `http`        | an HTTP/1.1 server **written by hand** on raw TCP, keep-alive, then `net/http` traced with `httptrace`    | `net`, `bufio`, `net/http`                                    |
| `rest`        | a JSON CRUD API with `ServeMux` patterns (`GET /books/{id}`), status codes, raw request/response bytes    | `net/http` (no framework)                                     |
| `websocket`   | the Upgrade handshake, `Sec-WebSocket-Accept`, masked frames, server push, ping/pong, close handshake      | **implemented from scratch** (RFC 6455)                        |
| `tls`         | certificate verification, every TLS record of the handshake (1.2 vs 1.3), what an eavesdropper sees       | `crypto/tls`, `crypto/x509`                                   |
| `dns`         | a DNS query built byte by byte, sent over UDP, decoded answer with name compression, TC fallback to TCP   | `net` (raw UDP/TCP) and `net.Resolver`                        |
| `grpc`        | HTTP/2 frames (SETTINGS, HPACK headers, DATA, trailers), gRPC message framing, protobuf wire format       | `google.golang.org/grpc`                                      |
| `concurrency` | the same TCP server sequential vs. one goroutine per connection, timed and charted                        | goroutines, `sync`, `sync/atomic`                             |

## Running it

Requirements: **Go 1.26+**. Node.js is only needed if you change the UI.

```bash
go run .                        # list the demos
go run . tcp                    # run one demo in the terminal
go run . dns -name go.dev -type MX
go run . tls -version 1.2       # every demo has flags: go run . tls -h
go run . all                    # run every demo
go run . serve                  # visual UI at http://localhost:8080
```

In the terminal, `-bytes N` controls how many bytes of each payload are hex-dumped. `NO_COLOR=1` turns colors off.

### The visual UI

`go run . serve` serves a React app that is embedded in the Go binary. Pick a demo, adjust its parameters and press **Run demo**:

- **Sequence diagram**: one lane per actor (client, server, network…). Solid arrows carry real bytes. Dashed arrows are things that happen but can't be observed from user space, such as the kernel's SYN/ACK. A ✕ marks a lost datagram.
- **Inspector**: click any arrow to see the exact bytes in a hex viewer. Each protocol field is colored and listed with its decoded value. Hover a field to find its bytes, or hover a byte to find its field.

The browser receives the events through this project's **own WebSocket implementation** (`internal/ws`), the same code the `websocket` demo teaches.

## How it works

```
 demos (tcp, udp, tls, …)          event bus                  consumers
 ┌──────────────────────┐   Emit   ┌─────────┐   subscribe   ┌──────────────────────┐
 │ real client + server │ ───────▶ │ events  │ ────────────▶ │ terminal printer     │
 │ on 127.0.0.1         │          │  .Bus   │               │ WebSocket → React UI │
 └──────────────────────┘          └─────────┘               └──────────────────────┘
          ▲
          │ wire.Conn: a net.Conn wrapper that copies every Read/Write
          │ (placed BELOW TLS / HTTP/2 so the real wire bytes are visible)
```

```
main.go                  CLI: list, run a demo, all, serve
internal/events          Event types, Bus (fan-out) and Emitter
internal/demo            demo registry and runner
internal/demos           one file per lesson
internal/wire            tapped net.Conn / net.Listener
internal/httpraw         hand-written HTTP/1.1 message reader + field annotations
internal/ws              hand-written WebSocket (RFC 6455): handshake and frames
internal/dnsmsg          DNS message builder/parser (RFC 1035), incl. compression
internal/tlsrec          TLS record splitter and handshake message decoder
internal/h2              HTTP/2 frame decoder, HPACK, gRPC framing, protobuf wire format
internal/pb/learnv1      code generated from proto/learn/v1/greeter.proto
internal/server          HTTP API + /ws event stream for the UI
internal/webui           go:embed of the built UI (dist/)
web/                     React + Vite + TypeScript source of the UI
```

## Developing

```bash
go test ./...                                  # parsers + every demo end to end (except DNS)
go test -race ./...                            # needs CGO_ENABLED=1 and a C compiler
```

UI (hot reload; the Vite dev server proxies `/api` and `/ws` to the Go server):

```bash
go run . serve
cd web && npm install && npm run dev           # http://localhost:5173
npm run build                                  # writes internal/webui/dist, embedded by Go
```

The built UI in `internal/webui/dist` is committed so that `go run .` works without Node.js. Rebuild it after changing `web/`.

Regenerating the gRPC code after editing `proto/` uses [buf](https://buf.build):

```bash
go install github.com/bufbuild/buf/cmd/buf@latest
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
buf generate
```

## Notes

- Everything except `dns` runs on `127.0.0.1` and needs no network access. `dns` queries a real resolver (`8.8.8.8:53` by default; change it with `-server`).
- The TLS demo generates a throwaway self-signed certificate in memory on every run.
- The hand-written HTTP and WebSocket code is written to teach, not for production. It skips things like chunked encoding, extensions and many limits.
