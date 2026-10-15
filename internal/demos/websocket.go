package demos

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/davipferr/learn-network-protocols/internal/demo"
	"github.com/davipferr/learn-network-protocols/internal/events"
	"github.com/davipferr/learn-network-protocols/internal/httpraw"
	"github.com/davipferr/learn-network-protocols/internal/ws"
)

func init() {
	demo.Register(&demo.Demo{
		ID:      "websocket",
		Title:   "WebSocket from scratch",
		Order:   5,
		Group:   "The Web",
		Summary: "An HTTP Upgrade handshake, then binary frames in both directions, implemented by hand following RFC 6455 (no library).",
		Actors:  []string{"client", "server"},
		Lesson: []string{
			"A WebSocket begins as an HTTP/1.1 GET with \"Upgrade: websocket\"; the server answers 101 Switching Protocols.",
			"Sec-WebSocket-Accept = base64(SHA-1(client key + fixed GUID)) proves the server understood the upgrade.",
			"After that, the same TCP connection carries small binary frames: FIN, opcode, MASK, length, payload.",
			"It is full duplex: the server can push messages at any time, without a request.",
			"Client-to-server frames are XOR-masked with a random key (to protect buggy proxies); server frames are not.",
			"Control frames (ping, pong, close) can be sent between data frames; close is a two-way handshake.",
		},
		Params: []demo.Param{
			{Name: "message", Default: "Hello, server!", Help: "text message the client sends"},
		},
		Run: runWebSocket,
	})
}

func runWebSocket(ctx context.Context, em *events.Emitter, p demo.Params) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/chat", func(w http.ResponseWriter, r *http.Request) {
		c, err := ws.Upgrade(w, r)
		if err != nil {
			em.Error("server", "upgrade failed", err)
			return
		}
		defer c.Close()
		for {
			op, msg, err := c.ReadMessage() // answers pings and close frames itself
			if err != nil {
				em.State("server", "connection finished", err.Error())
				return
			}
			switch {
			case op == ws.OpText && string(msg) == "subscribe":
				for i := 1; i <= 3; i++ {
					time.Sleep(80 * time.Millisecond)
					c.WriteText(fmt.Sprintf("server push #%d at %s", i, time.Now().Format("15:04:05.000")))
				}
			case op == ws.OpText:
				c.WriteText("echo: " + string(msg))
			default:
				c.WriteBinary(msg)
			}
		}
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	defer srv.Close()
	url := "ws://" + ln.Addr().String() + "/chat"
	em.State("server", "HTTP server with a /chat endpoint on "+ln.Addr().String(), "")

	em.Step("1. The opening handshake (plain HTTP)", "The client sends a normal GET with Upgrade headers and a random 16-byte key in base64.")
	dial := func(ctx context.Context, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}
	c, hs, err := ws.Dial(ctx, url, dial)
	if hs != nil {
		em.Send("client", "server", "http/1.1", "GET /chat (Upgrade: websocket)", hs.Request, httpraw.Fields(hs.Request), "")
		if hs.Response != nil {
			em.Send("server", "client", "http/1.1", hs.Response.StartLine, hs.Response.Raw, httpraw.Fields(hs.Response.Raw),
				fmt.Sprintf("The client checks the proof:\nbase64(SHA1(%q + \"258EAFA5-E914-47DA-95CA-C5AB0DC85B11\"))\n= %s\nIt matches, so both sides switch to the WebSocket protocol on this same TCP connection.", hs.Key, hs.ExpectedAccept))
		}
	}
	if err != nil {
		return err
	}
	defer c.Close()
	em.State("server", "hijacked the TCP connection from net/http", "http.ResponseController.Hijack() hands the raw TCP connection to our code. From now on both sides read and write WebSocket frames on it.")
	c.NetConn().SetDeadline(time.Now().Add(10 * time.Second))

	// Every frame the client sends or receives is shown with its wire bytes.
	c.SetHook(func(sent bool, f ws.Frame, raw []byte) {
		from, to := "server", "client"
		if sent {
			from, to = "client", "server"
		}
		title := "frame: " + ws.OpName(f.Opcode)
		switch f.Opcode {
		case ws.OpText, ws.OpPing, ws.OpPong:
			title += fmt.Sprintf(" %q", f.Payload)
		case ws.OpBinary:
			title += fmt.Sprintf(" (%d bytes)", len(f.Payload))
		}
		detail := ""
		if f.Masked {
			detail = fmt.Sprintf("Masked with key % x: every payload byte is XORed with key[i %% 4]. On the wire the text is unreadable; the server unmasks it.", f.MaskKey)
		}
		em.Send(from, to, "websocket", title, raw, ws.FrameFields(raw), detail)
	})

	em.Step("2. A text message and its echo", "The client's frame is masked (MASK bit = 1, 4-byte key). The server's reply is not.")
	if err := c.WriteText(p.String("message")); err != nil {
		return err
	}
	if _, msg, err := c.ReadMessage(); err != nil {
		return err
	} else {
		em.Info("client", fmt.Sprintf("received %q", msg), "")
	}

	em.Step("3. Server push", "After one \"subscribe\" message, the server sends three messages on its own, with no request for each one. Plain HTTP/1.1 cannot do this: the server may only answer.")
	if err := c.WriteText("subscribe"); err != nil {
		return err
	}
	for range 3 {
		if _, msg, err := c.ReadMessage(); err != nil {
			return err
		} else {
			em.Info("client", fmt.Sprintf("pushed: %q", msg), "")
		}
	}

	em.Step("4. Ping / pong", "Control frames check that the other side is alive (and keep NAT/proxies from closing an idle connection). The server's ReadMessage answers the ping automatically with a pong carrying the same payload.")
	if err := c.Ping([]byte("are you there?")); err != nil {
		return err
	}
	if _, _, err := c.ReadFrame(); err != nil {
		return err
	}

	em.Step("5. A bigger binary message", "300 bytes do not fit in the 7-bit length field (max 125), so the length byte says 126 and the real length follows in the next 2 bytes. Above 65535 bytes it would be 127 + 8 bytes.")
	payload := bytes.Repeat([]byte{0xCA, 0xFE}, 150)
	if err := c.WriteBinary(payload); err != nil {
		return err
	}
	if _, msg, err := c.ReadMessage(); err != nil {
		return err
	} else {
		em.Info("client", fmt.Sprintf("binary echo of %d bytes, identical: %v", len(msg), bytes.Equal(msg, payload)), "")
	}

	em.Step("6. The closing handshake", "The client sends a close frame with status 1000 (normal closure). The server replies with its own close frame, then the TCP connection is closed.")
	if err := c.CloseFrame(1000, "bye"); err != nil {
		return err
	}
	if f, _, err := c.ReadFrame(); err == nil && f.Opcode == ws.OpClose {
		em.State("client", "close handshake complete", "Both sides agreed to close; now the TCP connection itself is closed (FIN).")
	}
	return nil
}
