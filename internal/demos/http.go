package demos

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"time"

	"github.com/davipferr/learn-network-protocols/internal/demo"
	"github.com/davipferr/learn-network-protocols/internal/events"
	"github.com/davipferr/learn-network-protocols/internal/httpraw"
)

func init() {
	demo.Register(&demo.Demo{
		ID:      "http",
		Title:   "HTTP/1.1 by hand",
		Order:   3,
		Group:   "The Web",
		Summary: "A hand-written HTTP server on raw TCP, talked to first with hand-typed bytes and then by Go's net/http client (traced phase by phase).",
		Actors:  []string{"client", "server"},
		Lesson: []string{
			"HTTP/1.1 is plain text over TCP: a start line, headers, an empty line (\\r\\n\\r\\n), then the body.",
			"Content-Length is the framing: it tells the reader where the body (and so the message) ends.",
			"Keep-alive lets several requests reuse one TCP connection, saving the handshake each time.",
			"net/http does exactly this for you, plus connection pooling, redirects, gzip, timeouts...",
			"httptrace exposes each phase of a request: DNS, connect, TLS, write, first byte.",
		},
		Params: []demo.Param{
			{Name: "body", Default: "ping from the client", Help: "body sent in the POST /echo request"},
		},
		Run: runHTTP,
	})
}

func runHTTP(ctx context.Context, em *events.Emitter, p demo.Params) error {
	em.Step("1. A web server written with net.Listen", "No net/http on the server side: we accept TCP connections and parse requests ourselves with bufio. Every request line, header and body you see below was parsed by ~60 lines of code in internal/httpraw.")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer ln.Close()
	addr := ln.Addr().String()
	em.State("server", "listening on "+addr, "")
	go acceptLoop(ln, func(c net.Conn) { handwrittenHTTPServer(c, em) })

	em.Step("2. Speaking HTTP with raw bytes", "The client opens a TCP connection and writes the request text itself. Note the \\r\\n line endings and the empty line that ends the headers.")
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(conn)

	body := p.String("body")
	requests := []string{
		"GET /hello HTTP/1.1\r\nHost: " + addr + "\r\nUser-Agent: hand-typed/1.0\r\nAccept: text/plain\r\n\r\n",
		"POST /echo HTTP/1.1\r\nHost: " + addr + "\r\nContent-Type: text/plain\r\nContent-Length: " + fmt.Sprint(len(body)) + "\r\n\r\n" + body,
		"GET /missing HTTP/1.1\r\nHost: " + addr + "\r\nConnection: close\r\n\r\n",
	}
	notes := []string{
		"A first request on a fresh connection.",
		"Same TCP connection (keep-alive)! A body needs Content-Length so the server knows where it ends.",
		"\"Connection: close\" asks the server to close the TCP connection after answering.",
	}
	for i, req := range requests {
		em.Info("client", fmt.Sprintf("writing request #%d by hand", i+1), notes[i])
		if _, err := conn.Write([]byte(req)); err != nil {
			return err
		}
		resp, err := httpraw.ReadMessage(br)
		if err != nil {
			return err
		}
		em.Info("client", "parsed response: "+resp.StartLine, fmt.Sprintf("body: %q", resp.Body))
	}
	if _, err := br.ReadByte(); err == io.EOF {
		em.State("client", "server closed the connection (EOF)", "As requested with Connection: close.")
	}

	em.Step("3. The same server, called by net/http with httptrace", "Now the client is Go's real HTTP client. httptrace hooks report each phase. We use the name \"localhost\" so there is a DNS step too. Look at the request bytes the server receives: net/http adds headers like User-Agent and Accept-Encoding: gzip on its own.")
	port := addr[strings.LastIndex(addr, ":")+1:]
	url := "http://localhost:" + port + "/hello"
	tr := &http.Transport{} // a fresh pool, no proxy
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}

	for i := 1; i <= 2; i++ {
		t0 := time.Now()
		ms := func() string { return fmt.Sprintf("+%.2fms", float64(time.Since(t0).Microseconds())/1000) }
		trace := &httptrace.ClientTrace{
			GetConn: func(hostPort string) {
				em.Info("client", ms()+" GetConn "+hostPort, "Ask the connection pool for an idle connection to this host.")
			},
			DNSStart: func(i httptrace.DNSStartInfo) {
				em.Info("client", ms()+" DNSStart "+i.Host, "Resolve the name to IP addresses.")
			},
			DNSDone: func(i httptrace.DNSDoneInfo) {
				em.Info("client", fmt.Sprintf("%s DNSDone %v", ms(), i.Addrs), "")
			},
			ConnectStart: func(network, a string) {
				em.Info("client", ms()+" ConnectStart "+network+" "+a, "TCP handshake begins.")
			},
			ConnectDone: func(network, a string, err error) {
				if err != nil {
					em.Info("client", ms()+" ConnectDone "+a+" failed", err.Error()+"\nThe server only listens on IPv4, so Go falls back to the next address DNS returned.")
					return
				}
				em.Info("client", ms()+" ConnectDone "+a, "")
			},
			GotConn: func(i httptrace.GotConnInfo) {
				detail := "A brand-new TCP connection."
				if i.Reused {
					detail = fmt.Sprintf("REUSED an idle keep-alive connection (idle for %s): no DNS, no TCP handshake this time.", i.IdleTime.Round(time.Microsecond))
				}
				em.Info("client", fmt.Sprintf("%s GotConn reused=%v", ms(), i.Reused), detail)
			},
			WroteHeaders: func() { em.Info("client", ms()+" WroteHeaders", "") },
			WroteRequest: func(httptrace.WroteRequestInfo) {
				em.Info("client", ms()+" WroteRequest", "Now waiting for the server.")
			},
			GotFirstResponseByte: func() {
				em.Info("client", ms()+" GotFirstResponseByte", "Time to first byte (TTFB): network round trip + server processing.")
			},
		}
		req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		em.Info("client", fmt.Sprintf("client.Get(%q) #%d", url, i), "")
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		em.Info("client", fmt.Sprintf("%s %s -> %q", ms(), resp.Status, b), "resp.Body fully read and closed: the connection goes back to the pool for reuse.")
	}
	return nil
}

func acceptLoop(ln net.Listener, handle func(net.Conn)) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go handle(c)
	}
}

// handwrittenHTTPServer serves one TCP connection: read a request, answer,
// repeat while the client keeps the connection alive.
func handwrittenHTTPServer(c net.Conn, em *events.Emitter) {
	defer c.Close()
	br := bufio.NewReader(c)
	for {
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		req, err := httpraw.ReadMessage(br)
		if err != nil {
			return
		}
		em.Send("client", "server", "http/1.1", req.StartLine, req.Raw, httpraw.Fields(req.Raw), "")

		parts := strings.SplitN(req.StartLine, " ", 3)
		method, path := parts[0], ""
		if len(parts) > 1 {
			path = parts[1]
		}
		status, body := "404 Not Found", "no such page: "+path
		switch {
		case method == "GET" && path == "/hello":
			status, body = "200 OK", "Hello from a hand-written HTTP server!"
		case method == "POST" && path == "/echo":
			status, body = "200 OK", "you sent: "+string(req.Body)
		}
		closeAfter := strings.EqualFold(req.Header("Connection"), "close")

		resp := "HTTP/1.1 " + status + "\r\n" +
			"Content-Type: text/plain; charset=utf-8\r\n" +
			"Content-Length: " + fmt.Sprint(len(body)) + "\r\n" +
			"Date: " + time.Now().UTC().Format(http.TimeFormat) + "\r\n"
		if closeAfter {
			resp += "Connection: close\r\n"
		}
		resp += "\r\n" + body
		em.Send("server", "client", "http/1.1", "HTTP/1.1 "+status, []byte(resp), httpraw.Fields([]byte(resp)), "")
		if _, err := c.Write([]byte(resp)); err != nil {
			return
		}
		if closeAfter {
			em.State("server", "closing the TCP connection", "")
			return
		}
	}
}
