package demos

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/davipferr/learn-network-protocols/internal/demo"
	"github.com/davipferr/learn-network-protocols/internal/events"
)

func init() {
	demo.Register(&demo.Demo{
		ID:      "tcp",
		Title:   "TCP: a reliable byte stream",
		Order:   1,
		Group:   "Transport",
		Summary: "net.Listen + net.Dial: the handshake, the stream with no message boundaries, framing, and the FIN that closes it.",
		Actors:  []string{"client", "server"},
		Lesson: []string{
			"TCP is connection-oriented: the kernel does a 3-way handshake (SYN, SYN-ACK, ACK) before Dial returns.",
			"TCP delivers a stream of bytes, not messages. Three Write calls can arrive as one Read (or one Write as many Reads).",
			"Applications must add their own framing: a length prefix, a delimiter like '\\n', or a fixed size.",
			"Bytes arrive in order and are retransmitted if lost; you never see the gaps.",
			"Closing sends a FIN; the other side's Read returns io.EOF.",
		},
		Params: []demo.Param{
			{Name: "messages", Default: "hello,how are you?,bye", Help: "comma-separated messages the client sends"},
		},
		Run: runTCP,
	})
}

func runTCP(ctx context.Context, em *events.Emitter, p demo.Params) error {
	msgs := strings.Split(p.String("messages"), ",")

	em.Step("1. The server listens", "net.Listen(\"tcp\", addr) asks the operating system for a socket (socket + bind + listen syscalls). Port 0 means \"pick any free port\". The kernel now accepts connections for us, even before we call Accept.")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer ln.Close()
	em.State("server", "LISTEN on "+ln.Addr().String(), "")

	type result struct {
		conn net.Conn
		err  error
	}
	accepted := make(chan result, 1)
	go func() {
		c, err := ln.Accept()
		accepted <- result{c, err}
	}()

	em.Step("2. The client dials: the 3-way handshake", "net.Dial(\"tcp\", addr) asks the kernel to connect. The kernel exchanges three packets with the server's kernel and only then returns. Our Go code cannot see these packets (that needs raw sockets / Wireshark), so they are drawn dashed.")
	start := time.Now()
	var d net.Dialer
	client, err := d.DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		return err
	}
	defer client.Close()
	em.Concept("client", "server", "tcp", "SYN", "\"I want to talk. My initial sequence number is X.\"")
	em.Concept("server", "client", "tcp", "SYN-ACK", "\"OK. My sequence number is Y, and I acknowledge X+1.\"")
	em.Concept("client", "server", "tcp", "ACK", "\"I acknowledge Y+1.\" Both sides are now ESTABLISHED.")
	em.State("client", "ESTABLISHED", fmt.Sprintf("Dial returned in %s. The OS picked an ephemeral source port: %s -> %s", time.Since(start).Round(time.Microsecond), client.LocalAddr(), client.RemoteAddr()))

	r := <-accepted
	if r.err != nil {
		return r.err
	}
	server := r.conn
	defer server.Close()
	em.State("server", "Accept() returned a new socket", fmt.Sprintf("A connection is identified by 4 values: %s <-> %s. The listening socket keeps waiting for other clients.", server.LocalAddr(), server.RemoteAddr()))

	em.Step("3. TCP has no message boundaries", fmt.Sprintf("The client calls Write %d times, once per message. The server waits a little and then calls Read once. Watch what one Read returns.", len(msgs)))
	for _, m := range msgs {
		em.Send("client", "server", "tcp", fmt.Sprintf("Write(%q)", m), []byte(m), nil, "")
		if _, err := client.Write([]byte(m)); err != nil {
			return err
		}
	}
	time.Sleep(100 * time.Millisecond)
	buf := make([]byte, 4096)
	server.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := server.Read(buf)
	if err != nil {
		return err
	}
	em.Info("server", fmt.Sprintf("ONE Read() returned %d bytes: %q", n, buf[:n]),
		fmt.Sprintf("The %d writes were glued together in the server's receive buffer. TCP only promises the bytes arrive in order, not how they are grouped. Without framing, the server cannot know where \"%s\" ends.", len(msgs), msgs[0]))

	em.Step("4. Fixing it with framing: length-prefixed messages", "Now each message is sent as [2-byte big-endian length][payload]. The receiver reads exactly 2 bytes (io.ReadFull), learns the size, then reads exactly that many bytes. This is how many real protocols (DNS over TCP, gRPC, Kafka, Postgres...) frame messages.")
	done := make(chan error, 1)
	go func() { done <- framedEchoServer(server, em, len(msgs)) }()
	for _, m := range msgs {
		frame := binary.BigEndian.AppendUint16(nil, uint16(len(m)))
		frame = append(frame, m...)
		em.Send("client", "server", "tcp", fmt.Sprintf("framed %q", m), frame, []events.Field{
			{Name: "length prefix (uint16)", Start: 0, End: 2, Value: fmt.Sprint(len(m))},
			{Name: "payload", Start: 2, End: len(frame), Value: m},
		}, "")
		if _, err := client.Write(frame); err != nil {
			return err
		}
	}
	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	for range msgs {
		reply, err := readFrame(client)
		if err != nil {
			return err
		}
		em.Info("client", fmt.Sprintf("got framed reply %q", reply), "")
	}
	if err := <-done; err != nil {
		return err
	}

	em.Step("5. Closing: FIN", "The client calls CloseWrite() (a \"half close\"): its kernel sends a FIN meaning \"I will send no more bytes\". The server's next Read returns io.EOF. Then the server closes too.")
	if err := client.(*net.TCPConn).CloseWrite(); err != nil {
		return err
	}
	em.Concept("client", "server", "tcp", "FIN", "\"No more data from me.\"")
	server.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := server.Read(buf); errors.Is(err, io.EOF) {
		em.State("server", "Read() returned io.EOF", "That is how Go reports the FIN: the stream is over.")
	} else if err != nil {
		return err
	}
	server.Close()
	em.Concept("server", "client", "tcp", "FIN + ACK", "The server closes its side too.")
	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := client.Read(buf); errors.Is(err, io.EOF) {
		em.State("client", "CLOSED", "Both directions are closed. The client's kernel keeps the port in TIME_WAIT for a while so late packets cannot confuse a new connection.")
	}
	return nil
}

func framedEchoServer(c net.Conn, em *events.Emitter, count int) error {
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	for range count {
		msg, err := readFrame(c)
		if err != nil {
			return err
		}
		em.Info("server", fmt.Sprintf("read exactly one message: %q", msg), "io.ReadFull(conn, header[:2]) then io.ReadFull(conn, payload[:length]).")
		reply := strings.ToUpper(msg)
		frame := binary.BigEndian.AppendUint16(nil, uint16(len(reply)))
		frame = append(frame, reply...)
		em.Send("server", "client", "tcp", fmt.Sprintf("framed reply %q", reply), frame, []events.Field{
			{Name: "length prefix (uint16)", Start: 0, End: 2, Value: fmt.Sprint(len(reply))},
			{Name: "payload", Start: 2, End: len(frame), Value: reply},
		}, "")
		if _, err := c.Write(frame); err != nil {
			return err
		}
	}
	return nil
}

func readFrame(c net.Conn) (string, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return "", err
	}
	payload := make([]byte, binary.BigEndian.Uint16(hdr[:]))
	if _, err := io.ReadFull(c, payload); err != nil {
		return "", err
	}
	return string(payload), nil
}
