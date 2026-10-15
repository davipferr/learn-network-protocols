// Package ws is a from-scratch WebSocket (RFC 6455) implementation.
//
// A WebSocket starts life as an ordinary HTTP/1.1 request carrying
// "Upgrade: websocket". The server answers "101 Switching Protocols" and from
// then on both sides exchange binary *frames* over the same TCP connection:
//
//	 0                   1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-------+-+-------------+-------------------------------+
//	|F|R|R|R| opcode|M| Payload len |    Extended payload length    |
//	|I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
//	|N|V|V|V|       |S|             |   (if payload len==126/127)   |
//	| |1|2|3|       |K|             |                               |
//	+-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
//	|     Masking-key (0 or 4 bytes, only client -> server)         |
//	+---------------------------------------------------------------+
//	|                         Payload Data                          |
//	+---------------------------------------------------------------+
//
// This package is used both by the WebSocket demo and by the web UI itself.
package ws

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/davipferr/learn-network-protocols/internal/httpraw"
)

// The magic GUID from RFC 6455. Proves the server really speaks WebSocket.
const guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

const (
	OpContinuation byte = 0x0
	OpText         byte = 0x1
	OpBinary       byte = 0x2
	OpClose        byte = 0x8
	OpPing         byte = 0x9
	OpPong         byte = 0xA
)

func OpName(op byte) string {
	switch op {
	case OpContinuation:
		return "continuation"
	case OpText:
		return "text"
	case OpBinary:
		return "binary"
	case OpClose:
		return "close"
	case OpPing:
		return "ping"
	case OpPong:
		return "pong"
	}
	return fmt.Sprintf("0x%x", op)
}

// AcceptKey computes Sec-WebSocket-Accept = base64(SHA1(key + GUID)).
func AcceptKey(key string) string {
	h := sha1.Sum([]byte(key + guid))
	return base64.StdEncoding.EncodeToString(h[:])
}

// Frame is one decoded frame. Payload is already unmasked.
type Frame struct {
	Fin     bool
	Opcode  byte
	Masked  bool
	MaskKey [4]byte
	Payload []byte
}

// FrameHook observes every frame with its exact wire bytes.
// sent is true for frames written by this side.
type FrameHook func(sent bool, f Frame, raw []byte)

type Conn struct {
	nc       net.Conn
	br       *bufio.Reader
	isClient bool // clients must mask what they send
	wmu      sync.Mutex
	closed   bool
	hook     FrameHook
}

func (c *Conn) SetHook(h FrameHook) { c.hook = h }
func (c *Conn) NetConn() net.Conn   { return c.nc }

// ---- handshake ----

// Upgrade turns an HTTP request into a WebSocket connection (server side).
func Upgrade(w http.ResponseWriter, r *http.Request) (*Conn, error) {
	if r.Method != http.MethodGet ||
		!strings.EqualFold(r.Header.Get("Upgrade"), "websocket") ||
		!headerContains(r.Header.Get("Connection"), "upgrade") {
		http.Error(w, "expected a WebSocket upgrade", http.StatusBadRequest)
		return nil, errors.New("not a websocket handshake")
	}
	if r.Header.Get("Sec-WebSocket-Version") != "13" {
		w.Header().Set("Sec-WebSocket-Version", "13")
		http.Error(w, "unsupported version", http.StatusUpgradeRequired)
		return nil, errors.New("unsupported websocket version")
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		http.Error(w, "missing Sec-WebSocket-Key", http.StatusBadRequest)
		return nil, errors.New("missing key")
	}

	// Take the raw TCP connection away from net/http: from now on we own it.
	nc, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return nil, err
	}
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + AcceptKey(key) + "\r\n\r\n"
	if _, err := nc.Write([]byte(resp)); err != nil {
		nc.Close()
		return nil, err
	}
	return &Conn{nc: nc, br: brw.Reader}, nil
}

// Handshake describes the client side of the opening handshake.
type Handshake struct {
	Key            string
	ExpectedAccept string
	Request        []byte
	Response       *httpraw.Message
}

// Dial opens a TCP connection and performs the WebSocket handshake by hand.
// dial lets the caller wrap the connection (e.g. to tap the bytes).
func Dial(ctx context.Context, rawURL string, dial func(ctx context.Context, addr string) (net.Conn, error)) (*Conn, *Handshake, error) {
	host, path, ok := strings.Cut(strings.TrimPrefix(rawURL, "ws://"), "/")
	if !ok {
		path = ""
	}
	nc, err := dial(ctx, host)
	if err != nil {
		return nil, nil, err
	}

	keyBytes := make([]byte, 16)
	rand.Read(keyBytes)
	hs := &Handshake{Key: base64.StdEncoding.EncodeToString(keyBytes)}
	hs.ExpectedAccept = AcceptKey(hs.Key)
	hs.Request = []byte("GET /" + path + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + hs.Key + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n")
	if _, err := nc.Write(hs.Request); err != nil {
		nc.Close()
		return nil, nil, err
	}

	br := bufio.NewReader(nc)
	resp, err := httpraw.ReadMessage(br)
	if err != nil {
		nc.Close()
		return nil, nil, err
	}
	hs.Response = resp
	if !strings.HasPrefix(resp.StartLine, "HTTP/1.1 101") {
		nc.Close()
		return nil, hs, fmt.Errorf("server refused upgrade: %s", resp.StartLine)
	}
	if got := resp.Header("Sec-WebSocket-Accept"); got != hs.ExpectedAccept {
		nc.Close()
		return nil, hs, fmt.Errorf("bad Sec-WebSocket-Accept %q, want %q", got, hs.ExpectedAccept)
	}
	return &Conn{nc: nc, br: br, isClient: true}, hs, nil
}

// ---- frames ----

// EncodeFrame builds the wire bytes of a single frame.
func EncodeFrame(fin bool, op byte, payload []byte, mask bool) []byte {
	b0 := op
	if fin {
		b0 |= 0x80
	}
	buf := []byte{b0, 0}
	n := len(payload)
	switch {
	case n <= 125:
		buf[1] = byte(n)
	case n <= 0xFFFF:
		buf[1] = 126
		buf = binary.BigEndian.AppendUint16(buf, uint16(n))
	default:
		buf[1] = 127
		buf = binary.BigEndian.AppendUint64(buf, uint64(n))
	}
	if !mask {
		return append(buf, payload...)
	}
	buf[1] |= 0x80
	var key [4]byte
	rand.Read(key[:])
	buf = append(buf, key[:]...)
	start := len(buf)
	buf = append(buf, payload...)
	for i := range payload {
		buf[start+i] ^= key[i%4]
	}
	return buf
}

func (c *Conn) WriteFrame(fin bool, op byte, payload []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	raw := EncodeFrame(fin, op, payload, c.isClient)
	if c.hook != nil {
		f, _, _ := decode(raw)
		c.hook(true, f, raw)
	}
	_, err := c.nc.Write(raw)
	return err
}

func (c *Conn) WriteText(s string) error   { return c.WriteFrame(true, OpText, []byte(s)) }
func (c *Conn) WriteBinary(b []byte) error { return c.WriteFrame(true, OpBinary, b) }
func (c *Conn) Ping(b []byte) error        { return c.WriteFrame(true, OpPing, b) }

// MaxPayload limits a single frame so a peer cannot make us allocate gigabytes.
const MaxPayload = 16 << 20

// ReadFrame reads exactly one frame from the connection.
func (c *Conn) ReadFrame() (Frame, []byte, error) {
	var raw []byte
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c.br, hdr); err != nil {
		return Frame{}, nil, err
	}
	raw = append(raw, hdr...)
	n := uint64(hdr[1] & 0x7F)
	switch n {
	case 126:
		ext := make([]byte, 2)
		if _, err := io.ReadFull(c.br, ext); err != nil {
			return Frame{}, nil, err
		}
		raw = append(raw, ext...)
		n = uint64(binary.BigEndian.Uint16(ext))
	case 127:
		ext := make([]byte, 8)
		if _, err := io.ReadFull(c.br, ext); err != nil {
			return Frame{}, nil, err
		}
		raw = append(raw, ext...)
		n = binary.BigEndian.Uint64(ext)
	}
	if n > MaxPayload {
		return Frame{}, nil, fmt.Errorf("frame too large: %d bytes", n)
	}
	rest := int(n)
	if hdr[1]&0x80 != 0 {
		rest += 4
	}
	body := make([]byte, rest)
	if _, err := io.ReadFull(c.br, body); err != nil {
		return Frame{}, nil, err
	}
	raw = append(raw, body...)
	f, _, err := decode(raw)
	if err != nil {
		return Frame{}, nil, err
	}
	if c.hook != nil {
		c.hook(false, f, raw)
	}
	return f, raw, nil
}

// ReadMessage returns the next complete data message, transparently
// answering pings, joining fragmented messages and completing the close
// handshake (it then returns io.EOF).
func (c *Conn) ReadMessage() (op byte, payload []byte, err error) {
	var msgOp byte
	var buf []byte
	for {
		f, _, err := c.ReadFrame()
		if err != nil {
			return 0, nil, err
		}
		switch f.Opcode {
		case OpPing:
			if err := c.WriteFrame(true, OpPong, f.Payload); err != nil {
				return 0, nil, err
			}
		case OpPong:
			// nothing to do
		case OpClose:
			c.wmu.Lock()
			alreadyClosing := c.closed
			c.wmu.Unlock()
			if !alreadyClosing {
				c.WriteFrame(true, OpClose, f.Payload) // echo the close frame
				c.wmu.Lock()
				c.closed = true
				c.wmu.Unlock()
			}
			return 0, nil, io.EOF
		case OpText, OpBinary:
			msgOp, buf = f.Opcode, f.Payload
			if f.Fin {
				return msgOp, buf, validate(msgOp, buf)
			}
		case OpContinuation:
			buf = append(buf, f.Payload...)
			if f.Fin {
				return msgOp, buf, validate(msgOp, buf)
			}
		default:
			return 0, nil, fmt.Errorf("unknown opcode %d", f.Opcode)
		}
	}
}

func validate(op byte, b []byte) error {
	if op == OpText && !utf8.Valid(b) {
		return errors.New("text frame is not valid UTF-8")
	}
	return nil
}

// CloseFrame starts the closing handshake with a status code and reason.
// The caller should keep reading until ReadMessage returns io.EOF.
func (c *Conn) CloseFrame(code uint16, reason string) error {
	payload := binary.BigEndian.AppendUint16(nil, code)
	payload = append(payload, reason...)
	err := c.WriteFrame(true, OpClose, payload)
	c.wmu.Lock()
	c.closed = true
	c.wmu.Unlock()
	return err
}

func (c *Conn) Close() error { return c.nc.Close() }

func decode(raw []byte) (Frame, int, error) {
	if len(raw) < 2 {
		return Frame{}, 0, io.ErrUnexpectedEOF
	}
	f := Frame{Fin: raw[0]&0x80 != 0, Opcode: raw[0] & 0x0F, Masked: raw[1]&0x80 != 0}
	n := int(raw[1] & 0x7F)
	pos := 2
	switch n {
	case 126:
		n = int(binary.BigEndian.Uint16(raw[2:4]))
		pos = 4
	case 127:
		n = int(binary.BigEndian.Uint64(raw[2:10]))
		pos = 10
	}
	if f.Masked {
		copy(f.MaskKey[:], raw[pos:pos+4])
		pos += 4
	}
	if len(raw) < pos+n {
		return Frame{}, 0, io.ErrUnexpectedEOF
	}
	f.Payload = append([]byte(nil), raw[pos:pos+n]...)
	if f.Masked {
		for i := range f.Payload {
			f.Payload[i] ^= f.MaskKey[i%4]
		}
	}
	return f, pos, nil
}

func headerContains(v, token string) bool {
	for _, part := range strings.Split(v, ",") {
		if strings.EqualFold(strings.TrimSpace(part), token) {
			return true
		}
	}
	return false
}
