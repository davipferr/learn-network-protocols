// Package wire lets demos observe the exact bytes that cross a connection.
//
// A tapped net.Conn behaves exactly like the original one, but every
// successful Read and Write is also handed to a callback. Wrapping the raw
// TCP connection *below* TLS or HTTP/2 is what lets the demos show what is
// really on the wire.
package wire

import (
	"net"
	"sync"
)

// Dir is the direction of the bytes, from the point of view of the tapped side.
type Dir int

const (
	In  Dir = iota // the tapped side read these bytes
	Out            // the tapped side wrote these bytes
)

func (d Dir) String() string {
	if d == In {
		return "in"
	}
	return "out"
}

// Tap receives a copy of the bytes. It must not keep p after returning.
type Tap func(dir Dir, p []byte)

type Conn struct {
	net.Conn
	tap Tap
	mu  sync.Mutex // serializes tap calls when Read and Write run in parallel
}

func NewConn(c net.Conn, tap Tap) *Conn {
	return &Conn{Conn: c, tap: tap}
}

func (c *Conn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.mu.Lock()
		c.tap(In, p[:n])
		c.mu.Unlock()
	}
	return n, err
}

func (c *Conn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.mu.Lock()
		c.tap(Out, p[:n])
		c.mu.Unlock()
	}
	return n, err
}

// Listener taps every accepted connection.
type Listener struct {
	net.Listener
	newTap func(net.Conn) Tap
}

// NewListener wraps ln; newTap is called once per accepted connection.
func NewListener(ln net.Listener, newTap func(net.Conn) Tap) *Listener {
	return &Listener{Listener: ln, newTap: newTap}
}

func (l *Listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return NewConn(c, l.newTap(c)), nil
}
