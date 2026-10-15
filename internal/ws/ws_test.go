package ws

import (
	"bufio"
	"bytes"
	"net"
	"testing"
)

func TestAcceptKeyRFCExample(t *testing.T) {
	// The example from RFC 6455, section 1.3.
	if got, want := AcceptKey("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="; got != want {
		t.Fatalf("AcceptKey = %q, want %q", got, want)
	}
}

func TestFrameRoundTrip(t *testing.T) {
	for _, size := range []int{0, 5, 125, 126, 300, 70000} {
		payload := bytes.Repeat([]byte{'x'}, size)
		for _, mask := range []bool{false, true} {
			raw := EncodeFrame(true, OpBinary, payload, mask)
			client, server := net.Pipe()
			go func() { client.Write(raw); client.Close() }()
			c := &Conn{nc: server, br: bufio.NewReader(server)}
			f, got, err := c.ReadFrame()
			if err != nil {
				t.Fatalf("size %d mask %v: %v", size, mask, err)
			}
			if !bytes.Equal(got, raw) || !bytes.Equal(f.Payload, payload) || f.Masked != mask || !f.Fin {
				t.Fatalf("size %d mask %v: frame did not round-trip", size, mask)
			}
		}
	}
}
