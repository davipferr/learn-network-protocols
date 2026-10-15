package httpraw

import (
	"bufio"
	"strings"
	"testing"
)

func TestReadMessage(t *testing.T) {
	raw := "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhelloGET / HTTP/1.1\r\n\r\n"
	br := bufio.NewReader(strings.NewReader(raw))
	m, err := ReadMessage(br)
	if err != nil {
		t.Fatal(err)
	}
	if m.StartLine != "POST /echo HTTP/1.1" || m.Header("host") != "x" || string(m.Body) != "hello" {
		t.Fatalf("unexpected message %+v", m)
	}
	next, err := ReadMessage(br)
	if err != nil || next.StartLine != "GET / HTTP/1.1" {
		t.Fatalf("second message: %v %+v", err, next)
	}
}

func TestSplitKeepsIncompleteRest(t *testing.T) {
	buf := []byte("GET /a HTTP/1.1\r\n\r\nPOST /b HTTP/1.1\r\nContent-Length: 4\r\n\r\nab")
	msgs, rest := Split(buf)
	if len(msgs) != 1 || string(rest) != "POST /b HTTP/1.1\r\nContent-Length: 4\r\n\r\nab" {
		t.Fatalf("msgs=%q rest=%q", msgs, rest)
	}
}
