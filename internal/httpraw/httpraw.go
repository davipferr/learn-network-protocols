// Package httpraw is a tiny, hand-written HTTP/1.1 message reader.
//
// It exists to show that HTTP/1.1 is "just text over TCP": a start line,
// header lines, an empty line, then an optional body whose size is given by
// Content-Length. It intentionally supports only what the demos need
// (no chunked encoding, no multi-line headers).
package httpraw

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/davipferr/learn-network-protocols/internal/events"
)

// Message is a parsed HTTP request or response.
type Message struct {
	StartLine string      // "GET /hello HTTP/1.1" or "HTTP/1.1 200 OK"
	Headers   [][2]string // in wire order, original case
	Body      []byte
	Raw       []byte // exactly the bytes read from the connection
}

func (m *Message) Header(name string) string {
	for _, h := range m.Headers {
		if strings.EqualFold(h[0], name) {
			return h[1]
		}
	}
	return ""
}

// MaxHeaderBytes protects the reader from a peer that never sends "\r\n\r\n".
const MaxHeaderBytes = 64 << 10

// ReadMessage reads one HTTP/1.x message from br.
func ReadMessage(br *bufio.Reader) (*Message, error) {
	m := &Message{}
	var raw []byte
	readLine := func() (string, error) {
		line, err := br.ReadString('\n')
		raw = append(raw, line...)
		if err != nil {
			return "", err
		}
		if len(raw) > MaxHeaderBytes {
			return "", errors.New("header section too large")
		}
		return strings.TrimRight(line, "\r\n"), nil
	}

	start, err := readLine()
	if err != nil {
		return nil, err
	}
	m.StartLine = start
	for {
		line, err := readLine()
		if err != nil {
			return nil, err
		}
		if line == "" { // the empty line ends the header section
			break
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("malformed header line %q", line)
		}
		m.Headers = append(m.Headers, [2]string{strings.TrimSpace(name), strings.TrimSpace(value)})
	}

	if cl := m.Header("Content-Length"); cl != "" {
		n, err := strconv.Atoi(cl)
		if err != nil || n < 0 || n > 10<<20 {
			return nil, fmt.Errorf("bad Content-Length %q", cl)
		}
		m.Body = make([]byte, n)
		if _, err := io.ReadFull(br, m.Body); err != nil {
			return nil, err
		}
		raw = append(raw, m.Body...)
	}
	m.Raw = raw
	return m, nil
}

// Fields annotates the raw bytes of an HTTP/1.x message: start-line parts,
// each header, the blank line and the body. Works on requests and responses.
func Fields(raw []byte) []events.Field {
	var fields []events.Field
	s := string(raw)
	headerEnd := strings.Index(s, "\r\n\r\n")
	if headerEnd < 0 {
		return nil
	}

	lineEnd := strings.Index(s, "\r\n")
	startLine := s[:lineEnd]
	// The start line has three space-separated parts.
	names := []string{"method", "request-target", "version"}
	if strings.HasPrefix(startLine, "HTTP/") {
		names = []string{"version", "status code", "reason phrase"}
	}
	off := 0
	for i, part := range strings.SplitN(startLine, " ", 3) {
		if i < len(names) {
			fields = append(fields, events.Field{Name: names[i], Start: off, End: off + len(part), Value: part})
		}
		off += len(part) + 1
	}
	fields = append(fields, events.Field{Name: "CRLF", Start: lineEnd, End: lineEnd + 2, Value: `\r\n ends the line`})

	pos := lineEnd + 2
	for pos < headerEnd {
		end := strings.Index(s[pos:], "\r\n") + pos
		line := s[pos:end]
		name, value, _ := strings.Cut(line, ":")
		fields = append(fields, events.Field{Name: "header " + name, Start: pos, End: end, Value: strings.TrimSpace(value)})
		pos = end + 2
	}
	fields = append(fields, events.Field{Name: "empty line", Start: headerEnd + 2, End: headerEnd + 4, Value: "end of headers"})
	if len(raw) > headerEnd+4 {
		fields = append(fields, events.Field{Name: "body", Start: headerEnd + 4, End: len(raw), Value: fmt.Sprintf("%d bytes", len(raw)-headerEnd-4)})
	}
	return fields
}

// Split cuts a buffer containing several complete HTTP/1.x messages (with
// Content-Length bodies) into individual messages. Leftover bytes that do
// not form a complete message are returned as rest.
func Split(buf []byte) (msgs [][]byte, rest []byte) {
	for {
		s := string(buf)
		he := strings.Index(s, "\r\n\r\n")
		if he < 0 {
			return msgs, buf
		}
		n := he + 4
		for _, line := range strings.Split(s[:he], "\r\n") {
			name, value, ok := strings.Cut(line, ":")
			if ok && strings.EqualFold(strings.TrimSpace(name), "Content-Length") {
				cl, _ := strconv.Atoi(strings.TrimSpace(value))
				n += cl
			}
		}
		if len(buf) < n {
			return msgs, buf
		}
		msgs = append(msgs, buf[:n])
		buf = buf[n:]
	}
}
