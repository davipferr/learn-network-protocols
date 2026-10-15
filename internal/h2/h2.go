// Package h2 decodes the HTTP/2 frames that carry gRPC, plus the gRPC
// message framing and the protobuf wire format inside them.
//
// HTTP/2 is binary. After a fixed 24-byte "preface" from the client, both
// sides exchange frames with a 9-byte header:
//
//	+-----------------------------------------------+
//	|                 Length (24)                   |
//	+---------------+---------------+---------------+
//	|   Type (8)    |   Flags (8)   |
//	+-+-------------+---------------+-------------------------------+
//	|R|                 Stream Identifier (31)                      |
//	+=+=============================================================+
//	|                   Frame Payload (0...)                      ...
//	+---------------------------------------------------------------+
//
// Every gRPC call is one HTTP/2 *stream*; many calls share one TCP connection.
package h2

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

	"golang.org/x/net/http2/hpack"

	"github.com/davipferr/learn-network-protocols/internal/events"
)

const Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

var frameTypes = []string{"DATA", "HEADERS", "PRIORITY", "RST_STREAM", "SETTINGS", "PUSH_PROMISE", "PING", "GOAWAY", "WINDOW_UPDATE", "CONTINUATION"}

func FrameTypeName(t byte) string {
	if int(t) < len(frameTypes) {
		return frameTypes[t]
	}
	return fmt.Sprintf("type %d", t)
}

var settingNames = map[uint16]string{1: "HEADER_TABLE_SIZE", 2: "ENABLE_PUSH", 3: "MAX_CONCURRENT_STREAMS", 4: "INITIAL_WINDOW_SIZE", 5: "MAX_FRAME_SIZE", 6: "MAX_HEADER_LIST_SIZE"}

var errorCodes = []string{"NO_ERROR", "PROTOCOL_ERROR", "INTERNAL_ERROR", "FLOW_CONTROL_ERROR", "SETTINGS_TIMEOUT", "STREAM_CLOSED", "FRAME_SIZE_ERROR", "REFUSED_STREAM", "CANCEL"}

func errorName(c uint32) string {
	if int(c) < len(errorCodes) {
		return errorCodes[c]
	}
	return fmt.Sprintf("error %d", c)
}

// Frame is one decoded frame with its exact wire bytes.
type Frame struct {
	Type     byte
	Flags    byte
	StreamID uint32
	Raw      []byte

	Title   string
	Detail  string
	Fields  []events.Field
	Headers []hpack.HeaderField // decoded HEADERS block (if any)
}

// Parser reassembles one direction of an HTTP/2 connection.
type Parser struct {
	expectPreface bool
	buf           []byte
	dec           *hpack.Decoder // HPACK is stateful: one decoder per direction
	pendingHdr    []byte         // HEADERS fragment waiting for CONTINUATION
	OnPreface     func(raw []byte)
	OnFrame       func(Frame)
}

// NewParser creates a parser; clientSide=true for the client->server direction,
// which begins with the connection preface.
func NewParser(clientSide bool) *Parser {
	return &Parser{expectPreface: clientSide, dec: hpack.NewDecoder(4096, nil)}
}

func (p *Parser) Feed(b []byte) {
	p.buf = append(p.buf, b...)
	if p.expectPreface {
		if len(p.buf) < len(Preface) {
			return
		}
		if p.OnPreface != nil {
			p.OnPreface(append([]byte(nil), p.buf[:len(Preface)]...))
		}
		p.buf = p.buf[len(Preface):]
		p.expectPreface = false
	}
	for len(p.buf) >= 9 {
		n := int(p.buf[0])<<16 | int(p.buf[1])<<8 | int(p.buf[2])
		if len(p.buf) < 9+n {
			return
		}
		f := Frame{Type: p.buf[3], Flags: p.buf[4], StreamID: binary.BigEndian.Uint32(p.buf[5:9]) & 0x7FFFFFFF}
		f.Raw = append([]byte(nil), p.buf[:9+n]...)
		p.buf = p.buf[9+n:]
		p.describe(&f)
		if p.OnFrame != nil {
			p.OnFrame(f)
		}
	}
}

func (p *Parser) describe(f *Frame) {
	n := len(f.Raw) - 9
	f.Fields = []events.Field{
		{Name: "frame: length", Start: 0, End: 3, Value: fmt.Sprint(n)},
		{Name: "frame: type", Start: 3, End: 4, Value: FrameTypeName(f.Type)},
		{Name: "frame: flags", Start: 4, End: 5, Value: flagNames(f.Type, f.Flags)},
		{Name: "frame: stream id", Start: 5, End: 9, Value: streamNote(f.StreamID)},
	}
	pl := f.Raw[9:]
	f.Title = FrameTypeName(f.Type)
	if f.StreamID != 0 {
		f.Title += fmt.Sprintf(" stream %d", f.StreamID)
	}
	if fl := flagNames(f.Type, f.Flags); fl != "none" {
		f.Title += " [" + fl + "]"
	}

	switch f.Type {
	case 0: // DATA
		mf := GRPCMessageFields(pl, 9)
		f.Fields = append(f.Fields, mf...)
		var decoded []string
		for _, fl := range mf {
			if strings.HasSuffix(fl.Name, " bytes") || strings.HasSuffix(fl.Name, " value") {
				decoded = append(decoded, strings.TrimPrefix(strings.TrimSuffix(strings.TrimSuffix(fl.Name, " bytes"), " value"), "protobuf ")+" = "+fl.Value)
			}
		}
		f.Detail = "DATA carries the gRPC message: a 5-byte prefix (compressed flag + length) followed by the protobuf-encoded bytes."
		if len(decoded) > 0 {
			f.Detail += "\nDecoded without the schema: " + strings.Join(decoded, ", ")
		}
	case 1, 9: // HEADERS, CONTINUATION
		block := pl
		if f.Type == 1 && f.Flags&0x8 != 0 && len(pl) > 0 { // PADDED
			block = pl[1 : len(pl)-int(pl[0])]
		}
		if f.Type == 1 && f.Flags&0x20 != 0 && len(block) >= 5 { // PRIORITY
			block = block[5:]
		}
		p.pendingHdr = append(p.pendingHdr, block...)
		f.Fields = append(f.Fields, events.Field{Name: "HPACK-compressed header block", Start: 9, End: len(f.Raw), Value: fmt.Sprintf("%d bytes", len(block))})
		if f.Flags&0x4 != 0 { // END_HEADERS
			hf, err := p.dec.DecodeFull(p.pendingHdr)
			raw := len(p.pendingHdr)
			p.pendingHdr = nil
			if err != nil {
				f.Detail = "could not decode HPACK block: " + err.Error()
				return
			}
			f.Headers = hf
			plain := 0
			var lines []string
			for _, h := range hf {
				plain += len(h.Name) + len(h.Value) + 4
				lines = append(lines, h.Name+": "+h.Value)
			}
			f.Detail = fmt.Sprintf("Decoded headers (%d bytes as text, %d bytes after HPACK compression):\n%s", plain, raw, strings.Join(lines, "\n"))
			if hasHeader(hf, "grpc-status") {
				f.Title += " (trailers)"
			}
		}
	case 4: // SETTINGS
		var parts []string
		for i := 0; i+6 <= len(pl); i += 6 {
			id := binary.BigEndian.Uint16(pl[i:])
			v := binary.BigEndian.Uint32(pl[i+2:])
			name := settingNames[id]
			if name == "" {
				name = fmt.Sprintf("setting 0x%x", id)
			}
			f.Fields = append(f.Fields, events.Field{Name: name, Start: 9 + i, End: 9 + i + 6, Value: fmt.Sprint(v)})
			parts = append(parts, fmt.Sprintf("%s=%d", name, v))
		}
		if f.Flags&1 != 0 {
			f.Detail = "ACK: \"I received and applied your settings.\""
		} else if len(parts) == 0 {
			f.Detail = "Each side announces its limits for this connection. This one is empty: \"I'm fine with the defaults\"."
		} else {
			f.Detail = "Each side announces its limits for this connection: " + strings.Join(parts, ", ")
		}
	case 6: // PING
		f.Fields = append(f.Fields, events.Field{Name: "opaque data", Start: 9, End: len(f.Raw), Value: fmt.Sprintf("% x", pl)})
		f.Detail = "PING measures round-trip time and keeps the connection alive. gRPC uses it to estimate bandwidth (BDP) and size its flow-control windows."
		if f.Flags&1 != 0 {
			f.Detail = "The answer to a PING, echoing the same 8 bytes."
		}
	case 8: // WINDOW_UPDATE
		if len(pl) >= 4 {
			inc := binary.BigEndian.Uint32(pl) & 0x7FFFFFFF
			f.Fields = append(f.Fields, events.Field{Name: "window size increment", Start: 9, End: 13, Value: fmt.Sprint(inc)})
			f.Detail = fmt.Sprintf("Flow control: \"you may send me %d more bytes\" on %s.", inc, streamNote(f.StreamID))
		}
	case 3: // RST_STREAM
		if len(pl) >= 4 {
			f.Fields = append(f.Fields, events.Field{Name: "error code", Start: 9, End: 13, Value: errorName(binary.BigEndian.Uint32(pl))})
		}
		f.Detail = "Cancels a single stream (one call) without touching the others."
	case 7: // GOAWAY
		if len(pl) >= 8 {
			f.Fields = append(f.Fields,
				events.Field{Name: "last stream id", Start: 9, End: 13, Value: fmt.Sprint(binary.BigEndian.Uint32(pl) & 0x7FFFFFFF)},
				events.Field{Name: "error code", Start: 13, End: 17, Value: errorName(binary.BigEndian.Uint32(pl[4:]))})
		}
		f.Detail = "The sender is shutting the connection down gracefully."
	}
}

func hasHeader(hf []hpack.HeaderField, name string) bool {
	for _, h := range hf {
		if h.Name == name {
			return true
		}
	}
	return false
}

func streamNote(id uint32) string {
	if id == 0 {
		return "0 (the connection itself)"
	}
	return fmt.Sprintf("stream %d", id)
}

func flagNames(t, fl byte) string {
	var s []string
	switch t {
	case 0:
		if fl&1 != 0 {
			s = append(s, "END_STREAM")
		}
		if fl&8 != 0 {
			s = append(s, "PADDED")
		}
	case 1:
		if fl&1 != 0 {
			s = append(s, "END_STREAM")
		}
		if fl&4 != 0 {
			s = append(s, "END_HEADERS")
		}
		if fl&8 != 0 {
			s = append(s, "PADDED")
		}
		if fl&0x20 != 0 {
			s = append(s, "PRIORITY")
		}
	case 4, 6:
		if fl&1 != 0 {
			s = append(s, "ACK")
		}
	case 9:
		if fl&4 != 0 {
			s = append(s, "END_HEADERS")
		}
	}
	if len(s) == 0 {
		return "none"
	}
	return strings.Join(s, "|")
}

// GRPCMessageFields annotates the gRPC length-prefixed messages inside a DATA
// payload. base is the offset of the payload inside the frame's raw bytes.
func GRPCMessageFields(pl []byte, base int) []events.Field {
	var f []events.Field
	for pos := 0; pos+5 <= len(pl); {
		ml := int(binary.BigEndian.Uint32(pl[pos+1:]))
		f = append(f,
			events.Field{Name: "gRPC: compressed flag", Start: base + pos, End: base + pos + 1, Value: fmt.Sprint(pl[pos])},
			events.Field{Name: "gRPC: message length", Start: base + pos + 1, End: base + pos + 5, Value: fmt.Sprint(ml)})
		end := min(pos+5+ml, len(pl))
		f = append(f, ProtobufFields(pl[pos+5:end], base+pos+5, "")...)
		pos = end
	}
	return f
}

// ProtobufFields decodes protobuf wire format without knowing the schema.
// Each field is a key varint (field_number << 3 | wire_type) then a value.
// The schema (.proto) is what gives these numbers a name.
func ProtobufFields(b []byte, base int, prefix string) []events.Field {
	var out []events.Field
	for pos := 0; pos < len(b); {
		start := pos
		key, n := binary.Uvarint(b[pos:])
		if n <= 0 {
			break
		}
		pos += n
		num, wt := key>>3, key&7
		label := fmt.Sprintf("%sprotobuf field #%d", prefix, num)
		out = append(out, events.Field{Name: label + " key", Start: base + start, End: base + pos, Value: fmt.Sprintf("0x%02x = field %d, wire type %d (%s)", key, num, wt, wireTypeName(wt))})
		switch wt {
		case 0:
			v, n := binary.Uvarint(b[pos:])
			if n <= 0 {
				return out
			}
			out = append(out, events.Field{Name: label + " value", Start: base + pos, End: base + pos + n, Value: fmt.Sprintf("varint %d", v)})
			pos += n
		case 2:
			l, n := binary.Uvarint(b[pos:])
			if n <= 0 || pos+n+int(l) > len(b) {
				return out
			}
			out = append(out, events.Field{Name: label + " length", Start: base + pos, End: base + pos + n, Value: fmt.Sprint(l)})
			pos += n
			v := b[pos : pos+int(l)]
			out = append(out, events.Field{Name: label + " bytes", Start: base + pos, End: base + pos + int(l), Value: printable(v)})
			pos += int(l)
		case 1:
			if pos+8 > len(b) {
				return out
			}
			out = append(out, events.Field{Name: label + " value", Start: base + pos, End: base + pos + 8, Value: "fixed64"})
			pos += 8
		case 5:
			if pos+4 > len(b) {
				return out
			}
			out = append(out, events.Field{Name: label + " value", Start: base + pos, End: base + pos + 4, Value: "fixed32"})
			pos += 4
		default:
			return out
		}
	}
	return out
}

func wireTypeName(wt uint64) string {
	switch wt {
	case 0:
		return "varint"
	case 1:
		return "64-bit"
	case 2:
		return "length-delimited"
	case 5:
		return "32-bit"
	}
	return "?"
}

func printable(b []byte) string {
	if bytes.ContainsFunc(b, func(r rune) bool { return r < 32 || r == 0xFFFD }) {
		return fmt.Sprintf("% x", b)
	}
	return fmt.Sprintf("%q", b)
}
