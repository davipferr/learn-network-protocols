// Package dnsmsg builds and parses DNS messages by hand (RFC 1035).
//
// Every DNS message, query or answer, has the same layout:
//
//	+---------------------+
//	|        Header       | 12 bytes: ID, flags, 4 counters
//	+---------------------+
//	|       Question      | the name/type being asked
//	+---------------------+
//	|        Answer       | resource records answering the question
//	+---------------------+
//	|      Authority      | records pointing to authoritative servers
//	+---------------------+
//	|      Additional     | extra records (often EDNS0's OPT)
//	+---------------------+
package dnsmsg

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/davipferr/learn-network-protocols/internal/events"
)

var Types = map[string]uint16{
	"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28, "OPT": 41,
}

func TypeName(t uint16) string {
	for k, v := range Types {
		if v == t {
			return k
		}
	}
	return fmt.Sprintf("TYPE%d", t)
}

var rcodes = []string{"NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED"}

func RcodeName(c int) string {
	if c < len(rcodes) {
		return rcodes[c]
	}
	return fmt.Sprintf("RCODE%d", c)
}

// BuildQuery returns the bytes of a recursive query for name/qtype plus
// annotations for every field.
func BuildQuery(id uint16, name string, qtype uint16) ([]byte, []events.Field, error) {
	b := binary.BigEndian.AppendUint16(nil, id)
	b = binary.BigEndian.AppendUint16(b, 0x0100) // flags: standard query, RD=1 (please recurse)
	b = binary.BigEndian.AppendUint16(b, 1)      // QDCOUNT
	b = binary.BigEndian.AppendUint16(b, 0)      // ANCOUNT
	b = binary.BigEndian.AppendUint16(b, 0)      // NSCOUNT
	b = binary.BigEndian.AppendUint16(b, 0)      // ARCOUNT
	fields := []events.Field{
		{Name: "ID", Start: 0, End: 2, Value: fmt.Sprintf("0x%04x (random, matches answer to question)", id)},
		{Name: "flags", Start: 2, End: 4, Value: "0x0100: QR=0 query, OPCODE=0 standard, RD=1 recursion desired"},
		{Name: "QDCOUNT", Start: 4, End: 6, Value: "1 question"},
		{Name: "ANCOUNT", Start: 6, End: 8, Value: "0"},
		{Name: "NSCOUNT", Start: 8, End: 10, Value: "0"},
		{Name: "ARCOUNT", Start: 10, End: 12, Value: "0"},
	}

	name = strings.TrimSuffix(name, ".")
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return nil, nil, fmt.Errorf("invalid label %q in name", label)
		}
		start := len(b)
		b = append(b, byte(len(label)))
		b = append(b, label...)
		fields = append(fields, events.Field{Name: "QNAME label", Start: start, End: len(b), Value: fmt.Sprintf("length %d + %q", len(label), label)})
	}
	b = append(b, 0)
	fields = append(fields, events.Field{Name: "QNAME end", Start: len(b) - 1, End: len(b), Value: "0 = root label, name ends"})
	start := len(b)
	b = binary.BigEndian.AppendUint16(b, qtype)
	fields = append(fields, events.Field{Name: "QTYPE", Start: start, End: start + 2, Value: TypeName(qtype)})
	b = binary.BigEndian.AppendUint16(b, 1)
	fields = append(fields, events.Field{Name: "QCLASS", Start: start + 2, End: start + 4, Value: "IN (Internet)"})
	return b, fields, nil
}

// Record is one parsed resource record.
type Record struct {
	Section string // answer, authority, additional
	Name    string
	Type    uint16
	TTL     uint32
	Data    string // human readable RDATA
}

type Message struct {
	ID        uint16
	Flags     uint16
	Rcode     int
	Truncated bool
	Questions []string
	Records   []Record
}

// Parse decodes a full DNS message and annotates every field it reads.
func Parse(b []byte) (*Message, []events.Field, error) {
	if len(b) < 12 {
		return nil, nil, errors.New("message shorter than the 12-byte header")
	}
	p := &parser{b: b}
	m := &Message{ID: binary.BigEndian.Uint16(b[0:2]), Flags: binary.BigEndian.Uint16(b[2:4])}
	m.Rcode = int(m.Flags & 0x000F)
	m.Truncated = m.Flags&0x0200 != 0
	qd, an, ns, ar := p.u16at(4), p.u16at(6), p.u16at(8), p.u16at(10)
	p.add("ID", 0, 2, fmt.Sprintf("0x%04x", m.ID))
	p.add("flags", 2, 4, describeFlags(m.Flags))
	p.add("QDCOUNT", 4, 6, fmt.Sprint(qd))
	p.add("ANCOUNT", 6, 8, fmt.Sprint(an))
	p.add("NSCOUNT", 8, 10, fmt.Sprint(ns))
	p.add("ARCOUNT", 10, 12, fmt.Sprint(ar))
	p.pos = 12

	for range qd {
		start := p.pos
		name, err := p.name()
		if err != nil {
			return nil, p.fields, err
		}
		p.add("question name", start, p.pos, name)
		if p.pos+4 > len(b) {
			return nil, p.fields, errors.New("truncated question")
		}
		qt := p.u16at(p.pos)
		p.add("question type/class", p.pos, p.pos+4, TypeName(qt)+" IN")
		p.pos += 4
		m.Questions = append(m.Questions, name+" "+TypeName(qt))
	}

	sections := []struct {
		name  string
		count uint16
	}{{"answer", an}, {"authority", ns}, {"additional", ar}}
	for _, s := range sections {
		for range s.count {
			r, err := p.record(s.name)
			if err != nil {
				return m, p.fields, err
			}
			m.Records = append(m.Records, r)
		}
	}
	return m, p.fields, nil
}

func describeFlags(f uint16) string {
	var parts []string
	if f&0x8000 != 0 {
		parts = append(parts, "QR=1 response")
	} else {
		parts = append(parts, "QR=0 query")
	}
	if f&0x0400 != 0 {
		parts = append(parts, "AA authoritative")
	}
	if f&0x0200 != 0 {
		parts = append(parts, "TC truncated!")
	}
	if f&0x0100 != 0 {
		parts = append(parts, "RD")
	}
	if f&0x0080 != 0 {
		parts = append(parts, "RA recursion available")
	}
	parts = append(parts, "RCODE="+RcodeName(int(f&0xF)))
	return fmt.Sprintf("0x%04x: %s", f, strings.Join(parts, ", "))
}

type parser struct {
	b      []byte
	pos    int
	fields []events.Field
}

func (p *parser) add(name string, start, end int, value string) {
	p.fields = append(p.fields, events.Field{Name: name, Start: start, End: end, Value: value})
}

func (p *parser) u16at(i int) uint16 { return binary.BigEndian.Uint16(p.b[i : i+2]) }

// name reads a (possibly compressed) domain name at p.pos and advances p.pos.
func (p *parser) name() (string, error) {
	n, next, err := readName(p.b, p.pos)
	if err != nil {
		return "", err
	}
	p.pos = next
	return n, nil
}

// readName decodes a name starting at off. Names are a sequence of
// length-prefixed labels ending in 0, OR a 2-byte pointer (top bits 11)
// to a name that appeared earlier in the message: "message compression".
func readName(b []byte, off int) (name string, next int, err error) {
	var labels []string
	jumped := false
	next = -1
	for hops := 0; hops < 64; hops++ {
		if off >= len(b) {
			return "", 0, errors.New("name runs past end of message")
		}
		l := int(b[off])
		switch {
		case l == 0:
			if !jumped {
				next = off + 1
			}
			if len(labels) == 0 {
				return ".", next, nil
			}
			return strings.Join(labels, "."), next, nil
		case l&0xC0 == 0xC0:
			if off+1 >= len(b) {
				return "", 0, errors.New("truncated compression pointer")
			}
			if !jumped {
				next = off + 2
			}
			jumped = true
			off = int(binary.BigEndian.Uint16(b[off:off+2]) & 0x3FFF)
		default:
			if off+1+l > len(b) {
				return "", 0, errors.New("label runs past end of message")
			}
			labels = append(labels, string(b[off+1:off+1+l]))
			off += 1 + l
		}
	}
	return "", 0, errors.New("too many compression pointers (loop?)")
}

func (p *parser) record(section string) (Record, error) {
	start := p.pos
	compressed := p.pos < len(p.b) && p.b[p.pos]&0xC0 == 0xC0
	name, err := p.name()
	if err != nil {
		return Record{}, err
	}
	label := section + " name"
	val := name
	if compressed {
		ptr := int(p.u16at(start) & 0x3FFF)
		val = fmt.Sprintf("%s (compressed: pointer to offset %d)", name, ptr)
	}
	p.add(label, start, p.pos, val)

	if p.pos+10 > len(p.b) {
		return Record{}, errors.New("truncated record header")
	}
	r := Record{Section: section, Name: name}
	r.Type = p.u16at(p.pos)
	class := p.u16at(p.pos + 2)
	r.TTL = binary.BigEndian.Uint32(p.b[p.pos+4 : p.pos+8])
	rdlen := int(p.u16at(p.pos + 8))
	if r.Type == Types["OPT"] {
		p.add("OPT pseudo-record (EDNS0)", p.pos, p.pos+10, fmt.Sprintf("UDP payload size %d", class))
	} else {
		p.add("type", p.pos, p.pos+2, TypeName(r.Type))
		p.add("class", p.pos+2, p.pos+4, "IN")
		p.add("TTL", p.pos+4, p.pos+8, fmt.Sprintf("%d seconds (cache lifetime)", r.TTL))
		p.add("RDLENGTH", p.pos+8, p.pos+10, fmt.Sprint(rdlen))
	}
	p.pos += 10
	if p.pos+rdlen > len(p.b) {
		return Record{}, errors.New("truncated RDATA")
	}
	rd := p.b[p.pos : p.pos+rdlen]
	r.Data = p.rdata(r.Type, p.pos, rd)
	if r.Type != Types["OPT"] {
		p.add("RDATA "+TypeName(r.Type), p.pos, p.pos+rdlen, r.Data)
	}
	p.pos += rdlen
	return r, nil
}

func (p *parser) rdata(t uint16, off int, rd []byte) string {
	switch TypeName(t) {
	case "A":
		if a, ok := netip.AddrFromSlice(rd); ok && len(rd) == 4 {
			return a.String()
		}
	case "AAAA":
		if a, ok := netip.AddrFromSlice(rd); ok && len(rd) == 16 {
			return a.String()
		}
	case "CNAME", "NS", "PTR":
		if n, _, err := readName(p.b, off); err == nil {
			return n
		}
	case "MX":
		if len(rd) > 2 {
			if n, _, err := readName(p.b, off+2); err == nil {
				return fmt.Sprintf("preference %d, exchange %s", binary.BigEndian.Uint16(rd), n)
			}
		}
	case "TXT":
		var parts []string
		for i := 0; i < len(rd); {
			l := int(rd[i])
			if i+1+l > len(rd) {
				break
			}
			parts = append(parts, fmt.Sprintf("%q", rd[i+1:i+1+l]))
			i += 1 + l
		}
		return strings.Join(parts, " ")
	case "SOA":
		mname, n1, err1 := readName(p.b, off)
		if err1 == nil {
			rname, n2, err2 := readName(p.b, n1)
			if err2 == nil && n2+20 <= off+len(rd) {
				serial := binary.BigEndian.Uint32(p.b[n2 : n2+4])
				return fmt.Sprintf("primary %s, admin %s, serial %d", mname, rname, serial)
			}
		}
	case "OPT":
		return "EDNS0 options"
	}
	return fmt.Sprintf("% x", rd)
}
