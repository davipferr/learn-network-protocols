package dnsmsg

import (
	"encoding/binary"
	"testing"
)

func TestQueryLayout(t *testing.T) {
	q, _, err := BuildQuery(0xBEEF, "go.dev", Types["A"])
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0xBE, 0xEF, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 2, 'g', 'o', 3, 'd', 'e', 'v', 0, 0, 1, 0, 1}
	if string(q) != string(want) {
		t.Fatalf("query = % x\nwant    % x", q, want)
	}
}

func TestParseCompressedAnswer(t *testing.T) {
	q, _, _ := BuildQuery(1, "go.dev", Types["A"])
	resp := append([]byte(nil), q...)
	binary.BigEndian.PutUint16(resp[2:], 0x8180) // response, RD, RA
	binary.BigEndian.PutUint16(resp[6:], 1)      // one answer
	// Answer: pointer to the name at offset 12, type A, class IN, TTL 60, 4 bytes.
	resp = append(resp, 0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 216, 239, 32, 21)

	m, _, err := Parse(resp)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Records) != 1 {
		t.Fatalf("got %d records", len(m.Records))
	}
	r := m.Records[0]
	if r.Name != "go.dev" || r.Data != "216.239.32.21" || r.TTL != 60 {
		t.Fatalf("unexpected record %+v", r)
	}
}

func TestPointerLoopIsRejected(t *testing.T) {
	msg := make([]byte, 12)
	msg = append(msg, 0xC0, 12) // a name that points to itself
	if _, _, err := readName(msg, 12); err == nil {
		t.Fatal("expected an error for a compression loop")
	}
}
