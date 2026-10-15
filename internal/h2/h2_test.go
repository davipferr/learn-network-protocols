package h2

import "testing"

func TestProtobufFields(t *testing.T) {
	// HelloRequest{name: "Go", times: 2}: 0a 02 'G' 'o' 10 02
	f := ProtobufFields([]byte{0x0a, 0x02, 'G', 'o', 0x10, 0x02}, 0, "")
	var values []string
	for _, x := range f {
		values = append(values, x.Name+"="+x.Value)
	}
	want := []string{
		"protobuf field #1 key=0x0a = field 1, wire type 2 (length-delimited)",
		"protobuf field #1 length=2",
		`protobuf field #1 bytes="Go"`,
		"protobuf field #2 key=0x10 = field 2, wire type 0 (varint)",
		"protobuf field #2 value=varint 2",
	}
	if len(values) != len(want) {
		t.Fatalf("got %q", values)
	}
	for i := range want {
		if values[i] != want[i] {
			t.Errorf("field %d = %q, want %q", i, values[i], want[i])
		}
	}
}

func TestParserFramesAcrossChunks(t *testing.T) {
	var got []Frame
	p := NewParser(true)
	p.OnFrame = func(f Frame) { got = append(got, f) }
	settings := []byte{0, 0, 6, 4, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 100} // MAX_CONCURRENT_STREAMS=100
	stream := append([]byte(Preface), settings...)
	for _, b := range stream { // one byte at a time, like a slow network
		p.Feed([]byte{b})
	}
	if len(got) != 1 || got[0].Type != 4 || got[0].Fields[4].Value != "100" {
		t.Fatalf("unexpected frames %+v", got)
	}
}
