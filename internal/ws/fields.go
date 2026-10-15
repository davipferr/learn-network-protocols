package ws

import (
	"encoding/binary"
	"fmt"

	"github.com/davipferr/learn-network-protocols/internal/events"
)

// FrameFields annotates the wire bytes of one frame for the byte viewer.
func FrameFields(raw []byte) []events.Field {
	f, pos, err := decode(raw)
	if err != nil {
		return nil
	}
	b0, b1 := raw[0], raw[1]
	fields := []events.Field{
		{Name: "FIN bit", Start: 0, End: 1, Value: fmt.Sprintf("%v (last fragment of the message)", f.Fin)},
		{Name: "opcode (low 4 bits)", Start: 0, End: 1, Value: fmt.Sprintf("0x%x = %s", b0&0x0F, OpName(f.Opcode))},
		{Name: "MASK bit", Start: 1, End: 2, Value: fmt.Sprintf("%v", f.Masked)},
	}
	plen := b1 & 0x7F
	switch plen {
	case 126:
		fields = append(fields,
			events.Field{Name: "payload len (7 bits)", Start: 1, End: 2, Value: "126 = \"read the next 2 bytes\""},
			events.Field{Name: "extended length (16 bit)", Start: 2, End: 4, Value: fmt.Sprint(binary.BigEndian.Uint16(raw[2:4]))})
	case 127:
		fields = append(fields,
			events.Field{Name: "payload len (7 bits)", Start: 1, End: 2, Value: "127 = \"read the next 8 bytes\""},
			events.Field{Name: "extended length (64 bit)", Start: 2, End: 10, Value: fmt.Sprint(binary.BigEndian.Uint64(raw[2:10]))})
	default:
		fields = append(fields, events.Field{Name: "payload len (7 bits)", Start: 1, End: 2, Value: fmt.Sprint(plen)})
	}
	if f.Masked {
		fields = append(fields, events.Field{Name: "masking key", Start: pos - 4, End: pos, Value: fmt.Sprintf("% x", f.MaskKey)})
	}
	if len(f.Payload) > 0 {
		val := fmt.Sprintf("%d bytes", len(f.Payload))
		switch f.Opcode {
		case OpText, OpPing, OpPong:
			val = preview(f.Payload)
		case OpClose:
			if len(f.Payload) >= 2 {
				val = fmt.Sprintf("code %d %s", binary.BigEndian.Uint16(f.Payload), preview(f.Payload[2:]))
			}
		}
		name := "payload"
		if f.Masked {
			name = "payload (masked; unmasked shown)"
		}
		fields = append(fields, events.Field{Name: name, Start: pos, End: len(raw), Value: val})
	}
	return fields
}

func preview(b []byte) string {
	const max = 60
	if len(b) > max {
		return fmt.Sprintf("%q…", b[:max])
	}
	return fmt.Sprintf("%q", b)
}
