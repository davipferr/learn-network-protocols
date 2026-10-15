// Package tlsrec splits a raw TLS byte stream into records and describes
// the parts that are still readable (plaintext) on the wire.
//
// Every TLS record starts with a 5-byte header:
//
//	content type (1) | legacy version (2) | length (2) | fragment...
//
// Content types: 20 ChangeCipherSpec, 21 Alert, 22 Handshake, 23 ApplicationData.
package tlsrec

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/davipferr/learn-network-protocols/internal/events"
)

const (
	TypeChangeCipherSpec = 20
	TypeAlert            = 21
	TypeHandshake        = 22
	TypeApplicationData  = 23
)

// Record is one TLS record exactly as it appeared on the wire.
type Record struct {
	Type      byte
	Version   uint16
	Raw       []byte // header + fragment
	Encrypted bool   // the fragment is protected; we can only see its size
}

// Parser reassembles records from arbitrarily chunked bytes of ONE direction.
type Parser struct {
	buf       []byte
	encrypted bool // set after this side sent ChangeCipherSpec
	OnRecord  func(Record)
}

func (p *Parser) Feed(b []byte) {
	p.buf = append(p.buf, b...)
	for len(p.buf) >= 5 {
		n := int(binary.BigEndian.Uint16(p.buf[3:5]))
		if len(p.buf) < 5+n {
			return
		}
		r := Record{Type: p.buf[0], Version: binary.BigEndian.Uint16(p.buf[1:3]), Raw: append([]byte(nil), p.buf[:5+n]...)}
		r.Encrypted = r.Type == TypeApplicationData || (p.encrypted && r.Type != TypeChangeCipherSpec)
		if r.Type == TypeChangeCipherSpec {
			p.encrypted = true
		}
		p.buf = p.buf[5+n:]
		if p.OnRecord != nil {
			p.OnRecord(r)
		}
	}
}

var contentTypes = map[byte]string{20: "ChangeCipherSpec", 21: "Alert", 22: "Handshake", 23: "ApplicationData"}

var handshakeTypes = map[byte]string{
	1: "ClientHello", 2: "ServerHello", 4: "NewSessionTicket", 8: "EncryptedExtensions",
	11: "Certificate", 12: "ServerKeyExchange", 13: "CertificateRequest", 14: "ServerHelloDone",
	15: "CertificateVerify", 16: "ClientKeyExchange", 20: "Finished",
}

var extensionNames = map[uint16]string{
	0: "server_name (SNI)", 5: "status_request", 10: "supported_groups", 11: "ec_point_formats",
	13: "signature_algorithms", 16: "ALPN", 18: "signed_certificate_timestamp", 23: "extended_master_secret",
	35: "session_ticket", 41: "pre_shared_key", 43: "supported_versions", 45: "psk_key_exchange_modes",
	50: "signature_algorithms_cert", 51: "key_share", 27: "compress_certificate",
	65037: "encrypted_client_hello", 65281: "renegotiation_info",
}

func versionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	}
	return fmt.Sprintf("0x%04x", v)
}

var alertNames = map[byte]string{0: "close_notify", 10: "unexpected_message", 40: "handshake_failure", 42: "bad_certificate", 46: "certificate_unknown", 48: "unknown_ca", 70: "protocol_version", 80: "internal_error"}

// Describe returns a title, annotated fields and an explanation for a record.
func Describe(r Record) (title string, fields []events.Field, detail string) {
	ct := contentTypes[r.Type]
	if ct == "" {
		ct = fmt.Sprintf("type %d", r.Type)
	}
	n := len(r.Raw) - 5
	fields = []events.Field{
		{Name: "record: content type", Start: 0, End: 1, Value: fmt.Sprintf("%d = %s", r.Type, ct)},
		{Name: "record: legacy version", Start: 1, End: 3, Value: versionName(r.Version) + " (frozen for compatibility)"},
		{Name: "record: length", Start: 3, End: 5, Value: fmt.Sprintf("%d bytes follow", n)},
	}
	frag := r.Raw[5:]

	if r.Encrypted {
		fields = append(fields, events.Field{Name: "encrypted payload (AEAD ciphertext + tag)", Start: 5, End: len(r.Raw), Value: fmt.Sprintf("%d bytes of noise to an observer", n)})
		if r.Type == TypeHandshake {
			return "Handshake (encrypted)", fields, "Sent after ChangeCipherSpec, so it is already protected by the new keys. In TLS 1.2 this is the Finished message."
		}
		return "ApplicationData (encrypted)", fields, "An eavesdropper only sees the record header and the length. In TLS 1.3 even the remaining handshake messages (certificate, Finished...) and alerts travel inside records like this one, disguised as application data."
	}

	switch r.Type {
	case TypeChangeCipherSpec:
		fields = append(fields, events.Field{Name: "ChangeCipherSpec", Start: 5, End: len(r.Raw), Value: "1"})
		return "ChangeCipherSpec", fields, "\"Everything I send after this is encrypted.\" In TLS 1.3 it is a dummy message kept only so old middleboxes don't panic."
	case TypeAlert:
		if len(frag) >= 2 {
			name := alertNames[frag[1]]
			fields = append(fields, events.Field{Name: "alert level", Start: 5, End: 6, Value: map[byte]string{1: "warning", 2: "fatal"}[frag[0]]},
				events.Field{Name: "alert description", Start: 6, End: 7, Value: fmt.Sprintf("%d = %s", frag[1], name)})
			return "Alert: " + name, fields, ""
		}
	case TypeHandshake:
		var titles []string
		var notes []string
		for off := 0; off+4 <= len(frag); {
			ht := frag[off]
			hl := int(frag[off+1])<<16 | int(frag[off+2])<<8 | int(frag[off+3])
			name := handshakeTypes[ht]
			if name == "" {
				name = fmt.Sprintf("handshake type %d", ht)
			}
			titles = append(titles, name)
			base := 5 + off
			fields = append(fields,
				events.Field{Name: "handshake: type", Start: base, End: base + 1, Value: fmt.Sprintf("%d = %s", ht, name)},
				events.Field{Name: "handshake: length", Start: base + 1, End: base + 4, Value: fmt.Sprint(hl)})
			end := min(off+4+hl, len(frag))
			body := frag[off+4 : end]
			f, note := describeHandshake(ht, body, base+4)
			fields = append(fields, f...)
			if note != "" {
				notes = append(notes, note)
			}
			off = off + 4 + hl
		}
		return "Handshake: " + strings.Join(titles, " + "), fields, strings.Join(notes, "\n")
	}
	return ct, fields, ""
}

func describeHandshake(ht byte, b []byte, base int) ([]events.Field, string) {
	switch ht {
	case 1, 2:
		return describeHello(ht == 1, b, base)
	case 11:
		return describeCertificate(b, base)
	case 12:
		if len(b) >= 4 && b[0] == 3 {
			curve := tls.CurveID(binary.BigEndian.Uint16(b[1:3]))
			kl := int(b[3])
			return []events.Field{
				{Name: "curve type", Start: base, End: base + 1, Value: "named_curve"},
				{Name: "named curve", Start: base + 1, End: base + 3, Value: curve.String()},
				{Name: "server ephemeral public key", Start: base + 4, End: base + 4 + kl, Value: fmt.Sprintf("%d bytes", kl)},
				{Name: "signature (proves the server owns the certificate key)", Start: base + 4 + kl, End: base + len(b)},
			}, "The server's half of the Diffie-Hellman key exchange, signed with its certificate's private key."
		}
	case 14:
		return nil, "ServerHelloDone: \"your turn\"."
	case 16:
		return []events.Field{{Name: "client ephemeral public key", Start: base, End: base + len(b), Value: fmt.Sprintf("%d bytes", len(b))}},
			"The client's half of the key exchange. Both sides can now compute the same secret without ever sending it."
	}
	return nil, ""
}

func describeHello(client bool, b []byte, base int) ([]events.Field, string) {
	var f []events.Field
	if len(b) < 38 {
		return nil, ""
	}
	f = append(f, events.Field{Name: "legacy_version", Start: base, End: base + 2, Value: versionName(binary.BigEndian.Uint16(b))})
	f = append(f, events.Field{Name: "random (32 bytes)", Start: base + 2, End: base + 34, Value: "fresh randomness mixed into the keys"})
	pos := 34
	sl := int(b[pos])
	f = append(f, events.Field{Name: "session id", Start: base + pos, End: base + pos + 1 + sl, Value: fmt.Sprintf("%d bytes", sl)})
	pos += 1 + sl
	var note string
	if client {
		if pos+2 > len(b) {
			return f, ""
		}
		cl := int(binary.BigEndian.Uint16(b[pos:]))
		var names []string
		for i := pos + 2; i+1 < pos+2+cl && i+1 < len(b); i += 2 {
			names = append(names, tls.CipherSuiteName(binary.BigEndian.Uint16(b[i:])))
		}
		f = append(f, events.Field{Name: fmt.Sprintf("cipher suites (%d offered)", len(names)), Start: base + pos, End: base + pos + 2 + cl, Value: strings.Join(names, ", ")})
		pos += 2 + cl
		if pos >= len(b) {
			return f, ""
		}
		ml := int(b[pos])
		f = append(f, events.Field{Name: "compression methods", Start: base + pos, End: base + pos + 1 + ml, Value: "null (compression is disabled since CRIME)"})
		pos += 1 + ml
		note = "The client proposes: which TLS versions, cipher suites and key-exchange groups it supports, plus its key_share (the public half of a Diffie-Hellman exchange) so the handshake can finish in one round trip."
	} else {
		if pos+3 > len(b) {
			return f, ""
		}
		cs := binary.BigEndian.Uint16(b[pos:])
		f = append(f, events.Field{Name: "chosen cipher suite", Start: base + pos, End: base + pos + 2, Value: tls.CipherSuiteName(cs)})
		f = append(f, events.Field{Name: "compression", Start: base + pos + 2, End: base + pos + 3, Value: "null"})
		pos += 3
		note = "The server picks one option from each list and sends its own key_share. From this point on both sides can derive the session keys."
	}
	if pos+2 > len(b) {
		return f, note
	}
	pos += 2 // extensions total length
	for pos+4 <= len(b) {
		et := binary.BigEndian.Uint16(b[pos:])
		el := int(binary.BigEndian.Uint16(b[pos+2:]))
		end := min(pos+4+el, len(b))
		name := extensionNames[et]
		if name == "" {
			name = fmt.Sprintf("extension %d", et)
		}
		f = append(f, events.Field{Name: "ext " + name, Start: base + pos, End: base + end, Value: extensionValue(et, b[pos+4:end], client)})
		pos = end
	}
	return f, note
}

func extensionValue(et uint16, d []byte, client bool) string {
	switch et {
	case 0: // server_name: list len(2) type(1) len(2) name
		if len(d) > 5 {
			return string(d[5:])
		}
	case 43: // supported_versions
		if client && len(d) > 1 {
			var v []string
			for i := 1; i+1 < len(d); i += 2 {
				v = append(v, versionName(binary.BigEndian.Uint16(d[i:])))
			}
			return strings.Join(v, ", ")
		}
		if !client && len(d) == 2 {
			return "selected " + versionName(binary.BigEndian.Uint16(d))
		}
	case 10: // supported_groups
		var g []string
		for i := 2; i+1 < len(d); i += 2 {
			g = append(g, tls.CurveID(binary.BigEndian.Uint16(d[i:])).String())
		}
		return strings.Join(g, ", ")
	case 51: // key_share
		var g []string
		i := 0
		if client {
			i = 2
		}
		for i+4 <= len(d) {
			grp := tls.CurveID(binary.BigEndian.Uint16(d[i:]))
			kl := int(binary.BigEndian.Uint16(d[i+2:]))
			g = append(g, fmt.Sprintf("%s (%d-byte key share)", grp, kl))
			i += 4 + kl
		}
		return strings.Join(g, ", ")
	case 16: // ALPN
		var p []string
		for i := 2; i < len(d); {
			l := int(d[i])
			if i+1+l > len(d) {
				break
			}
			p = append(p, string(d[i+1:i+1+l]))
			i += 1 + l
		}
		return strings.Join(p, ", ")
	}
	return fmt.Sprintf("%d bytes", len(d))
}

func describeCertificate(b []byte, base int) ([]events.Field, string) {
	if len(b) < 6 {
		return nil, ""
	}
	pos := 3 // total certificates length
	var f []events.Field
	for pos+3 <= len(b) {
		cl := int(b[pos])<<16 | int(b[pos+1])<<8 | int(b[pos+2])
		end := min(pos+3+cl, len(b))
		val := fmt.Sprintf("%d bytes DER", cl)
		if c, err := x509.ParseCertificate(b[pos+3 : end]); err == nil {
			val = "subject " + c.Subject.String() + ", issuer " + c.Issuer.String()
		}
		f = append(f, events.Field{Name: "X.509 certificate", Start: base + pos, End: base + end, Value: val})
		pos = end
	}
	return f, "In TLS 1.2 the certificate travels in plaintext: anyone on the path can see which certificate (and thus which site) you are talking to. TLS 1.3 encrypts it."
}
