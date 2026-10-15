package demos

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/davipferr/learn-network-protocols/internal/demo"
	"github.com/davipferr/learn-network-protocols/internal/events"
	"github.com/davipferr/learn-network-protocols/internal/tlsrec"
	"github.com/davipferr/learn-network-protocols/internal/wire"
)

func init() {
	demo.Register(&demo.Demo{
		ID:      "tls",
		Title:   "TLS: encrypting a TCP connection",
		Order:   6,
		Group:   "Security",
		Summary: "crypto/tls with a self-signed certificate: certificate verification, the handshake record by record, and what an eavesdropper sees.",
		Actors:  []string{"client", "server"},
		Lesson: []string{
			"TLS sits between TCP and the application: same byte stream, but encrypted and authenticated.",
			"The certificate proves identity only if a trusted authority signed it (or the client was told to trust it).",
			"The handshake agrees on a version, a cipher suite and fresh keys via (EC)Diffie-Hellman, so the keys never travel on the wire.",
			"TLS 1.3 needs one round trip and encrypts almost the whole handshake, including the certificate. TLS 1.2 shows much more in plaintext.",
			"After the handshake, an observer only sees record headers and sizes, never the content.",
		},
		Params: []demo.Param{
			{Name: "version", Default: "1.3", Help: "maximum TLS version", Options: []string{"1.3", "1.2"}},
			{Name: "message", Default: "my password is hunter2", Help: "secret the client sends"},
		},
		Run: runTLS,
	})
}

func runTLS(ctx context.Context, em *events.Emitter, p demo.Params) error {
	maxVer := uint16(tls.VersionTLS13)
	if p.String("version") == "1.2" {
		maxVer = tls.VersionTLS12
	}

	em.Step("1. The server gets a certificate", "We generate an ECDSA P-256 key pair and a self-signed X.509 certificate for \"localhost\" with crypto/x509. In production a Certificate Authority (e.g. Let's Encrypt) would sign it instead.")
	cert, leaf, err := selfSignedCert()
	if err != nil {
		return err
	}
	fp := sha256.Sum256(leaf.Raw)
	em.Emit(events.Event{Kind: events.KindInfo, Actor: "server", Layer: "x509", Title: "certificate for " + strings.Join(leaf.DNSNames, ", "),
		Bytes: leaf.Raw,
		Detail: fmt.Sprintf("Subject: %s\nIssuer: %s (self-signed: issuer = subject)\nValid: %s to %s\nPublic key: %s, signature: %s\nSHA-256 fingerprint: %x\nThe bytes are the certificate in DER (binary ASN.1) form.",
			leaf.Subject, leaf.Issuer, leaf.NotBefore.Format(time.DateOnly), leaf.NotAfter.Format(time.DateOnly), leaf.PublicKeyAlgorithm, leaf.SignatureAlgorithm, fp[:8])})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer ln.Close()
	serverCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MaxVersion: maxVer, NextProtos: []string{"demo/1"}}

	// Each accepted connection is served by echoServer. The first one is not
	// tapped (failing verification); later ones are.
	var tapNext atomic.Bool
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			conn := raw
			if tapNext.Load() {
				// Tap BELOW TLS: we see the encrypted records exactly as they travel.
				cr := &recordReporter{em: em, from: "client", to: "server", tls13: maxVer == tls.VersionTLS13,
					hints: []string{"the client's Finished"}}
				sr := &recordReporter{em: em, from: "server", to: "client", tls13: maxVer == tls.VersionTLS13,
					hints: []string{"EncryptedExtensions", "Certificate (hidden in TLS 1.3!)", "CertificateVerify (signature proving key ownership)", "the server's Finished"}}
				cp := &tlsrec.Parser{OnRecord: cr.report}
				sp := &tlsrec.Parser{OnRecord: sr.report}
				conn = wire.NewConn(raw, func(dir wire.Dir, b []byte) {
					if dir == wire.In {
						cp.Feed(b)
					} else {
						sp.Feed(b)
					}
				})
			}
			go tlsEchoServer(tls.Server(conn, serverCfg), em)
		}
	}()

	em.Step("2. A client that doesn't trust the certificate", "The client uses the system's trusted root CAs. Our certificate isn't signed by any of them, so verification fails and the handshake is aborted. This is what protects you from a man-in-the-middle.")
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	_, err = tls.DialWithDialer(dialer, "tcp", ln.Addr().String(), &tls.Config{ServerName: "localhost", MaxVersion: maxVer})
	if err != nil {
		em.Error("client", "handshake refused", err)
	}
	time.Sleep(50 * time.Millisecond)

	em.Step("3. A client that trusts our certificate", fmt.Sprintf("Now the client puts the certificate in its RootCAs pool (like installing a company CA). We also record the session secrets with KeyLogWriter, the same format Wireshark uses to decrypt captures. Max version: TLS %s. Every TLS record below is captured from the raw TCP connection, under the encryption.", p.String("version")))
	tapNext.Store(true)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	var keylog bytes.Buffer
	clientCfg := &tls.Config{RootCAs: pool, ServerName: "localhost", MaxVersion: maxVer, NextProtos: []string{"demo/1"}, KeyLogWriter: &keylog}
	start := time.Now()
	conn, err := tls.DialWithDialer(dialer, "tcp", ln.Addr().String(), clientCfg)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	time.Sleep(30 * time.Millisecond) // let the tap report the last handshake records first

	st := conn.ConnectionState()
	em.State("client", fmt.Sprintf("handshake complete in %s", time.Since(start).Round(time.Microsecond)),
		fmt.Sprintf("Version: %s\nCipher suite: %s\nKey exchange: %s\nALPN protocol: %q\nServer certificate verified: %s (chain length %d)",
			tls.VersionName(st.Version), tls.CipherSuiteName(st.CipherSuite), st.CurveID, st.NegotiatedProtocol,
			st.PeerCertificates[0].Subject, len(st.VerifiedChains[0])))

	var labels []string
	for _, line := range strings.Split(strings.TrimSpace(keylog.String()), "\n") {
		if f := strings.Fields(line); len(f) == 3 {
			labels = append(labels, f[0]+" "+f[2][:16]+"…")
		}
	}
	em.Info("client", "session secrets (KeyLogWriter)", "These secrets were derived on both sides and never sent. Anyone holding them could decrypt this capture:\n"+strings.Join(labels, "\n"))

	em.Step("4. Sending a secret", "The application writes plaintext into the tls.Conn. TLS encrypts it into an ApplicationData record. Compare the plaintext with what actually crosses the wire.")
	msg := p.String("message")
	em.Info("client", fmt.Sprintf("conn.Write(%q)", msg), "This is what the application sees (plaintext).")
	if _, err := conn.Write([]byte(msg + "\n")); err != nil {
		return err
	}
	reply, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return err
	}
	em.Info("client", fmt.Sprintf("decrypted reply: %q", strings.TrimSpace(reply)), "")

	em.Step("5. Closing", "conn.Close() sends a close_notify alert (encrypted in TLS 1.3) so the peer knows the stream ended on purpose and wasn't cut by an attacker.")
	conn.Close()
	time.Sleep(50 * time.Millisecond)
	return nil
}

// recordReporter emits one direction's TLS records. In TLS 1.3 the
// handshake messages after ServerHello are encrypted, but their order is
// fixed, so the first encrypted records can be labeled with what they
// (almost certainly) contain.
type recordReporter struct {
	em        *events.Emitter
	from, to  string
	tls13     bool
	hints     []string
	encrypted int
}

func (rr *recordReporter) report(r tlsrec.Record) {
	title, fields, detail := tlsrec.Describe(r)
	if r.Type == tlsrec.TypeApplicationData {
		if rr.tls13 && rr.encrypted < len(rr.hints) {
			title += ": probably " + rr.hints[rr.encrypted]
		}
		if rr.encrypted > 0 || rr.from == "client" {
			detail = "Only the 5-byte header and the size are visible."
		}
		rr.encrypted++
	}
	rr.em.Send(rr.from, rr.to, "tls", title, r.Raw, fields, detail)
}

func tlsEchoServer(c *tls.Conn, em *events.Emitter) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if err := c.Handshake(); err != nil {
		em.Error("server", "handshake failed", err)
		return
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return
	}
	em.Info("server", fmt.Sprintf("decrypted: %q", strings.TrimSpace(line)), "Only the two endpoints can read this.")
	c.Write([]byte("got it, your secret is safe with me\n"))
	// Wait for the client's close_notify.
	c.Read(make([]byte, 1))
}

func selfSignedCert() (tls.Certificate, *x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "localhost", Organization: []string{"learn-network-protocols"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, leaf, nil
}
