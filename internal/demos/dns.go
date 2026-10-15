package demos

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/davipferr/learn-network-protocols/internal/demo"
	"github.com/davipferr/learn-network-protocols/internal/dnsmsg"
	"github.com/davipferr/learn-network-protocols/internal/events"
)

func init() {
	types := []string{"A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"}
	demo.Register(&demo.Demo{
		ID:      "dns",
		Title:   "DNS: asking where a name lives",
		Order:   7,
		Group:   "Infrastructure",
		Summary: "Builds a DNS query byte by byte, sends it over UDP to a real resolver, decodes the answer (with name compression), then compares with Go's net.Resolver.",
		Actors:  []string{"client", "resolver"},
		Lesson: []string{
			"DNS translates names into records: A (IPv4), AAAA (IPv6), MX (mail), TXT, NS, CNAME...",
			"A query is one small UDP datagram, and so is the answer. No handshake, so it's fast.",
			"The 2-byte ID matches answers to questions; flags carry RD (please recurse), RA, the response code...",
			"Names are encoded as length-prefixed labels; answers reuse earlier names with 2-byte compression pointers.",
			"Answers bigger than 512 bytes set the TC (truncated) flag and the client retries over TCP, with a 2-byte length prefix.",
			"Every record has a TTL: how long resolvers and clients may cache it.",
		},
		Params: []demo.Param{
			{Name: "name", Default: "go.dev", Help: "domain name to look up"},
			{Name: "type", Default: "A", Help: "record type", Options: types},
			{Name: "server", Default: "8.8.8.8:53", Help: "DNS resolver address (host:port)"},
			{Name: "transport", Default: "udp", Help: "start with UDP or force TCP", Options: []string{"udp", "tcp"}},
		},
		Run: runDNS,
	})
}

func runDNS(ctx context.Context, em *events.Emitter, p demo.Params) error {
	name := strings.TrimSpace(p.String("name"))
	qtypeName := p.String("type")
	qtype := dnsmsg.Types[qtypeName]
	server := p.String("server")

	n := 0
	step := func(title, detail string) {
		n++
		em.Step(fmt.Sprintf("%d. %s", n, title), detail)
	}

	step("Building the query by hand", fmt.Sprintf("A 12-byte header, then the question: %q encoded as labels (each prefixed by its length), the type %s and the class IN. Hover the bytes to see each field.", name, qtypeName))
	id := uint16(rand.IntN(0x10000))
	query, fields, err := dnsmsg.BuildQuery(id, name, qtype)
	if err != nil {
		return err
	}
	em.Info("client", fmt.Sprintf("query is %d bytes", len(query)), "")

	var resp []byte
	var rtt time.Duration
	if p.String("transport") == "udp" {
		step("Sending it in one UDP datagram", fmt.Sprintf("To %s. If no answer comes back in time we would simply ask again: UDP won't do it for us.", server))
		em.Send("client", "resolver", "dns/udp", fmt.Sprintf("query %s %s (id 0x%04x)", name, qtypeName, id), query, fields, "")
		resp, rtt, err = dnsUDP(ctx, server, query)
		if err != nil {
			return fmt.Errorf("%w (is %s reachable? try -server with your router's address)", err, server)
		}
	}

	if resp != nil {
		msg, rfields, perr := dnsmsg.Parse(resp)
		em.Send("resolver", "client", "dns/udp", fmt.Sprintf("answer id 0x%04x, %d records", binary.BigEndian.Uint16(resp), countRecords(msg)), resp, rfields,
			fmt.Sprintf("Round trip: %s. Look for \"compressed\" names: a 2-byte pointer (first byte 0xc0) back to where the name first appeared.", rtt.Round(time.Microsecond)))
		if perr != nil {
			return perr
		}
		if msg.ID != id {
			return fmt.Errorf("answer ID 0x%04x does not match query ID 0x%04x", msg.ID, id)
		}
		if msg.Truncated {
			em.Info("client", "TC flag set: the answer didn't fit in 512 bytes", "Classic DNS over UDP is limited to 512 bytes (without the EDNS0 extension). The rule is to retry the same query over TCP.")
			resp = nil
		} else {
			reportAnswers(em, msg)
		}
	}

	if resp == nil {
		step("DNS over TCP", "Same query bytes, but TCP is a stream (see the TCP demo), so DNS adds a 2-byte length prefix in front of each message.")
		framed := binary.BigEndian.AppendUint16(nil, uint16(len(query)))
		framed = append(framed, query...)
		tcpFields := append([]events.Field{{Name: "TCP length prefix", Start: 0, End: 2, Value: fmt.Sprint(len(query))}}, shift(fields, 2)...)
		em.Send("client", "resolver", "dns/tcp", fmt.Sprintf("query %s %s over TCP", name, qtypeName), framed, tcpFields, "")
		resp, rtt, err = dnsTCP(ctx, server, framed)
		if err != nil {
			return err
		}
		msg, rfields, perr := dnsmsg.Parse(resp)
		em.Send("resolver", "client", "dns/tcp", fmt.Sprintf("answer over TCP, %d records", countRecords(msg)), resp, rfields, fmt.Sprintf("Round trip including the TCP handshake: %s (length prefix already removed).", rtt.Round(time.Microsecond)))
		if perr != nil {
			return perr
		}
		reportAnswers(em, msg)
	}

	step("The easy way: net.Resolver", "Go's standard library does all of the above (and reads the OS configuration, tries several servers, handles search domains...). Lookups through it may also be answered from a cache.")
	r := &net.Resolver{PreferGo: true}
	lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	start := time.Now()
	var results []string
	switch qtypeName {
	case "A", "AAAA":
		network := "ip4"
		if qtypeName == "AAAA" {
			network = "ip6"
		}
		ips, e := r.LookupIP(lctx, network, name)
		for _, ip := range ips {
			results = append(results, ip.String())
		}
		err = e
	case "MX":
		mxs, e := r.LookupMX(lctx, name)
		for _, mx := range mxs {
			results = append(results, fmt.Sprintf("%d %s", mx.Pref, mx.Host))
		}
		err = e
	case "TXT":
		results, err = r.LookupTXT(lctx, name)
	case "NS":
		nss, e := r.LookupNS(lctx, name)
		for _, ns := range nss {
			results = append(results, ns.Host)
		}
		err = e
	case "CNAME":
		c, e := r.LookupCNAME(lctx, name)
		results, err = []string{c}, e
	default:
		em.Info("client", "net.Resolver has no helper for "+qtypeName, "For other types you build the query yourself, like above (or use a DNS library).")
		return nil
	}
	if err != nil {
		em.Error("client", "net.Resolver lookup failed", err)
		return nil
	}
	em.Info("client", fmt.Sprintf("net.Resolver: %d result(s) in %s", len(results), time.Since(start).Round(time.Microsecond)), strings.Join(results, "\n"))
	return nil
}

func dnsUDP(ctx context.Context, server string, query []byte) ([]byte, time.Duration, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "udp", server)
	if err != nil {
		return nil, 0, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	start := time.Now()
	if _, err := conn.Write(query); err != nil {
		return nil, 0, err
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, 0, err
	}
	return buf[:n], time.Since(start), nil
}

func dnsTCP(ctx context.Context, server string, framed []byte) ([]byte, time.Duration, error) {
	start := time.Now()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", server)
	if err != nil {
		return nil, 0, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(framed); err != nil {
		return nil, 0, err
	}
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, 0, err
	}
	resp := make([]byte, binary.BigEndian.Uint16(hdr[:]))
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, 0, err
	}
	return resp, time.Since(start), nil
}

func reportAnswers(em *events.Emitter, m *dnsmsg.Message) {
	if m.Rcode != 0 {
		em.Info("client", "response code "+dnsmsg.RcodeName(m.Rcode), map[int]string{
			2: "SERVFAIL: the resolver couldn't get an answer.",
			3: "NXDOMAIN: this name does not exist.",
			5: "REFUSED: the server won't answer us.",
		}[m.Rcode])
		return
	}
	var lines []string
	for _, r := range m.Records {
		if r.Type == dnsmsg.Types["OPT"] {
			continue
		}
		lines = append(lines, fmt.Sprintf("[%s] %s  %s  TTL %ds  %s", r.Section, r.Name, dnsmsg.TypeName(r.Type), r.TTL, r.Data))
	}
	if len(lines) == 0 {
		lines = []string{"(no records of this type: the name exists but has no " + strings.Join(m.Questions, "") + " data)"}
	}
	em.Info("client", "decoded answer", strings.Join(lines, "\n"))
}

func countRecords(m *dnsmsg.Message) int {
	if m == nil {
		return 0
	}
	return len(m.Records)
}

func shift(fields []events.Field, by int) []events.Field {
	out := slices.Clone(fields)
	for i := range out {
		out[i].Start += by
		out[i].End += by
	}
	return out
}
