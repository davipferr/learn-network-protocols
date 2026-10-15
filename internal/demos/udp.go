package demos

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"net"
	"time"

	"github.com/davipferr/learn-network-protocols/internal/demo"
	"github.com/davipferr/learn-network-protocols/internal/events"
)

func init() {
	demo.Register(&demo.Demo{
		ID:      "udp",
		Title:   "UDP: independent datagrams",
		Order:   2,
		Group:   "Transport",
		Summary: "net.ListenUDP + net.DialUDP: no handshake, message boundaries preserved, and no guarantee of delivery or order.",
		Actors:  []string{"client", "network", "server"},
		Lesson: []string{
			"UDP has no connection: DialUDP sends nothing, it only remembers the destination.",
			"Each Write is one datagram and each Read returns exactly one datagram. Boundaries are preserved, unlike TCP.",
			"Datagrams can be lost, duplicated or reordered. UDP does not notice and does not retransmit.",
			"Reliability, if needed, is the application's job: sequence numbers, ACKs, timeouts (this is what QUIC and many games do).",
			"In exchange UDP is cheap and fast: no handshake, no head-of-line blocking. DNS, video calls, games and QUIC (HTTP/3) use it.",
		},
		Params: []demo.Param{
			{Name: "count", Default: "10", Help: "how many datagrams to send"},
			{Name: "loss", Default: "25", Help: "simulated packet loss, in percent"},
			{Name: "reorder", Default: "yes", Help: "simulate datagrams overtaking each other", Options: []string{"yes", "no"}},
		},
		Run: runUDP,
	})
}

func runUDP(ctx context.Context, em *events.Emitter, p demo.Params) error {
	count := max(1, min(p.Int("count"), 200))
	loss := max(0, min(p.Int("loss"), 100))
	reorder := p.Bool("reorder")

	em.Step("1. The server binds a UDP socket", "net.ListenUDP gives a socket that receives datagrams from anyone. There is no Accept: there are no connections to accept.")
	srv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return err
	}
	defer srv.Close()
	em.State("server", "bound to "+srv.LocalAddr().String(), "")

	em.Step("2. The client \"dials\"", "net.DialUDP creates a socket and records the default destination. Nothing goes on the wire: compare with the TCP handshake.")
	start := time.Now()
	cli, err := net.DialUDP("udp", nil, srv.LocalAddr().(*net.UDPAddr))
	if err != nil {
		return err
	}
	defer cli.Close()
	em.State("client", fmt.Sprintf("ready in %s, zero packets sent", time.Since(start).Round(time.Microsecond)), "local "+cli.LocalAddr().String())

	type recv struct {
		seq  uint32
		from string
	}
	got := make(chan []recv, 1)
	go func() {
		var list []recv
		buf := make([]byte, 65535)
		for {
			srv.SetReadDeadline(time.Now().Add(700 * time.Millisecond))
			n, from, err := srv.ReadFromUDP(buf)
			if err != nil {
				got <- list
				return
			}
			if n < 4 {
				continue
			}
			seq := binary.BigEndian.Uint32(buf[:4])
			list = append(list, recv{seq, from.String()})
			em.Info("server", fmt.Sprintf("ReadFromUDP -> one whole datagram: seq=%d %q", seq, buf[4:n]), fmt.Sprintf("%d bytes from %s", n, from))
			// The server answers with a tiny ACK. The client ignores it here, but
			// this is the starting point of any reliability scheme.
			ack := binary.BigEndian.AppendUint32([]byte("ACK"), seq)
			srv.WriteToUDP(ack, from)
		}
	}()

	em.Step("3. Sending datagrams through an unreliable network", fmt.Sprintf("The client sends %d datagrams, each with a 4-byte sequence number we added ourselves (UDP has none). A simulated network in the middle drops %d%% of them and may swap neighbours, like the real Internet sometimes does.", count, loss))
	var held []byte
	var heldSeq uint32
	for i := range count {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		payload := fmt.Sprintf("datagram #%d", i)
		dg := binary.BigEndian.AppendUint32(nil, uint32(i))
		dg = append(dg, payload...)
		fields := []events.Field{
			{Name: "sequence number (our own header)", Start: 0, End: 4, Value: fmt.Sprint(i)},
			{Name: "payload", Start: 4, End: len(dg), Value: payload},
		}

		if rand.IntN(100) < loss {
			em.Emit(events.Event{Kind: events.KindSend, From: "client", To: "network", Layer: "udp", Title: fmt.Sprintf("seq=%d lost", i), Bytes: dg, Fields: fields, Dropped: true,
				Detail: "The network dropped this datagram (congested router, Wi-Fi noise...). Nobody is told: the client's Write already returned success."})
			continue
		}
		if reorder && held == nil && i < count-1 && rand.IntN(3) == 0 {
			held, heldSeq = dg, uint32(i)
			em.Send("client", "network", "udp", fmt.Sprintf("seq=%d delayed", i), dg, fields, "This datagram takes a slower path and will arrive after the next one.")
			continue
		}
		em.Send("client", "server", "udp", fmt.Sprintf("seq=%d", i), dg, fields, "")
		if _, err := cli.Write(dg); err != nil {
			return err
		}
		if held != nil {
			time.Sleep(5 * time.Millisecond)
			em.Send("network", "server", "udp", fmt.Sprintf("seq=%d (late, out of order)", heldSeq), held, nil, "Arrives after a later datagram.")
			cli.Write(held)
			held = nil
		}
		time.Sleep(15 * time.Millisecond)
	}
	if held != nil {
		em.Send("network", "server", "udp", fmt.Sprintf("seq=%d (late)", heldSeq), held, nil, "")
		cli.Write(held)
	}

	list := <-got
	acks := 0
	buf := make([]byte, 64)
	for {
		cli.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		if _, err := cli.Read(buf); err != nil {
			break // read deadline reached: no more ACKs
		}
		acks++
	}

	em.Step("4. What arrived?", "The server only knows what it received. Because we numbered the datagrams, it can detect gaps and reordering. UDP itself would never tell us.")
	var order []uint32
	seen := map[uint32]bool{}
	outOfOrder := 0
	for i, r := range list {
		order = append(order, r.seq)
		seen[r.seq] = true
		if i > 0 && r.seq < list[i-1].seq {
			outOfOrder++
		}
	}
	var missing []int
	for i := range count {
		if !seen[uint32(i)] {
			missing = append(missing, i)
		}
	}
	em.Info("server", fmt.Sprintf("arrival order: %v", order), fmt.Sprintf("missing: %v. Out-of-order arrivals: %d.", missing, outOfOrder))
	em.Metric("udp summary", map[string]float64{"sent": float64(count), "received": float64(len(list)), "lost": float64(len(missing)), "outOfOrder": float64(outOfOrder), "acksBack": float64(acks)})
	em.Info("client", fmt.Sprintf("received %d ACKs back", acks), "If the client wanted reliability it would resend every datagram whose ACK did not come back in time. That is (very roughly) what TCP does for you inside the kernel.")
	return nil
}
