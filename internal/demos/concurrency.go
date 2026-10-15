package demos

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/davipferr/learn-network-protocols/internal/demo"
	"github.com/davipferr/learn-network-protocols/internal/events"
)

func init() {
	demo.Register(&demo.Demo{
		ID:      "concurrency",
		Title:   "Concurrent connections with goroutines",
		Order:   9,
		Group:   "Server design",
		Summary: "The same TCP server handling many clients sequentially (one at a time) and concurrently (one goroutine per connection), measured side by side.",
		Actors:  []string{"clients", "server"},
		Lesson: []string{
			"A sequential server handles one connection at a time: everyone else waits in the kernel's accept queue.",
			"`go handle(conn)` gives each connection its own goroutine, so slow clients don't block fast ones.",
			"Goroutines are cheap (a few KB of stack). Thousands of them are normal, unlike OS threads.",
			"While a goroutine waits on the network, Go's runtime parks it and runs others (the netpoller uses epoll/kqueue/IOCP).",
			"Total time drops from N x work to roughly 1 x work, as long as the work is mostly waiting (I/O).",
		},
		Params: []demo.Param{
			{Name: "clients", Default: "20", Help: "number of simultaneous clients (max 500)"},
			{Name: "work", Default: "150", Help: "milliseconds each request takes on the server (simulated I/O)"},
			{Name: "mode", Default: "both", Help: "which server(s) to run", Options: []string{"both", "sequential", "concurrent"}},
		},
		Run: runConcurrency,
	})
}

func runConcurrency(ctx context.Context, em *events.Emitter, p demo.Params) error {
	clients := max(1, min(p.Int("clients"), 500))
	work := time.Duration(max(1, min(p.Int("work"), 2000))) * time.Millisecond
	modes := []string{"sequential", "concurrent"}
	if m := p.String("mode"); m != "both" {
		modes = []string{m}
	}

	results := map[string]time.Duration{}
	for i, mode := range modes {
		code := "for {\n    conn, _ := ln.Accept()\n    handle(conn)      // the loop waits until this client is done\n}"
		if mode == "concurrent" {
			code = "for {\n    conn, _ := ln.Accept()\n    go handle(conn)   // a new goroutine per connection, back to Accept at once\n}"
		}
		em.Step(fmt.Sprintf("%d. %s server", i+1, mode), fmt.Sprintf("%d clients connect at the same time. Each request needs %s of server work (think: a database query).\n%s", clients, work, code))
		total, err := runLoad(ctx, em, mode, clients, work)
		if err != nil {
			return err
		}
		results[mode] = total
	}

	if len(results) == 2 {
		em.Step(fmt.Sprintf("%d. Comparison", len(modes)+1), "Same server code, same clients. The only difference is the `go` keyword in the accept loop.")
		s, c := results["sequential"], results["concurrent"]
		em.Info("server", fmt.Sprintf("sequential %s vs concurrent %s: %.1fx faster", s.Round(time.Millisecond), c.Round(time.Millisecond), float64(s)/float64(c)),
			fmt.Sprintf("Sequential is about clients x work = %d x %s. Concurrent is about one unit of work, because all the waiting overlaps.", clients, work))
	}
	return nil
}

func runLoad(ctx context.Context, em *events.Emitter, mode string, clients int, work time.Duration) (time.Duration, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()

	var active, peak, served atomic.Int64
	handle := func(c net.Conn) {
		defer c.Close()
		n := active.Add(1)
		for {
			old := peak.Load()
			if n <= old || peak.CompareAndSwap(old, n) {
				break
			}
		}
		defer active.Add(-1)
		c.SetDeadline(time.Now().Add(30 * time.Second))
		line, err := bufio.NewReader(c).ReadString('\n')
		if err != nil {
			return
		}
		time.Sleep(work) // the "work": blocked on I/O, like a DB call
		fmt.Fprintf(c, "done %s", line)
		served.Add(1)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if mode == "concurrent" {
				go handle(c)
			} else {
				handle(c)
			}
		}
	}()

	baseline := runtime.NumGoroutine()
	start := time.Now()
	stop := make(chan struct{})
	var tick sync.WaitGroup
	tick.Go(func() {
		t := time.NewTicker(25 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
			}
			em.Metric(mode, map[string]float64{
				"t":          float64(time.Since(start).Milliseconds()),
				"active":     float64(active.Load()),
				"served":     float64(served.Load()),
				"goroutines": float64(max(0, runtime.NumGoroutine()-baseline)),
			})
		}
	})

	verbose := clients <= 10
	latencies := make([]time.Duration, clients)
	var wg sync.WaitGroup
	var errMu sync.Mutex
	var firstErr error
	setErr := func(err error) {
		errMu.Lock()
		if firstErr == nil {
			firstErr = err
		}
		errMu.Unlock()
	}
	for i := range clients {
		wg.Go(func() {
			t0 := time.Now()
			c, err := (&net.Dialer{}).DialContext(ctx, "tcp", ln.Addr().String())
			if err != nil {
				setErr(err)
				return
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(30 * time.Second))
			if verbose {
				em.Send("clients", "server", "tcp", fmt.Sprintf("client %d: request", i), []byte(fmt.Sprintf("req %d\n", i)), nil, "")
			}
			fmt.Fprintf(c, "req %d\n", i)
			if _, err := bufio.NewReader(c).ReadString('\n'); err != nil {
				setErr(err)
				return
			}
			latencies[i] = time.Since(t0)
			if verbose {
				em.Send("server", "clients", "tcp", fmt.Sprintf("client %d: reply after %s", i, latencies[i].Round(time.Millisecond)), []byte("done"), nil, "")
			}
		})
	}
	wg.Wait()
	total := time.Since(start)
	close(stop)
	tick.Wait()
	em.Metric(mode, map[string]float64{"t": float64(total.Milliseconds()), "active": 0, "served": float64(served.Load()), "goroutines": 0})
	if firstErr != nil {
		return 0, firstErr
	}

	slices.Sort(latencies)
	var sum time.Duration
	for _, l := range latencies {
		sum += l
	}
	em.Info("server", fmt.Sprintf("%s: %d clients served in %s", mode, served.Load(), total.Round(time.Millisecond)),
		fmt.Sprintf("Peak simultaneous connections being handled: %d\nLatency: fastest %s, average %s, slowest %s",
			peak.Load(), latencies[0].Round(time.Millisecond), (sum/time.Duration(clients)).Round(time.Millisecond), latencies[len(latencies)-1].Round(time.Millisecond)))
	return total, nil
}
