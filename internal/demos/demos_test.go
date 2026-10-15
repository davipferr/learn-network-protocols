package demos

import (
	"context"
	"testing"

	"github.com/davipferr/learn-network-protocols/internal/demo"
	"github.com/davipferr/learn-network-protocols/internal/events"
)

// Every demo runs real clients and servers on 127.0.0.1, so this test
// exercises the whole stack. DNS needs the Internet and is skipped.
func TestDemosRun(t *testing.T) {
	small := map[string]map[string]string{
		"concurrency": {"clients": "5", "work": "20"},
		"udp":         {"count": "5"},
	}
	for _, d := range demo.All() {
		if d.ID == "dns" {
			continue
		}
		t.Run(d.ID, func(t *testing.T) {
			bus := events.NewBus()
			evs, stop := bus.Subscribe(1 << 16)
			err := demo.Run(context.Background(), bus, "test", d, small[d.ID])
			stop()
			if err != nil {
				t.Fatal(err)
			}
			sends := 0
			for e := range evs {
				if e.Kind == events.KindSend {
					sends++
				}
			}
			if sends == 0 {
				t.Fatal("demo emitted no send events")
			}
		})
	}
}
