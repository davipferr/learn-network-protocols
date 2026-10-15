// Package events defines the structured events every demo emits.
//
// Demos never print directly. They describe what happens (a step of the
// lesson, bytes crossing the wire, a state change, a metric) as an Event,
// and the event is fanned out to whoever is listening: the terminal printer
// in CLI mode or the browser UI over a WebSocket in "serve" mode.
package events

import (
	"sync"
	"sync/atomic"
	"time"
)

// Kind tells consumers how to render an event.
type Kind string

const (
	KindStart  Kind = "start"  // a demo run began
	KindStep   Kind = "step"   // a new section of the lesson, with an explanation
	KindInfo   Kind = "info"   // something an actor did or learned
	KindState  Kind = "state"  // a connection/socket changed state
	KindSend   Kind = "send"   // bytes moved From -> To
	KindMetric Kind = "metric" // numeric samples (used by charts)
	KindError  Kind = "error"  // something failed (sometimes on purpose)
	KindEnd    Kind = "end"    // a demo run finished
)

// Field annotates a byte range [Start, End) of Event.Bytes so a viewer can
// highlight it ("these 2 bytes are the DNS transaction ID").
type Field struct {
	Name  string `json:"name"`
	Start int    `json:"start"`
	End   int    `json:"end"`
	Value string `json:"value,omitempty"`
}

// MaxBytes caps how many bytes of a payload are kept in an event.
const MaxBytes = 4096

type Event struct {
	Seq       int64              `json:"seq"`
	RunID     string             `json:"runId"`
	Demo      string             `json:"demo"`
	Time      time.Time          `json:"time"`
	ElapsedMs float64            `json:"elapsedMs"`
	Kind      Kind               `json:"kind"`
	Actor     string             `json:"actor,omitempty"` // who did it (info/state/error)
	From      string             `json:"from,omitempty"`  // sender (send)
	To        string             `json:"to,omitempty"`    // receiver (send)
	Layer     string             `json:"layer,omitempty"` // protocol layer: tcp, tls, http2, dns...
	Title     string             `json:"title"`
	Detail    string             `json:"detail,omitempty"`
	Bytes     []byte             `json:"bytes,omitempty"`
	Size      int                `json:"size,omitempty"` // real payload size (Bytes may be truncated)
	Fields    []Field            `json:"fields,omitempty"`
	Metrics   map[string]float64 `json:"metrics,omitempty"`
	Simulated bool               `json:"simulated,omitempty"` // conceptual, not observed (e.g. kernel SYN)
	Dropped   bool               `json:"dropped,omitempty"`   // lost on the way
}

// Bus fans events out to any number of subscribers.
type Bus struct {
	mu   sync.Mutex
	subs map[int]chan Event
	next int
	seq  atomic.Int64
}

func NewBus() *Bus {
	return &Bus{subs: make(map[int]chan Event)}
}

// Subscribe returns a channel of events and a function to stop receiving.
func (b *Bus) Subscribe(buffer int) (<-chan Event, func()) {
	ch := make(chan Event, buffer)
	b.mu.Lock()
	id := b.next
	b.next++
	b.subs[id] = ch
	b.mu.Unlock()

	var once sync.Once
	return ch, func() {
		once.Do(func() {
			b.mu.Lock()
			delete(b.subs, id)
			b.mu.Unlock()
			close(ch)
		})
	}
}

// Publish delivers e to every subscriber. A subscriber whose buffer is full
// misses the event instead of blocking the demo.
func (b *Bus) Publish(e Event) {
	e.Seq = b.seq.Add(1)
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, ch := range b.subs {
		select {
		case ch <- e:
		default:
		}
	}
}

// Emitter is the handle a demo uses to publish events for one run.
type Emitter struct {
	bus   *Bus
	runID string
	demo  string
	start time.Time
}

func NewEmitter(bus *Bus, runID, demo string) *Emitter {
	return &Emitter{bus: bus, runID: runID, demo: demo, start: time.Now()}
}

func (e *Emitter) RunID() string { return e.runID }

func (e *Emitter) Emit(ev Event) {
	now := time.Now()
	ev.RunID = e.runID
	ev.Demo = e.demo
	ev.Time = now
	ev.ElapsedMs = float64(now.Sub(e.start).Microseconds()) / 1000
	if ev.Bytes != nil {
		ev.Size = len(ev.Bytes)
		n := min(len(ev.Bytes), MaxBytes)
		ev.Bytes = append([]byte(nil), ev.Bytes[:n]...)
		kept := ev.Fields[:0:0]
		for _, f := range ev.Fields {
			if f.Start < n {
				f.End = min(f.End, n)
				kept = append(kept, f)
			}
		}
		ev.Fields = kept
	}
	e.bus.Publish(ev)
}

// Step starts a new section of the lesson.
func (e *Emitter) Step(title, detail string) {
	e.Emit(Event{Kind: KindStep, Title: title, Detail: detail})
}

func (e *Emitter) Info(actor, title, detail string) {
	e.Emit(Event{Kind: KindInfo, Actor: actor, Title: title, Detail: detail})
}

func (e *Emitter) State(actor, title, detail string) {
	e.Emit(Event{Kind: KindState, Actor: actor, Title: title, Detail: detail})
}

func (e *Emitter) Error(actor, title string, err error) {
	e.Emit(Event{Kind: KindError, Actor: actor, Title: title, Detail: err.Error()})
}

func (e *Emitter) Metric(title string, m map[string]float64) {
	e.Emit(Event{Kind: KindMetric, Title: title, Metrics: m})
}

// Send records bytes moving between two actors.
func (e *Emitter) Send(from, to, layer, title string, b []byte, fields []Field, detail string) {
	if b == nil {
		b = []byte{}
	}
	e.Emit(Event{Kind: KindSend, From: from, To: to, Layer: layer, Title: title, Bytes: b, Fields: fields, Detail: detail})
}

// Concept records a message that really happens but that user-space code
// cannot observe (for example the kernel's TCP SYN/ACK packets).
func (e *Emitter) Concept(from, to, layer, title, detail string) {
	e.Emit(Event{Kind: KindSend, From: from, To: to, Layer: layer, Title: title, Detail: detail, Simulated: true})
}
