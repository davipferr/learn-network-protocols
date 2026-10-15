// Package demo holds the registry of runnable lessons.
package demo

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/davipferr/learn-network-protocols/internal/events"
)

// Param is a user-tunable input of a demo (a CLI flag / a form field in the UI).
type Param struct {
	Name    string   `json:"name"`
	Default string   `json:"default"`
	Help    string   `json:"help"`
	Options []string `json:"options,omitempty"`
}

type Demo struct {
	ID      string   `json:"id"`
	Order   int      `json:"-"` // position in the learning path
	Title   string   `json:"title"`
	Group   string   `json:"group"`   // section of the learning path, e.g. "Transport"
	Summary string   `json:"summary"` // one line
	Lesson  []string `json:"lesson"`  // key takeaways
	Actors  []string `json:"actors"`  // lanes for the sequence diagram, left to right
	Params  []Param  `json:"params"`

	Run func(ctx context.Context, em *events.Emitter, p Params) error `json:"-"`
}

var registry []*Demo

// Register adds a demo; demos call it from init functions.
func Register(d *Demo) {
	registry = append(registry, d)
	slices.SortStableFunc(registry, func(a, b *Demo) int { return a.Order - b.Order })
}

// All returns the demos in learning order.
func All() []*Demo { return registry }

func Get(id string) *Demo {
	for _, d := range registry {
		if d.ID == id {
			return d
		}
	}
	return nil
}

// Params are the resolved parameter values of a run.
type Params map[string]string

func (p Params) String(name string) string { return p[name] }

func (p Params) Int(name string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(p[name]))
	return n
}

func (p Params) Bool(name string) bool {
	switch strings.ToLower(strings.TrimSpace(p[name])) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// Timeout bounds a single run so a stuck demo never hangs the program.
const Timeout = 45 * time.Second

// Run executes d, filling missing params with defaults and publishing
// start/end events around it. It returns when the demo finishes.
func Run(ctx context.Context, bus *events.Bus, runID string, d *Demo, in map[string]string) error {
	em := events.NewEmitter(bus, runID, d.ID)
	em.Emit(events.Event{Kind: events.KindStart, Title: d.Title, Detail: d.Summary})

	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()

	p, err := resolve(d, in)
	if err == nil {
		err = safeRun(ctx, em, d, p)
	}
	end := events.Event{Kind: events.KindEnd, Title: "Finished"}
	if err != nil {
		em.Error("", "Demo failed", err)
		end.Title = "Finished with an error"
		end.Detail = err.Error()
	}
	em.Emit(end)
	return err
}

// resolve fills missing params with their defaults and validates options.
func resolve(d *Demo, in map[string]string) (Params, error) {
	p := Params{}
	for _, prm := range d.Params {
		v, ok := in[prm.Name]
		if !ok || strings.TrimSpace(v) == "" {
			v = prm.Default
		}
		if len(prm.Options) > 0 && !slices.Contains(prm.Options, v) {
			return nil, fmt.Errorf("param %q must be one of %v", prm.Name, prm.Options)
		}
		p[prm.Name] = v
	}
	return p, nil
}

func safeRun(ctx context.Context, em *events.Emitter, d *Demo, p Params) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return d.Run(ctx, em, p)
}

func NewRunID() string {
	b := make([]byte, 6)
	rand.Read(b)
	return hex.EncodeToString(b)
}
