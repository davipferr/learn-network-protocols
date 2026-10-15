// Package server exposes the demos to the browser UI.
//
//	GET  /api/demos  -> the catalog (JSON)
//	POST /api/runs   -> start a demo, returns {"runId": "..."}
//	GET  /ws         -> live event stream, over our own WebSocket implementation
//	GET  /           -> the React app, embedded in the binary
package server

import (
	"context"
	"encoding/json"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/davipferr/learn-network-protocols/internal/demo"
	"github.com/davipferr/learn-network-protocols/internal/events"
	"github.com/davipferr/learn-network-protocols/internal/ws"
)

type Server struct {
	bus *events.Bus
	ui  fs.FS
}

func New(bus *events.Bus, ui fs.FS) *Server {
	return &Server{bus: bus, ui: ui}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/demos", s.listDemos)
	mux.HandleFunc("POST /api/runs", s.startRun)
	mux.HandleFunc("GET /ws", s.events)
	mux.Handle("GET /", http.FileServerFS(s.ui))
	return logRequests(mux)
}

func (s *Server) listDemos(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(demo.All())
}

func (s *Server) startRun(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Demo   string            `json:"demo"`
		Params map[string]string `json:"params"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	d := demo.Get(body.Demo)
	if d == nil {
		http.Error(w, "unknown demo", http.StatusNotFound)
		return
	}
	runID := demo.NewRunID()
	// The run outlives this request: it streams its events over /ws.
	go demo.Run(context.Background(), s.bus, runID, d, body.Params)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"runId": runID})
}

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		http.Error(w, "cross-origin WebSocket refused", http.StatusForbidden)
		return
	}
	conn, err := ws.Upgrade(w, r)
	if err != nil {
		return
	}
	defer conn.Close()
	evs, unsubscribe := s.bus.Subscribe(4096)
	defer unsubscribe()

	// Reader: we don't expect messages, but we must read to handle the
	// browser's pings and close frames.
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	ping := time.NewTicker(30 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-closed:
			return
		case <-ping.C:
			if err := conn.Ping(nil); err != nil {
				return
			}
		case e := <-evs:
			b, _ := json.Marshal(e)
			if err := conn.WriteText(string(b)); err != nil {
				return
			}
		}
	}
}

// sameOrigin rejects WebSocket connections opened by pages from other
// sites (browsers send cookies and connect anywhere, so servers must check).
func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true // not a browser
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	if u.Host == r.Host {
		return true
	}
	host, _, _ := net.SplitHostPort(u.Host)
	return host == "localhost" || host == "127.0.0.1" // the Vite dev server
}

func logRequests(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		h.ServeHTTP(w, r)
		if r.URL.Path != "/ws" {
			log.Printf("%s %s (%s)", r.Method, r.URL.Path, time.Since(start).Round(time.Microsecond))
		}
	})
}
