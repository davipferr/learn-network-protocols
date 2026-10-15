package demos

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/davipferr/learn-network-protocols/internal/demo"
	"github.com/davipferr/learn-network-protocols/internal/events"
	"github.com/davipferr/learn-network-protocols/internal/httpraw"
	"github.com/davipferr/learn-network-protocols/internal/wire"
)

func init() {
	demo.Register(&demo.Demo{
		ID:      "rest",
		Title:   "REST API with net/http",
		Order:   4,
		Group:   "The Web",
		Summary: "A JSON CRUD API built only with the standard library's ServeMux (Go 1.22+ method and wildcard patterns), exercised call by call.",
		Actors:  []string{"client", "server"},
		Lesson: []string{
			"REST maps operations onto HTTP: the URL names a resource, the method says what to do with it.",
			"POST creates (201 + Location), GET reads (200), PUT replaces (200), DELETE removes (204).",
			"GET, PUT and DELETE are idempotent: repeating them leaves the server in the same state. POST is not.",
			"Status codes carry meaning: 404 the resource doesn't exist, 405 the method isn't allowed, 400 bad input.",
			"Since Go 1.22, http.ServeMux understands patterns like \"GET /books/{id}\", so no framework is needed.",
		},
		Params: []demo.Param{
			{Name: "title", Default: "The Go Programming Language", Help: "title of the first book created"},
		},
		Run: runREST,
	})
}

type book struct {
	ID     int    `json:"id,omitempty"`
	Title  string `json:"title"`
	Author string `json:"author"`
}

type bookStore struct {
	mu     sync.Mutex
	nextID int
	books  map[int]book
}

func (s *bookStore) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /books", s.list)
	mux.HandleFunc("POST /books", s.create)
	mux.HandleFunc("GET /books/{id}", s.get)
	mux.HandleFunc("PUT /books/{id}", s.replace)
	mux.HandleFunc("DELETE /books/{id}", s.remove)
	return mux
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, _ := json.Marshal(v)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	w.WriteHeader(status)
	w.Write(b)
}

func (s *bookStore) list(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []book{}
	for id := 1; id < s.nextID; id++ {
		if b, ok := s.books[id]; ok {
			out = append(out, b)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *bookStore) create(w http.ResponseWriter, r *http.Request) {
	var b book
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil || b.Title == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "body must be JSON with a non-empty title"})
		return
	}
	s.mu.Lock()
	b.ID = s.nextID
	s.nextID++
	s.books[b.ID] = b
	s.mu.Unlock()
	w.Header().Set("Location", fmt.Sprintf("/books/%d", b.ID))
	writeJSON(w, http.StatusCreated, b)
}

func (s *bookStore) lookup(w http.ResponseWriter, r *http.Request) (int, bool) {
	id, err := strconv.Atoi(r.PathValue("id")) // {id} from the pattern
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id must be a number"})
		return 0, false
	}
	if _, ok := s.books[id]; !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "book not found"})
		return 0, false
	}
	return id, true
}

func (s *bookStore) get(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id, ok := s.lookup(w, r); ok {
		writeJSON(w, http.StatusOK, s.books[id])
	}
}

func (s *bookStore) replace(w http.ResponseWriter, r *http.Request) {
	var b book
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil || b.Title == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "body must be JSON with a non-empty title"})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if id, ok := s.lookup(w, r); ok {
		b.ID = id
		s.books[id] = b
		writeJSON(w, http.StatusOK, b)
	}
}

func (s *bookStore) remove(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id, ok := s.lookup(w, r); ok {
		delete(s.books, id)
		w.WriteHeader(http.StatusNoContent)
	}
}

func runREST(ctx context.Context, em *events.Emitter, p demo.Params) error {
	em.Step("1. Routes", "The whole API is five lines of routing:\n"+
		"  mux.HandleFunc(\"GET /books\", list)\n"+
		"  mux.HandleFunc(\"POST /books\", create)\n"+
		"  mux.HandleFunc(\"GET /books/{id}\", get)\n"+
		"  mux.HandleFunc(\"PUT /books/{id}\", replace)\n"+
		"  mux.HandleFunc(\"DELETE /books/{id}\", remove)\n"+
		"Handlers read the wildcard with r.PathValue(\"id\"). The listener is tapped so you can see the raw HTTP bytes of every call.")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	// Tap the server side of each connection and cut the byte stream into
	// complete HTTP messages before emitting them.
	tapped := wire.NewListener(ln, func(net.Conn) wire.Tap {
		var mu sync.Mutex
		var in, out []byte
		return func(dir wire.Dir, b []byte) {
			mu.Lock()
			defer mu.Unlock()
			if dir == wire.In {
				var msgs [][]byte
				msgs, in = httpraw.Split(append(in, b...))
				for _, m := range msgs {
					em.Send("client", "server", "http/1.1", firstLine(m), m, httpraw.Fields(m), "")
				}
			} else {
				var msgs [][]byte
				msgs, out = httpraw.Split(append(out, b...))
				for _, m := range msgs {
					em.Send("server", "client", "http/1.1", firstLine(m), m, httpraw.Fields(m), "")
				}
			}
		}
	})
	store := &bookStore{nextID: 1, books: map[int]book{}}
	srv := &http.Server{Handler: store.routes(), ReadHeaderTimeout: 5 * time.Second}
	go srv.Serve(tapped)
	defer srv.Close()
	base := "http://" + ln.Addr().String()
	em.State("server", "serving on "+base, "")

	tr := &http.Transport{}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}

	call := func(step, why, method, path string, body any) error {
		em.Step(step, why)
		var rd io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		}
		req, err := http.NewRequestWithContext(ctx, method, base+path, rd)
		if err != nil {
			return err
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		time.Sleep(20 * time.Millisecond) // let the tap flush before the next step
		em.Info("client", fmt.Sprintf("%s %s -> %s", method, path, resp.Status), string(b))
		return nil
	}

	steps := []struct {
		step, why, method, path string
		body                    any
	}{
		{"2. Create: POST /books", "POST to the collection creates a new member. The server picks the id and answers 201 Created with a Location header pointing at the new resource.", "POST", "/books", book{Title: p.String("title"), Author: "Donovan & Kernighan"}},
		{"3. Create another", "POST is not idempotent: sending it again creates another book.", "POST", "/books", book{Title: "Network Programming with Go", Author: "Jan Newmarch"}},
		{"4. Read the collection: GET /books", "GET is safe (changes nothing) and cacheable.", "GET", "/books", nil},
		{"5. Read one: GET /books/1", "{id} in the pattern captures \"1\".", "GET", "/books/1", nil},
		{"6. Replace: PUT /books/1", "PUT sends the full new representation. It is idempotent: doing it twice has the same effect as once.", "PUT", "/books/1", book{Title: "The Go Programming Language (2nd ed.)", Author: "Donovan & Kernighan"}},
		{"7. Delete: DELETE /books/2", "204 No Content: success, and nothing to send back.", "DELETE", "/books/2", nil},
		{"8. Read what was deleted", "404 Not Found.", "GET", "/books/2", nil},
		{"9. A method the route doesn't support", "PATCH isn't registered for /books/{id}. ServeMux answers 405 Method Not Allowed by itself and lists the allowed methods in the Allow header.", "PATCH", "/books/1", map[string]string{"title": "x"}},
		{"10. Invalid input", "Validation errors are the client's fault: 400 Bad Request.", "POST", "/books", map[string]string{"author": "nobody"}},
	}
	for _, s := range steps {
		if err := call(s.step, s.why, s.method, s.path, s.body); err != nil {
			return err
		}
	}
	return nil
}

func firstLine(b []byte) string {
	if i := bytes.Index(b, []byte("\r\n")); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}
