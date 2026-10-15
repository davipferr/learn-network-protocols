// learn-network-protocols shows how network protocols work under the hood.
//
//	go run .                     list the demos
//	go run . tcp                 run one demo in the terminal
//	go run . dns -name go.dev -type MX
//	go run . all                 run every demo
//	go run . serve               open the visual UI at http://localhost:8080
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/davipferr/learn-network-protocols/internal/console"
	"github.com/davipferr/learn-network-protocols/internal/demo"
	_ "github.com/davipferr/learn-network-protocols/internal/demos" // registers every demo
	"github.com/davipferr/learn-network-protocols/internal/events"
	"github.com/davipferr/learn-network-protocols/internal/server"
	"github.com/davipferr/learn-network-protocols/internal/webui"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	args := os.Args[1:]
	if len(args) == 0 || args[0] == "list" || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		usage()
		return
	}

	var err error
	switch args[0] {
	case "serve":
		err = serve(ctx, args[1:])
	case "all":
		err = runAll(ctx, args[1:])
	default:
		d := demo.Get(args[0])
		if d == nil {
			fmt.Fprintf(os.Stderr, "unknown demo %q\n\n", args[0])
			usage()
			os.Exit(2)
		}
		err = runOne(ctx, d, args[1:])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Println("learn-network-protocols: see how network protocols work under the hood")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  learn-network-protocols <demo> [flags]   run a demo in the terminal")
	fmt.Println("  learn-network-protocols all              run every demo")
	fmt.Println("  learn-network-protocols serve [-addr]    open the visual UI in the browser")
	fmt.Println()
	group := ""
	for _, d := range demo.All() {
		if d.Group != group {
			group = d.Group
			fmt.Printf("%s:\n", group)
		}
		fmt.Printf("  %-12s %s\n", d.ID, d.Title)
	}
	fmt.Println()
	fmt.Println("Run `learn-network-protocols <demo> -h` to see a demo's flags.")
}

// runOne parses the demo's params as flags and prints its events.
func runOne(ctx context.Context, d *demo.Demo, args []string) error {
	fs := flag.NewFlagSet(d.ID, flag.ExitOnError)
	values := map[string]*string{}
	for _, p := range d.Params {
		help := p.Help
		if len(p.Options) > 0 {
			help += " (" + strings.Join(p.Options, "|") + ")"
		}
		values[p.Name] = fs.String(p.Name, p.Default, help)
	}
	maxBytes := fs.Int("bytes", 256, "max bytes of each payload to hexdump")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "%s\n%s\n\nFlags:\n", d.Title, d.Summary)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	params := map[string]string{}
	for k, v := range values {
		params[k] = *v
	}
	return runPrinted(ctx, d, params, *maxBytes)
}

func runAll(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("all", flag.ExitOnError)
	maxBytes := fs.Int("bytes", 128, "max bytes of each payload to hexdump")
	fs.Parse(args)
	var failed []string
	for _, d := range demo.All() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := runPrinted(ctx, d, nil, *maxBytes); err != nil {
			failed = append(failed, d.ID)
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("demos with errors: %s", strings.Join(failed, ", "))
	}
	return nil
}

func runPrinted(ctx context.Context, d *demo.Demo, params map[string]string, maxBytes int) error {
	bus := events.NewBus()
	evs, unsubscribe := bus.Subscribe(1 << 16)
	printer := console.NewPrinter(os.Stdout, maxBytes)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for e := range evs {
			printer.Print(e)
		}
	}()
	err := demo.Run(ctx, bus, demo.NewRunID(), d, params)
	unsubscribe()
	<-done
	if err == nil && len(d.Lesson) > 0 {
		fmt.Println("\nKey takeaways:")
		for _, l := range d.Lesson {
			fmt.Println("  •", l)
		}
	}
	return err
}

func serve(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", "localhost:8080", "address to listen on")
	fs.Parse(args)

	bus := events.NewBus()
	srv := &http.Server{
		Addr:              *addr,
		Handler:           server.New(bus, webui.FS()).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return err
	}
	log.Printf("UI ready at http://%s", ln.Addr())

	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		srv.Shutdown(shutdown)
	}()
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
