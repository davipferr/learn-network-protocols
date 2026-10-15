// Package console renders events in the terminal (CLI mode).
package console

import (
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/davipferr/learn-network-protocols/internal/events"
)

type Printer struct {
	w        io.Writer
	color    bool
	maxBytes int // hexdump at most this many bytes per event
}

func NewPrinter(w io.Writer, maxBytes int) *Printer {
	_, noColor := os.LookupEnv("NO_COLOR")
	if f, ok := w.(*os.File); ok {
		if st, err := f.Stat(); err == nil && st.Mode()&os.ModeCharDevice == 0 {
			noColor = true // output redirected to a file or pipe
		}
	}
	return &Printer{w: w, color: !noColor, maxBytes: maxBytes}
}

const (
	reset   = "\x1b[0m"
	bold    = "\x1b[1m"
	dim     = "\x1b[2m"
	red     = "\x1b[31m"
	green   = "\x1b[32m"
	yellow  = "\x1b[33m"
	blue    = "\x1b[34m"
	magenta = "\x1b[35m"
	cyan    = "\x1b[36m"
)

func (p *Printer) c(code, s string) string {
	if !p.color {
		return s
	}
	return code + s + reset
}

func (p *Printer) Print(e events.Event) {
	w := p.w
	t := p.c(dim, fmt.Sprintf("%8.1fms", e.ElapsedMs))
	switch e.Kind {
	case events.KindStart:
		fmt.Fprintf(w, "\n%s\n%s\n", p.c(bold+cyan, "■ "+e.Title), p.c(dim, e.Detail))
	case events.KindStep:
		fmt.Fprintf(w, "\n%s %s\n", p.c(bold+yellow, "── "+e.Title+" "), p.c(yellow, strings.Repeat("─", max(0, 60-len(e.Title)))))
		if e.Detail != "" {
			fmt.Fprintln(w, indent(wrap(e.Detail, 88), "   "))
		}
	case events.KindInfo, events.KindState:
		tag := "info "
		col := blue
		if e.Kind == events.KindState {
			tag, col = "state", magenta
		}
		fmt.Fprintf(w, "%s %s %s %s\n", t, p.c(col, tag), p.c(bold, "["+e.Actor+"]"), e.Title)
		if e.Detail != "" {
			fmt.Fprintln(w, indent(wrap(e.Detail, 84), "                    "))
		}
	case events.KindError:
		fmt.Fprintf(w, "%s %s %s %s\n", t, p.c(red, "error"), p.c(bold, "["+e.Actor+"]"), p.c(red, e.Title))
		if e.Detail != "" {
			fmt.Fprintln(w, indent(wrap(e.Detail, 84), "                    "))
		}
	case events.KindSend:
		arrow := "──▶"
		switch {
		case e.Dropped:
			arrow = "──✕"
		case e.Simulated:
			arrow = "┄┄▶"
		}
		layer := ""
		if e.Layer != "" {
			layer = p.c(dim, "("+e.Layer+")")
		}
		size := ""
		if e.Size > 0 {
			size = p.c(dim, fmt.Sprintf(" %d bytes", e.Size))
		}
		fmt.Fprintf(w, "%s %s %s %s %s %s %s%s\n", t, p.c(green, "send "), p.c(bold, e.From), p.c(green, arrow), p.c(bold, e.To), layer, e.Title, size)
		if e.Detail != "" {
			fmt.Fprintln(w, indent(wrap(e.Detail, 84), "                    "))
		}
		if len(e.Bytes) > 0 {
			fmt.Fprintln(w, indent(p.hexdump(e.Bytes, e.Size), "                    "))
		}
		for _, f := range e.Fields {
			if f.Start >= p.maxBytes {
				break
			}
			fmt.Fprintf(w, "                    %s %-28s %s\n", p.c(dim, fmt.Sprintf("[%4d:%-4d]", f.Start, f.End)), f.Name, p.c(cyan, f.Value))
		}
	case events.KindMetric:
		var parts []string
		for k, v := range e.Metrics {
			parts = append(parts, fmt.Sprintf("%s=%g", k, v))
		}
		slices.Sort(parts)
		fmt.Fprintf(w, "%s %s %s %s\n", t, p.c(dim, "metric"), e.Title, p.c(dim, strings.Join(parts, " ")))
	case events.KindEnd:
		fmt.Fprintf(w, "\n%s %s\n", p.c(bold+cyan, "■ "+e.Title), e.Detail)
	}
}

func (p *Printer) hexdump(b []byte, size int) string {
	var sb strings.Builder
	n := min(len(b), p.maxBytes)
	for off := 0; off < n; off += 16 {
		end := min(off+16, n)
		fmt.Fprintf(&sb, "%s  ", p.c(dim, fmt.Sprintf("%04x", off)))
		for i := off; i < off+16; i++ {
			if i < end {
				fmt.Fprintf(&sb, "%02x ", b[i])
			} else {
				sb.WriteString("   ")
			}
			if i == off+7 {
				sb.WriteByte(' ')
			}
		}
		sb.WriteString(" |")
		for _, c := range b[off:end] {
			if c >= 32 && c < 127 {
				sb.WriteByte(c)
			} else {
				sb.WriteByte('.')
			}
		}
		sb.WriteString("|\n")
	}
	if size > n {
		sb.WriteString(p.c(dim, fmt.Sprintf("… %d more bytes (use -bytes to show more)\n", size-n)))
	}
	return sb.String()
}

func indent(s, pad string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		lines[i] = pad + l
	}
	return strings.Join(lines, "\n")
}

// wrap breaks long paragraphs at word boundaries, keeping existing newlines.
func wrap(s string, width int) string {
	var out []string
	for _, para := range strings.Split(s, "\n") {
		lead := para[:len(para)-len(strings.TrimLeft(para, " "))] // keep code indentation
		line := lead
		for _, word := range strings.Fields(para) {
			if line != lead && len(line)+1+len(word) > width {
				out = append(out, line)
				line = lead + word
				continue
			}
			if line != lead {
				line += " "
			}
			line += word
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}
