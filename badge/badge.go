// Package badge generates Shields.io-compatible SVG status badges for go-FuSa reports.
package badge

import (
	"fmt"
	"io"
)

// Status represents the overall check result.
type Status int

const (
	StatusPass Status = iota
	StatusWarn
	StatusFail
)

// Badge holds the data needed to render a badge.
type Badge struct {
	Status   Status
	Errors   int
	Warnings int
	Version  string
}

// New returns a Badge derived from finding counts.
//
//fusa:req REQ-BADGE001
func New(errors, warnings int, version string) Badge {
	var s Status
	switch {
	case errors > 0:
		s = StatusFail
	case warnings > 0:
		s = StatusWarn
	default:
		s = StatusPass
	}
	return Badge{Status: s, Errors: errors, Warnings: warnings, Version: version}
}

// Render writes the badge as a self-contained SVG to w.
//
//fusa:req REQ-BADGE002
func Render(w io.Writer, b Badge) error {
	label := "go-fusa"
	msg, color := statusText(b)
	_, err := fmt.Fprint(w, svg(label, msg, color))
	return err
}

func statusText(b Badge) (string, string) {
	switch b.Status {
	case StatusFail:
		return fmt.Sprintf("failing (%d errors)", b.Errors), "#e05d44"
	case StatusWarn:
		return fmt.Sprintf("warnings (%d)", b.Warnings), "#dfb317"
	default:
		return "passing", "#4c1"
	}
}

// svg returns a minimal flat Shields.io-style badge SVG.
// Label width ~60px, message width varies with text length.
func svg(label, message, color string) string {
	lw := 60
	mw := len(message)*7 + 10
	total := lw + mw
	mx := lw + mw/2

	return fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="20">
  <linearGradient id="s" x2="0" y2="100%%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <rect rx="3" width="%d" height="20" fill="#555"/>
  <rect rx="3" x="%d" width="%d" height="20" fill="%s"/>
  <rect rx="3" width="%d" height="20" fill="url(#s)"/>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
    <text x="31" y="15" fill="#010101" fill-opacity=".3">%s</text>
    <text x="31" y="14">%s</text>
    <text x="%d" y="15" fill="#010101" fill-opacity=".3">%s</text>
    <text x="%d" y="14">%s</text>
  </g>
</svg>`, total, total, lw, mw, color, total, label, label, mx, message, mx, message)
}
