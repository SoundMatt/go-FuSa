package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/badge"
	"github.com/SoundMatt/go-FuSa/report"
)

//fusa:req REQ-CLI-BADGE001
func runBadge(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa badge", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: gofusa badge [flags] [report.json]\n\n")
		fmt.Fprintf(stderr, "Generate an SVG status badge. Reads a gofusa check --format json report,\n")
		fmt.Fprintf(stderr, "or reads from stdin if no file is given.\n\n")
		fmt.Fprintf(stderr, "Flags:\n")
		fs.PrintDefaults()
	}
	output := fs.String("output", "", "write SVG to file (default: stdout)")
	if err := fs.Parse(args); err != nil {
		return 1
	}

	var r report.Report
	switch fs.NArg() {
	case 0:
		if err := json.NewDecoder(os.Stdin).Decode(&r); err != nil {
			fmt.Fprintf(stderr, "gofusa badge: read stdin: %v\n", err)
			return 1
		}
	case 1:
		data, err := os.ReadFile(fs.Arg(0))
		if err != nil {
			fmt.Fprintf(stderr, "gofusa badge: %v\n", err)
			return 1
		}
		if err := json.Unmarshal(data, &r); err != nil {
			fmt.Fprintf(stderr, "gofusa badge: parse report: %v\n", err)
			return 1
		}
	default:
		fs.Usage()
		return 1
	}

	errors, warnings := 0, 0
	for _, f := range r.Findings {
		switch f.Severity {
		case fusa.SeverityError:
			errors++
		case fusa.SeverityWarning:
			warnings++
		}
	}

	b := badge.New(errors, warnings, fusa.Version)
	w := stdout
	if *output != "" {
		f, err := os.Create(*output)
		if err != nil {
			fmt.Fprintf(stderr, "gofusa badge: create output: %v\n", err)
			return 1
		}
		defer func() { _ = f.Close() }()
		w = f
	}
	if err := badge.Render(w, b); err != nil {
		fmt.Fprintf(stderr, "gofusa badge: render: %v\n", err)
		return 1
	}
	return 0
}
