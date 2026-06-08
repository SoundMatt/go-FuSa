package main

import (
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/SoundMatt/go-FuSa/engine"
)

// runAnalyze runs only ANA* rules against the project root.
//
//fusa:req REQ-CLI009
func runAnalyze(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa analyze", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: gofusa analyze [flags]\n\n")
		fmt.Fprintf(stderr, "Run static analysis checks (ANA001–ANA004). Exits 1 on ERROR findings.\n\n")
		fmt.Fprintf(stderr, "Flags:\n")
		fs.PrintDefaults()
	}

	var (
		dir    = fs.String("dir", "", "project root directory (default: current directory)")
		format = fs.String("format", "", "output format: text or json (default: from config or text)")
		output = fs.String("output", "", "write report to file (default: stdout)")
		strict = fs.Bool("strict", false, "exit 1 on any WARNING or ERROR finding")
	)
	if err := fs.Parse(args); err != nil {
		return 1
	}

	return runFiltered(args[:0], stdout, stderr, "gofusa analyze", *dir, *format, *output, *strict,
		func(r engine.Rule) bool { return strings.HasPrefix(r.ID(), "ANA") })
}
