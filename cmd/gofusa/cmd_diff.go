package main

import (
	"flag"
	"fmt"
	"io"

	"github.com/SoundMatt/go-FuSa/diff"
)

//fusa:req REQ-CLI-DIFF001
func runDiff(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa diff", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: gofusa diff [flags] <baseline.json> <current.json>\n\n")
		fmt.Fprintf(stderr, "Compare two gofusa check --format json report files.\n")
		fmt.Fprintf(stderr, "Exits 1 if any new findings were introduced.\n\n")
		fmt.Fprintf(stderr, "Flags:\n")
		fs.PrintDefaults()
	}

	format := fs.String("format", "text", "output format: text or json")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if fs.NArg() != 2 {
		fs.Usage()
		return 1
	}

	baseline, err := diff.LoadReport(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "gofusa diff: %v\n", err)
		return 1
	}
	current, err := diff.LoadReport(fs.Arg(1))
	if err != nil {
		fmt.Fprintf(stderr, "gofusa diff: %v\n", err)
		return 1
	}

	d := diff.Compare(baseline, current)
	if err := diff.Render(stdout, d, *format); err != nil {
		fmt.Fprintf(stderr, "gofusa diff: %v\n", err)
		return 1
	}
	if len(d.Introduced) > 0 {
		return 1
	}
	return 0
}
