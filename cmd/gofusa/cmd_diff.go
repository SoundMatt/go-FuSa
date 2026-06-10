package main

import (
	"flag"
	"fmt"
	"io"

	fusa "github.com/SoundMatt/go-FuSa"
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
	if code := parseFlags(fs, args); code != 0 {
		return code
	}
	if fs.NArg() != 2 {
		fs.Usage()
		return fusa.ExitRuntime
	}

	baseline, err := diff.LoadReport(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "gofusa diff: %v\n", err)
		return fusa.ExitRuntime
	}
	current, err := diff.LoadReport(fs.Arg(1))
	if err != nil {
		fmt.Fprintf(stderr, "gofusa diff: %v\n", err)
		return fusa.ExitRuntime
	}

	d := diff.Compare(baseline, current)
	if err := diff.Render(stdout, d, *format); err != nil {
		fmt.Fprintf(stderr, "gofusa diff: %v\n", err)
		return fusa.ExitRuntime
	}
	if len(d.Introduced) > 0 {
		return fusa.ExitRuntime
	}
	return fusa.ExitOK
}
