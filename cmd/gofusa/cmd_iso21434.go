package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/SoundMatt/go-FuSa/iso21434"
)

//fusa:req REQ-CLI-ISO21434-001
func runISO21434(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa iso21434", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: gofusa iso21434 [flags]\n\n")
		fmt.Fprintf(stderr, "Generate an ISO 21434 cybersecurity compliance gap report.\n\n")
		fmt.Fprintf(stderr, "Flags:\n")
		fs.PrintDefaults()
	}

	var (
		dir    = fs.String("dir", "", "project root directory (default: current directory)")
		cal    = fs.String("cal", "CAL-1", "cybersecurity assurance level: CAL-1, CAL-2, CAL-3, CAL-4")
		format = fs.String("format", "text", "output format: text, json")
		output = fs.String("output", "", "write report to file (default: stdout)")
	)
	if err := fs.Parse(args); err != nil {
		return 1
	}

	projectRoot := *dir
	if projectRoot == "" {
		var err error
		projectRoot, err = os.Getwd()
		if err != nil {
			fmt.Fprintf(stderr, "gofusa iso21434: get working directory: %v\n", err)
			return 1
		}
	}

	_ = filepath.Base(projectRoot) // ensure path is valid

	rep, err := iso21434.Assess(projectRoot, *cal)
	if err != nil {
		fmt.Fprintf(stderr, "gofusa iso21434: assess: %v\n", err)
		return 1
	}

	w := stdout
	if *output != "" {
		f, ferr := os.Create(*output)
		if ferr != nil {
			fmt.Fprintf(stderr, "gofusa iso21434: create %s: %v\n", *output, ferr)
			return 1
		}
		defer func() { _ = f.Close() }()
		w = f
	}

	if err := iso21434.Render(w, rep, *format); err != nil {
		fmt.Fprintf(stderr, "gofusa iso21434: render: %v\n", err)
		return 1
	}

	if *output != "" {
		fmt.Fprintf(stdout, "ISO 21434 gap report written to %s (%d gaps)\n", *output, rep.Gap)
	}

	if rep.Gap > 0 {
		return 1
	}
	return 0
}
