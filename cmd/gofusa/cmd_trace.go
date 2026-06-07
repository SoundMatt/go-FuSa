package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/SoundMatt/go-FuSa/trace"
)

func runTrace(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa trace", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: gofusa trace [flags]\n\n")
		fmt.Fprintf(stderr, "Show the requirements traceability matrix.\n\n")
		fmt.Fprintf(stderr, "Flags:\n")
		fs.PrintDefaults()
	}

	var (
		dir    = fs.String("dir", "", "project root directory (default: current directory)")
		format = fs.String("format", "text", "output format: text or json")
		output = fs.String("output", "", "write output to file (default: stdout)")
	)
	if err := fs.Parse(args); err != nil {
		return 1
	}

	projectRoot := *dir
	if projectRoot == "" {
		var err error
		projectRoot, err = os.Getwd()
		if err != nil {
			fmt.Fprintf(stderr, "gofusa trace: get working directory: %v\n", err)
			return 1
		}
	}

	matrix, err := trace.Build(projectRoot)
	if err != nil {
		fmt.Fprintf(stderr, "gofusa trace: %v\n", err)
		return 1
	}

	w := stdout
	if *output != "" {
		f, err := os.Create(*output)
		if err != nil {
			fmt.Fprintf(stderr, "gofusa trace: create output: %v\n", err)
			return 1
		}
		defer func() { _ = f.Close() }()
		w = f
	}

	if err := trace.Render(w, matrix, *format); err != nil {
		fmt.Fprintf(stderr, "gofusa trace: render: %v\n", err)
		return 1
	}
	return 0
}
