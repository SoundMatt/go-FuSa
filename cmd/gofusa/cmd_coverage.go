package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/SoundMatt/go-FuSa/coverage"
)

//fusa:req REQ-CLI-COV001
func runCoverage(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa coverage", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: gofusa coverage [flags] [coverage.out]\n\n")
		fmt.Fprintf(stderr, "Produce a DO-178C structural coverage report from a Go coverage profile.\n")
		fmt.Fprintf(stderr, "Generate coverage.out with: go test -coverprofile=coverage.out ./...\n\n")
		fmt.Fprintf(stderr, "Flags:\n")
		fs.PrintDefaults()
	}

	var (
		dalFlag = fs.String("dal", "DAL-B", "design assurance level: DAL-A, DAL-B, DAL-C, DAL-D")
		format  = fs.String("format", "text", "output format: text or json")
		output  = fs.String("output", "", "write report to file (default: stdout)")
	)
	if err := fs.Parse(args); err != nil {
		return 1
	}

	profilePath := coverage.CoverageFile
	if fs.NArg() > 0 {
		profilePath = fs.Arg(0)
	} else if fs.NArg() == 0 {
		// Try current directory
		if _, err := os.Stat(profilePath); err != nil {
			// Try looking in current working directory
			cwd, _ := os.Getwd()
			profilePath = filepath.Join(cwd, coverage.CoverageFile)
		}
	}

	dal := coverage.DAL(*dalFlag)
	switch dal {
	case coverage.DALA, coverage.DALB, coverage.DALC, coverage.DALD:
	default:
		fmt.Fprintf(stderr, "gofusa coverage: invalid --dal %q\n", *dalFlag)
		return 1
	}

	rep, err := coverage.BuildFromFile(profilePath, dal)
	if err != nil {
		fmt.Fprintf(stderr, "gofusa coverage: %v\n", err)
		fmt.Fprintf(stderr, "Tip: generate a profile with: go test -coverprofile=%s ./...\n", coverage.CoverageFile)
		return 1
	}

	w := stdout
	if *output != "" {
		f, err := os.Create(*output)
		if err != nil {
			fmt.Fprintf(stderr, "gofusa coverage: create output: %v\n", err)
			return 1
		}
		defer func() { _ = f.Close() }()
		w = f
	}

	if err := coverage.Render(w, rep, *format); err != nil {
		fmt.Fprintf(stderr, "gofusa coverage: render: %v\n", err)
		return 1
	}
	return 0
}
