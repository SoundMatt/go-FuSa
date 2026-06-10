package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/iso26262"
)

//fusa:req REQ-CLI-ISO26262-001
func runISO26262(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa iso26262", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: gofusa iso26262 [flags]\n\n")
		fmt.Fprintf(stderr, "Generate an ISO 26262 Part 6 compliance gap report.\n\n")
		fmt.Fprintf(stderr, "Flags:\n")
		fs.PrintDefaults()
	}

	var (
		dir    = fs.String("dir", "", "project root directory (default: current directory)")
		asil   = fs.String("asil", "ASIL-B", "ASIL level: ASIL-A, ASIL-B, ASIL-C, ASIL-D")
		format = fs.String("format", "text", "output format: text, json")
		output = fs.String("output", "", "write report to file (default: stdout)")
	)
	if code := parseFlags(fs, args); code != 0 {
		return code
	}

	validASILs := map[string]bool{"ASIL-A": true, "ASIL-B": true, "ASIL-C": true, "ASIL-D": true}
	if !validASILs[*asil] {
		fmt.Fprintf(stderr, "gofusa iso26262: unknown ASIL level %q (must be ASIL-A, ASIL-B, ASIL-C, or ASIL-D)\n", *asil)
		return fusa.ExitUsage
	}

	projectRoot := *dir
	if projectRoot == "" {
		var err error
		projectRoot, err = os.Getwd()
		if err != nil {
			fmt.Fprintf(stderr, "gofusa iso26262: get working directory: %v\n", err)
			return fusa.ExitRuntime
		}
	}

	project := filepath.Base(projectRoot)

	rep, err := iso26262.Assess(projectRoot, project, iso26262.ASIL(*asil))
	if err != nil {
		fmt.Fprintf(stderr, "gofusa iso26262: assess: %v\n", err)
		return fusa.ExitRuntime
	}

	w := stdout
	if *output != "" {
		f, ferr := os.Create(*output)
		if ferr != nil {
			fmt.Fprintf(stderr, "gofusa iso26262: create %s: %v\n", *output, ferr)
			return fusa.ExitRuntime
		}
		defer func() { _ = f.Close() }()
		w = f
	}

	if err := iso26262.Render(w, rep, *format); err != nil {
		fmt.Fprintf(stderr, "gofusa iso26262: render: %v\n", err)
		return fusa.ExitRuntime
	}

	if *output == "" && *format == "text" {
		// summary already in render
	} else if *output != "" {
		fmt.Fprintf(stdout, "ISO 26262 gap report written to %s (%d gaps)\n", *output, rep.Gap)
	}

	if rep.Gap > 0 {
		return fusa.ExitGateFail
	}
	return fusa.ExitOK
}
