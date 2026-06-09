package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/SoundMatt/go-FuSa/iec61508"
)

//fusa:req REQ-CLI-IEC61508-001
func runIEC61508(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa iec61508", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: gofusa iec61508 [flags]\n\n")
		fmt.Fprintf(stderr, "Generate an IEC 61508 Parts 1-3 compliance gap report.\n\n")
		fmt.Fprintf(stderr, "Flags:\n")
		fs.PrintDefaults()
	}

	var (
		dir    = fs.String("dir", "", "project root directory (default: current directory)")
		sil    = fs.String("sil", "SIL-2", "SIL level: SIL-1, SIL-2, SIL-3, SIL-4")
		format = fs.String("format", "text", "output format: text, json")
		output = fs.String("output", "", "write report to file (default: stdout)")
	)
	if err := fs.Parse(args); err != nil {
		return 1
	}

	validSILs := map[string]bool{"SIL-1": true, "SIL-2": true, "SIL-3": true, "SIL-4": true}
	if !validSILs[*sil] {
		fmt.Fprintf(stderr, "gofusa iec61508: unknown SIL level %q (must be SIL-1, SIL-2, SIL-3, or SIL-4)\n", *sil)
		return 1
	}

	projectRoot := *dir
	if projectRoot == "" {
		var err error
		projectRoot, err = os.Getwd()
		if err != nil {
			fmt.Fprintf(stderr, "gofusa iec61508: get working directory: %v\n", err)
			return 1
		}
	}

	project := filepath.Base(projectRoot)

	rep, err := iec61508.Assess(projectRoot, project, iec61508.SIL(*sil))
	if err != nil {
		fmt.Fprintf(stderr, "gofusa iec61508: assess: %v\n", err)
		return 1
	}

	w := stdout
	if *output != "" {
		f, ferr := os.Create(*output)
		if ferr != nil {
			fmt.Fprintf(stderr, "gofusa iec61508: create %s: %v\n", *output, ferr)
			return 1
		}
		defer func() { _ = f.Close() }()
		w = f
	}

	if err := iec61508.Render(w, rep, *format); err != nil {
		fmt.Fprintf(stderr, "gofusa iec61508: render: %v\n", err)
		return 1
	}

	if *output != "" {
		fmt.Fprintf(stdout, "IEC 61508 gap report written to %s (%d gaps)\n", *output, rep.Gap)
	}

	if rep.Gap > 0 {
		return 1
	}
	return 0
}
