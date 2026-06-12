package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/iec62443"
)

//fusa:req REQ-CLI-IEC62443-001
func runIEC62443(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa iec62443", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: gofusa iec62443 [flags]\n\n")
		fmt.Fprintf(stderr, "Generate an IEC 62443-4-2 IACS cybersecurity gap report.\n\n")
		fmt.Fprintf(stderr, "Flags:\n")
		fs.PrintDefaults()
	}

	var (
		dir    = fs.String("dir", "", "project root directory (default: current directory)")
		sl     = fs.String("sl", "SL-2", "Security Level: SL-1, SL-2, SL-3, SL-4")
		format = fs.String("format", "text", "output format: text, json")
		output = fs.String("output", "", "write report to file (default: stdout)")
	)
	if code := parseFlags(fs, args); code != 0 {
		return code
	}

	validSLs := map[string]bool{"SL-1": true, "SL-2": true, "SL-3": true, "SL-4": true}
	if !validSLs[*sl] {
		fmt.Fprintf(stderr, "gofusa iec62443: unknown Security Level %q (must be SL-1, SL-2, SL-3, or SL-4)\n", *sl)
		return fusa.ExitUsage
	}

	projectRoot := *dir
	if projectRoot == "" {
		var err error
		projectRoot, err = os.Getwd()
		if err != nil {
			fmt.Fprintf(stderr, "gofusa iec62443: get working directory: %v\n", err)
			return fusa.ExitRuntime
		}
	}

	project := filepath.Base(projectRoot)

	rep, err := iec62443.Assess(projectRoot, project, iec62443.SL(*sl))
	if err != nil {
		fmt.Fprintf(stderr, "gofusa iec62443: assess: %v\n", err)
		return fusa.ExitRuntime
	}

	w := stdout
	if *output != "" {
		f, ferr := os.Create(*output)
		if ferr != nil {
			fmt.Fprintf(stderr, "gofusa iec62443: create %s: %v\n", *output, ferr)
			return fusa.ExitRuntime
		}
		defer func() { _ = f.Close() }()
		w = f
	}

	if err := iec62443.Render(w, rep, *format); err != nil {
		fmt.Fprintf(stderr, "gofusa iec62443: render: %v\n", err)
		return fusa.ExitRuntime
	}

	if *output != "" {
		fmt.Fprintf(stdout, "IEC 62443 gap report written to %s (%d gaps)\n", *output, rep.Gap)
	}

	if rep.Gap > 0 {
		return fusa.ExitGateFail
	}
	return fusa.ExitOK
}
