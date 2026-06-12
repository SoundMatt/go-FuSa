package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/slsa"
)

//fusa:req REQ-CLI-SLSA-001
func runSLSA(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa slsa", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: gofusa slsa [flags]\n\n")
		fmt.Fprintf(stderr, "Generate a SLSA v1.0 supply-chain integrity gap report.\n\n")
		fmt.Fprintf(stderr, "Flags:\n")
		fs.PrintDefaults()
	}

	var (
		dir    = fs.String("dir", "", "project root directory (default: current directory)")
		level  = fs.String("level", "L2", "SLSA level: L1, L2, L3, L4")
		format = fs.String("format", "text", "output format: text, json")
		output = fs.String("output", "", "write report to file (default: stdout)")
	)
	if code := parseFlags(fs, args); code != 0 {
		return code
	}

	validLevels := map[string]bool{"L1": true, "L2": true, "L3": true, "L4": true}
	if !validLevels[*level] {
		fmt.Fprintf(stderr, "gofusa slsa: unknown level %q (must be L1, L2, L3, or L4)\n", *level)
		return fusa.ExitUsage
	}

	projectRoot := *dir
	if projectRoot == "" {
		var err error
		projectRoot, err = os.Getwd()
		if err != nil {
			fmt.Fprintf(stderr, "gofusa slsa: get working directory: %v\n", err)
			return fusa.ExitRuntime
		}
	}

	project := filepath.Base(projectRoot)

	rep, err := slsa.Assess(projectRoot, project, slsa.Level(*level))
	if err != nil {
		fmt.Fprintf(stderr, "gofusa slsa: assess: %v\n", err)
		return fusa.ExitRuntime
	}

	w := stdout
	if *output != "" {
		f, ferr := os.Create(*output)
		if ferr != nil {
			fmt.Fprintf(stderr, "gofusa slsa: create %s: %v\n", *output, ferr)
			return fusa.ExitRuntime
		}
		defer func() { _ = f.Close() }()
		w = f
	}

	if err := slsa.Render(w, rep, *format); err != nil {
		fmt.Fprintf(stderr, "gofusa slsa: render: %v\n", err)
		return fusa.ExitRuntime
	}

	if *output != "" {
		fmt.Fprintf(stdout, "SLSA gap report written to %s (%d gaps)\n", *output, rep.Gap)
	}

	if rep.Gap > 0 {
		return fusa.ExitGateFail
	}
	return fusa.ExitOK
}
