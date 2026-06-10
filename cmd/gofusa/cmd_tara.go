package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/config"
	"github.com/SoundMatt/go-FuSa/cyber"
	"github.com/SoundMatt/go-FuSa/tara"
)

// runTara generates a TARA from CYBER findings per ISO 21434 Chapter 9.
//
//fusa:req REQ-CLI019
func runTara(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa tara", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: gofusa tara [flags]\n\n")
		fmt.Fprintf(stderr, "Generate a Threat Analysis and Risk Assessment (TARA) per ISO 21434 Chapter 9.\n")
		fmt.Fprintf(stderr, "Runs CYBER rules to identify threats then maps each finding to STRIDE/CWE/risk.\n\n")
		fmt.Fprintf(stderr, "Flags:\n")
		fs.PrintDefaults()
	}

	var (
		dir       = fs.String("dir", "", "project root directory (default: current directory)")
		outputDir = fs.String("output-dir", "", "output directory for tara.json and tara.md (default: project root)")
	)
	if code := parseFlags(fs, args); code != 0 {
		return code
	}

	projectRoot := *dir
	if projectRoot == "" {
		var err error
		projectRoot, err = os.Getwd()
		if err != nil {
			fmt.Fprintf(stderr, "gofusa tara: get working directory: %v\n", err)
			return fusa.ExitRuntime
		}
	}

	outDir := *outputDir
	if outDir == "" {
		outDir = projectRoot
	}

	cfg, err := config.Load(filepath.Join(projectRoot, ".fusa.json"))
	if err != nil && !errors.Is(err, fusa.ErrNoConfig) {
		fmt.Fprintf(stderr, "gofusa tara: load config: %v\n", err)
		return fusa.ExitRuntime
	}
	if cfg == nil {
		cfg = config.Default("", filepath.Base(projectRoot))
	}

	// Run CYBER scan to gather findings.
	cyberFindings, err := cyber.Scan(context.Background(), projectRoot, cfg)
	if err != nil {
		fmt.Fprintf(stderr, "gofusa tara: cyber scan: %v\n", err)
		return fusa.ExitRuntime
	}

	// Build TARA.
	report, err := tara.Scan(projectRoot, cyberFindings)
	if err != nil {
		fmt.Fprintf(stderr, "gofusa tara: build tara: %v\n", err)
		return fusa.ExitRuntime
	}

	// Write tara.json
	jsonPath := filepath.Join(outDir, tara.TARAFile)
	if err := writeFile(jsonPath, func(f io.Writer) error {
		return tara.Render(f, report, "json")
	}); err != nil {
		fmt.Fprintf(stderr, "gofusa tara: write %s: %v\n", jsonPath, err)
		return fusa.ExitRuntime
	}
	fmt.Fprintf(stdout, "TARA report written to %s\n", jsonPath)

	// Write tara.md
	mdPath := filepath.Join(outDir, tara.TARAMarkdownFile)
	if err := writeFile(mdPath, func(f io.Writer) error {
		return tara.Render(f, report, "markdown")
	}); err != nil {
		fmt.Fprintf(stderr, "gofusa tara: write %s: %v\n", mdPath, err)
		return fusa.ExitRuntime
	}
	fmt.Fprintf(stdout, "TARA markdown written to %s\n", mdPath)
	fmt.Fprintf(stdout, "Threats identified: %d\n", len(report.Entries))
	return fusa.ExitOK
}

func writeFile(path string, fn func(io.Writer) error) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return fn(f)
}
