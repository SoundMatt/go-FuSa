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
	"github.com/SoundMatt/go-FuSa/fmea"
)

// runFmea generates the dFMEA report for the project.
//
//fusa:req REQ-CLI013
func runFmea(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa fmea", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: gofusa fmea [flags]\n\n")
		fmt.Fprintf(stderr, "Generate a Design Failure Mode and Effects Analysis (dFMEA) table\n")
		fmt.Fprintf(stderr, "from exported Go functions, annotated with //fusa:req traceability.\n\n")
		fmt.Fprintf(stderr, "Generates fmea.json and fmea.csv in the output directory.\n\n")
		fmt.Fprintf(stderr, "Flags:\n")
		fs.PrintDefaults()
	}

	var (
		dir       = fs.String("dir", "", "project root directory (default: current directory)")
		outputDir = fs.String("output-dir", "", "output directory (default: project root)")
		withCyber = fs.Bool("cyber", false, "enrich FMEA entries with CYBER findings (adds CyberRisks column)")
	)
	if err := fs.Parse(args); err != nil {
		return 1
	}

	projectRoot := *dir
	if projectRoot == "" {
		var err error
		projectRoot, err = os.Getwd()
		if err != nil {
			fmt.Fprintf(stderr, "gofusa fmea: get working directory: %v\n", err)
			return 1
		}
	}

	outDir := *outputDir
	if outDir == "" {
		outDir = projectRoot
	}

	report, err := fmea.Scan(projectRoot)
	if err != nil {
		fmt.Fprintf(stderr, "gofusa fmea: scan: %v\n", err)
		return 1
	}

	if *withCyber {
		cfg, cfgErr := config.Load(projectRoot)
		if cfgErr != nil && !errors.Is(cfgErr, fusa.ErrNoConfig) {
			fmt.Fprintf(stderr, "gofusa fmea: load config: %v\n", cfgErr)
			return 1
		}
		if cfg == nil {
			cfg = config.Default("", filepath.Base(projectRoot))
		}
		cyberFindings, cyberErr := cyber.Scan(context.Background(), projectRoot, cfg)
		if cyberErr != nil {
			fmt.Fprintf(stderr, "gofusa fmea: cyber scan: %v\n", cyberErr)
			return 1
		}
		fmea.EnrichWithCyber(report, cyberFindings)
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fmt.Fprintf(stderr, "gofusa fmea: mkdir: %v\n", err)
		return 1
	}

	// Write fmea.json
	jsonPath := filepath.Join(outDir, fmea.FMEAFile)
	if err := writeFmea(jsonPath, report, "json"); err != nil {
		fmt.Fprintf(stderr, "gofusa fmea: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "FMEA report written to %s\n", jsonPath)

	// Write fmea.csv
	csvPath := filepath.Join(outDir, fmea.FMEACSVFile)
	if err := writeFmea(csvPath, report, "csv"); err != nil {
		fmt.Fprintf(stderr, "gofusa fmea: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "FMEA report written to %s\n", csvPath)

	// Print summary
	high, med, low := countBySeverity(report)
	fmt.Fprintf(stdout, "\nEntries: %d  (high: %d  medium: %d  low: %d)\n",
		len(report.Entries), high, med, low)

	return 0
}

func writeFmea(path string, r *fmea.Report, format string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	if err := fmea.Render(f, r, format); err != nil {
		return fmt.Errorf("render %s: %w", path, err)
	}
	return nil
}

func countBySeverity(r *fmea.Report) (high, med, low int) {
	for _, e := range r.Entries {
		switch e.Severity {
		case fmea.SeverityHigh:
			high++
		case fmea.SeverityMedium:
			med++
		default:
			low++
		}
	}
	return
}
