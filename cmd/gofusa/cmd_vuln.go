package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/SoundMatt/go-FuSa/vuln"
)

// runVuln scans go.mod dependencies against the OSV vulnerability database.
//
//fusa:req REQ-CLI015
func runVuln(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa vuln", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: gofusa vuln [flags]\n\n")
		fmt.Fprintf(stderr, "Scan go.mod dependencies against the OSV vulnerability database.\n")
		fmt.Fprintf(stderr, "Writes vuln.json to the output directory.\n\n")
		fmt.Fprintf(stderr, "Relevant standard: ISO 21434 §8.5 (vulnerability monitoring)\n\n")
		fmt.Fprintf(stderr, "Flags:\n")
		fs.PrintDefaults()
	}

	var (
		dir       = fs.String("dir", "", "project root directory (default: current directory)")
		outputDir = fs.String("output-dir", "", "output directory (default: project root)")
		format    = fs.String("format", "json", "output format: json or text")
	)
	if err := fs.Parse(args); err != nil {
		return 1
	}

	projectRoot := *dir
	if projectRoot == "" {
		var err error
		projectRoot, err = os.Getwd()
		if err != nil {
			fmt.Fprintf(stderr, "gofusa vuln: get working directory: %v\n", err)
			return 1
		}
	}

	outDir := *outputDir
	if outDir == "" {
		outDir = projectRoot
	}

	if mkErr := os.MkdirAll(outDir, 0o755); mkErr != nil {
		fmt.Fprintf(stderr, "gofusa vuln: mkdir: %v\n", mkErr)
		return 1
	}

	report, err := vuln.Scan(projectRoot)
	if err != nil {
		fmt.Fprintf(stderr, "gofusa vuln: %v\n", err)
		return 1
	}

	outPath := filepath.Join(outDir, vuln.VulnFile)
	f, err := os.Create(outPath)
	if err != nil {
		fmt.Fprintf(stderr, "gofusa vuln: create %s: %v\n", outPath, err)
		return 1
	}
	defer func() { _ = f.Close() }()

	if err := vuln.Render(f, report, "json"); err != nil {
		fmt.Fprintf(stderr, "gofusa vuln: write %s: %v\n", outPath, err)
		return 1
	}
	fmt.Fprintf(stdout, "Vulnerability report written to %s\n", outPath)

	// Also print text summary to stdout
	if *format == "text" || *format == "" {
		if err := vuln.Render(stdout, report, "text"); err != nil {
			fmt.Fprintf(stderr, "gofusa vuln: render text: %v\n", err)
			return 1
		}
	} else {
		fmt.Fprintf(stdout, "Scanned: %d dependencies  Findings: %d\n",
			report.Scanned, len(report.Findings))
	}

	return 0
}
