package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/config"
	"github.com/SoundMatt/go-FuSa/cyber"
)

// runCyber runs only CYBER* rules against the project root.
//
//fusa:req REQ-CLI018
func runCyber(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa cyber", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: gofusa cyber [flags]\n\n")
		fmt.Fprintf(stderr, "Run cybersecurity static analysis (CYBER001–CYBER020). Exits 1 on ERROR findings.\n\n")
		fmt.Fprintf(stderr, "Flags:\n")
		fs.PrintDefaults()
	}

	var (
		dir    = fs.String("dir", "", "project root directory (default: current directory)")
		output = fs.String("output", "", "write JSON report to file (default: cyber-report.json in project root)")
		strict = fs.Bool("strict", false, "exit 1 on any WARNING or ERROR finding")
	)
	if err := fs.Parse(args); err != nil {
		return 1
	}

	projectRoot := *dir
	if projectRoot == "" {
		var err error
		projectRoot, err = os.Getwd()
		if err != nil {
			fmt.Fprintf(stderr, "gofusa cyber: get working directory: %v\n", err)
			return 1
		}
	}

	cfg, err := config.Load(projectRoot)
	if err != nil && !errors.Is(err, fusa.ErrNoConfig) {
		fmt.Fprintf(stderr, "gofusa cyber: load config: %v\n", err)
		return 1
	}
	if cfg == nil {
		cfg = config.Default("", filepath.Base(projectRoot))
	}

	findings, err := cyber.Scan(context.Background(), projectRoot, cfg)
	if err != nil {
		fmt.Fprintf(stderr, "gofusa cyber: scan: %v\n", err)
		return 1
	}

	// Print summary.
	var errors_, warnings, infos int
	for _, f := range findings {
		switch f.Severity {
		case fusa.SeverityError:
			errors_++
		case fusa.SeverityWarning:
			warnings++
		case fusa.SeverityInfo:
			infos++
		}
		fmt.Fprintf(stdout, "[%s] %s:%d  %s\n", f.Severity, f.Location.File, f.Location.Line, f.Message)
	}
	fmt.Fprintf(stdout, "\nCyber findings: %d error  %d warning  %d info\n", errors_, warnings, infos)

	// Write JSON report.
	outPath := *output
	if outPath == "" {
		outPath = filepath.Join(projectRoot, "cyber-report.json")
	}
	if err := writeCyberReport(outPath, findings, projectRoot); err != nil {
		fmt.Fprintf(stderr, "gofusa cyber: write report: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "Cyber report written to %s\n", outPath)

	if errors_ > 0 {
		return 1
	}
	if *strict && (warnings > 0 || errors_ > 0) {
		return 1
	}
	return 0
}

type cyberReport struct {
	Format   string         `json:"format"`
	Module   string         `json:"module"`
	Findings []fusa.Finding `json:"findings"`
}

func writeCyberReport(path string, findings []fusa.Finding, root string) error {
	r := cyberReport{
		Format:   "go-FuSa Cyber Report v1",
		Findings: findings,
	}
	// Read module name from go.mod.
	data, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "module ") {
				r.Module = strings.TrimSpace(strings.TrimPrefix(line, "module "))
				break
			}
		}
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
