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

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/config"
	"github.com/SoundMatt/go-FuSa/engine"
	"github.com/SoundMatt/go-FuSa/report"
)

//fusa:req REQ-CLI-FIX001
func runFix(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa fix", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: gofusa fix [flags]\n\n")
		fmt.Fprintf(stderr, "Show auto-fixable findings from gofusa check.\n")
		fmt.Fprintf(stderr, "Prints a remediation summary; use --report to also save the report.\n\n")
		fmt.Fprintf(stderr, "Flags:\n")
		fs.PrintDefaults()
	}

	var (
		dir    = fs.String("dir", "", "project root directory (default: current directory)")
		output = fs.String("report", "", "write full JSON report to file")
	)
	if err := fs.Parse(args); err != nil {
		return 1
	}

	projectRoot := *dir
	if projectRoot == "" {
		var err error
		projectRoot, err = os.Getwd()
		if err != nil {
			fmt.Fprintf(stderr, "gofusa fix: get working directory: %v\n", err)
			return 1
		}
	}

	cfg, err := config.Load(filepath.Join(projectRoot, config.ConfigFile))
	if err != nil {
		if errors.Is(err, fusa.ErrNoConfig) {
			cfg = config.Default("", filepath.Base(projectRoot))
		} else {
			fmt.Fprintf(stderr, "gofusa fix: %v\n", err)
			return 1
		}
	}

	result, err := engine.Default.Run(context.Background(), projectRoot, cfg)
	if err != nil {
		fmt.Fprintf(stderr, "gofusa fix: engine error: %v\n", err)
		return 1
	}

	fixable := filterFixable(result.Findings)
	if len(fixable) == 0 {
		fmt.Fprintf(stdout, "No auto-fixable findings found.\n")
	} else {
		fmt.Fprintf(stdout, "Auto-fixable findings: %d\n\n", len(fixable))
		for _, f := range fixable {
			fmt.Fprintf(stdout, "  [%s] %s:%d\n    %s\n    Fix: %s\n\n",
				f.RuleID, f.Location.File, f.Location.Line, f.Message, f.Remediation)
		}
		fmt.Fprintf(stdout, "Apply fixes manually using the remediation guidance above.\n")
		fmt.Fprintf(stdout, "Run 'gofusa check' again to verify.\n")
	}

	if *output != "" {
		rep := report.New(projectRoot, result.Findings)
		data, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "gofusa fix: marshal report: %v\n", err)
			return 1
		}
		if err := os.WriteFile(*output, data, 0o640); err != nil {
			fmt.Fprintf(stderr, "gofusa fix: write report: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "Report written to %s\n", *output)
	}

	if result.HasErrors() {
		return 1
	}
	return 0
}

// filterFixable returns findings that have a non-empty Remediation field,
// indicating go-FuSa knows how to address them.
func filterFixable(findings []fusa.Finding) []fusa.Finding {
	var out []fusa.Finding
	for _, f := range findings {
		if f.Remediation != "" {
			out = append(out, f)
		}
	}
	return out
}
