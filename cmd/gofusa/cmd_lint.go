package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/config"
	"github.com/SoundMatt/go-FuSa/engine"
	"github.com/SoundMatt/go-FuSa/report"
)

// runLint runs only LINT* rules against the project root.
//
//fusa:req REQ-CLI008
func runLint(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa lint", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: gofusa lint [flags]\n\n")
		fmt.Fprintf(stderr, "Run safety coding-standard checks (LINT001–LINT006). Exits 1 on ERROR findings.\n\n")
		fmt.Fprintf(stderr, "Flags:\n")
		fs.PrintDefaults()
	}

	var (
		dir    = fs.String("dir", "", "project root directory (default: current directory)")
		format = fs.String("format", "", "output format: text or json (default: from config or text)")
		output = fs.String("output", "", "write report to file (default: stdout)")
		strict = fs.Bool("strict", false, "exit 1 on any WARNING or ERROR finding")
	)
	if code := parseFlags(fs, args); code != 0 {
		return code
	}

	return runFiltered(args[:0], stdout, stderr, "gofusa lint", *dir, *format, *output, *strict,
		func(r engine.Rule) bool { return strings.HasPrefix(r.ID(), "LINT") })
}

// runFiltered is the shared implementation for runLint and runAnalyze.
func runFiltered(
	_ []string,
	stdout, stderr io.Writer,
	cmdName, dir, format, output string,
	strict bool,
	keep func(engine.Rule) bool,
) int {
	projectRoot := dir
	if projectRoot == "" {
		var err error
		projectRoot, err = os.Getwd()
		if err != nil {
			fmt.Fprintf(stderr, "%s: get working directory: %v\n", cmdName, err)
			return fusa.ExitRuntime
		}
	}

	cfg, err := config.Load(filepath.Join(projectRoot, config.ConfigFile))
	if err != nil {
		if errors.Is(err, fusa.ErrNoConfig) {
			cfg = config.Default("", filepath.Base(projectRoot))
		} else {
			fmt.Fprintf(stderr, "%s: %v\n", cmdName, err)
			return fusa.ExitRuntime
		}
	}

	if format != "" {
		cfg.Report.Format = format
	}
	if output != "" {
		cfg.Report.Output = output
	}

	result, err := engine.Default.RunFilter(context.Background(), projectRoot, cfg, keep)
	if err != nil {
		fmt.Fprintf(stderr, "%s: engine error: %v\n", cmdName, err)
		return fusa.ExitRuntime
	}
	for _, runErr := range result.Errors {
		fmt.Fprintf(stderr, "%s: warning: %v\n", cmdName, runErr)
	}

	rep := report.New(projectRoot, result.Findings)
	w := stdout
	if cfg.Report.Output != "" {
		f, err := os.Create(cfg.Report.Output)
		if err != nil {
			fmt.Fprintf(stderr, "%s: create output: %v\n", cmdName, err)
			return fusa.ExitRuntime
		}
		defer func() { _ = f.Close() }()
		w = f
	}
	if err := report.Render(w, rep, cfg.Report.Format); err != nil {
		fmt.Fprintf(stderr, "%s: render: %v\n", cmdName, err)
		return fusa.ExitRuntime
	}

	if result.HasErrors() {
		return fusa.ExitGateFail
	}
	if strict && result.HasWarnings() {
		return fusa.ExitGateFail
	}
	return fusa.ExitOK
}
