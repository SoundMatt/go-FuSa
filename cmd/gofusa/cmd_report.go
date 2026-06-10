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
	"github.com/SoundMatt/go-FuSa/engine"
	"github.com/SoundMatt/go-FuSa/report"
)

func runReport(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa report", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: gofusa report [flags]\n\n")
		fmt.Fprintf(stderr, "Generate a safety compliance report. Always exits 0.\n\n")
		fmt.Fprintf(stderr, "Flags:\n")
		fs.PrintDefaults()
	}

	var (
		dir    = fs.String("dir", "", "project root directory (default: current directory)")
		format = fs.String("format", "", "output format: text, json, or html (default: from config or text)")
		output = fs.String("output", "", "write report to file (default: stdout)")
	)
	if code := parseFlags(fs, args); code != 0 {
		return code
	}

	projectRoot := *dir
	if projectRoot == "" {
		var err error
		projectRoot, err = os.Getwd()
		if err != nil {
			fmt.Fprintf(stderr, "gofusa report: get working directory: %v\n", err)
			return fusa.ExitRuntime
		}
	}

	cfg, err := config.Load(filepath.Join(projectRoot, config.ConfigFile))
	if err != nil {
		if errors.Is(err, fusa.ErrNoConfig) {
			cfg = config.Default("", filepath.Base(projectRoot))
		} else {
			fmt.Fprintf(stderr, "gofusa report: %v\n", err)
			return fusa.ExitRuntime
		}
	}

	if *format != "" {
		cfg.Report.Format = *format
	}
	if *output != "" {
		cfg.Report.Output = *output
	}

	result, err := engine.Default.Run(context.Background(), projectRoot, cfg)
	if err != nil {
		fmt.Fprintf(stderr, "gofusa report: engine error: %v\n", err)
		return fusa.ExitRuntime
	}
	for _, runErr := range result.Errors {
		fmt.Fprintf(stderr, "gofusa report: warning: %v\n", runErr)
	}

	rep := report.New(projectRoot, result.Findings)
	outPath := cfg.Report.Output
	w := stdout
	if outPath != "" {
		f, err := os.Create(outPath)
		if err != nil {
			fmt.Fprintf(stderr, "gofusa report: create output: %v\n", err)
			return fusa.ExitRuntime
		}
		defer func() { _ = f.Close() }()
		w = f
	}
	if err := report.Render(w, rep, cfg.Report.Format); err != nil {
		fmt.Fprintf(stderr, "gofusa report: render: %v\n", err)
		return fusa.ExitRuntime
	}
	return fusa.ExitOK
}
