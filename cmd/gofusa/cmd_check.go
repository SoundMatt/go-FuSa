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

func runCheck(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: gofusa check [flags]\n\n")
		fmt.Fprintf(stderr, "Run safety checks. Exits 1 if any ERROR-severity findings exist.\n\n")
		fmt.Fprintf(stderr, "Flags:\n")
		fs.PrintDefaults()
	}

	var (
		dir    = fs.String("dir", "", "project root directory (default: current directory)")
		format = fs.String("format", "", "output format: text or json (default: from config or text)")
		output = fs.String("output", "", "write report to file (default: stdout)")
	)
	if err := fs.Parse(args); err != nil {
		return 1
	}

	projectRoot := *dir
	if projectRoot == "" {
		var err error
		projectRoot, err = os.Getwd()
		if err != nil {
			fmt.Fprintf(stderr, "gofusa check: get working directory: %v\n", err)
			return 1
		}
	}

	cfg, err := config.Load(filepath.Join(projectRoot, config.ConfigFile))
	if err != nil {
		if errors.Is(err, fusa.ErrNoConfig) {
			cfg = config.Default("", filepath.Base(projectRoot))
		} else {
			fmt.Fprintf(stderr, "gofusa check: %v\n", err)
			return 1
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
		fmt.Fprintf(stderr, "gofusa check: engine error: %v\n", err)
		return 1
	}
	for _, runErr := range result.Errors {
		fmt.Fprintf(stderr, "gofusa check: warning: %v\n", runErr)
	}

	rep := report.New(projectRoot, result.Findings)
	outPath := cfg.Report.Output
	var w io.Writer = stdout
	if outPath != "" {
		f, err := os.Create(outPath)
		if err != nil {
			fmt.Fprintf(stderr, "gofusa check: create output: %v\n", err)
			return 1
		}
		defer func() { _ = f.Close() }()
		w = f
	}
	if err := report.Render(w, rep, cfg.Report.Format); err != nil {
		fmt.Fprintf(stderr, "gofusa check: render: %v\n", err)
		return 1
	}

	if result.HasErrors() {
		return 1
	}
	return 0
}
