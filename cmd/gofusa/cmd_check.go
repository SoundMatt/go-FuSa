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
		format = fs.String("format", "", "output format: text, json, html, sarif, or md (default: from config or text)")
		output = fs.String("output", "", "write report to file (default: stdout)")
		//fusa:req REQ-CLI011
		strict    = fs.Bool("strict", false, "exit 1 on any WARNING or ERROR finding (default: exit 1 on ERROR only)")
		noSummary = fs.Bool("no-summary", false, "suppress the per-category and top-rules summary block")
	)
	if code := parseFlags(fs, args); code != 0 {
		return code
	}

	projectRoot := *dir
	if projectRoot == "" {
		var err error
		projectRoot, err = os.Getwd()
		if err != nil {
			return runtimeErrorf(stderr, "check", "get working directory: %v", err)
		}
	}

	cfg, err := config.Load(filepath.Join(projectRoot, config.ConfigFile))
	if err != nil {
		if errors.Is(err, fusa.ErrNoConfig) {
			cfg = config.Default("", filepath.Base(projectRoot))
		} else {
			return runtimeErrorf(stderr, "check", "%v", err)
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
		return runtimeErrorf(stderr, "check", "engine error: %v", err)
	}
	for _, runErr := range result.Errors {
		fmt.Fprintf(stderr, "gofusa check: warning: %v\n", runErr)
	}

	rep := report.New(projectRoot, result.Findings)
	rep.NoSummary = *noSummary
	rep.Standard = string(cfg.Project.Standard)
	switch cfg.Project.Standard {
	case "IEC61508":
		rep.SIL = cfg.Project.ASIL
	case "DO178C":
		rep.DAL = cfg.Project.ASIL
	default:
		rep.ASIL = cfg.Project.ASIL
	}
	outPath := cfg.Report.Output
	w := stdout
	if outPath != "" {
		f, err := os.Create(outPath)
		if err != nil {
			return runtimeErrorf(stderr, "check", "create output: %v", err)
		}
		defer func() { _ = f.Close() }()
		w = f
	}
	if err := report.Render(w, rep, cfg.Report.Format); err != nil {
		return runtimeErrorf(stderr, "check", "render: %v", err)
	}

	//fusa:req REQ-CLI006
	if result.HasErrors() {
		return fusa.ExitGateFail
	}
	if *strict && result.HasWarnings() {
		return fusa.ExitGateFail
	}
	//fusa:req REQ-CLI005
	return fusa.ExitOK
}
