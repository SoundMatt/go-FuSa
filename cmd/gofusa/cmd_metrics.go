package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/metrics"
)

//fusa:req REQ-CLI-METRICS001
func runMetrics(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa metrics", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: gofusa metrics <subcommand> [flags]\n\n")
		fmt.Fprintf(stderr, "Track go-FuSa safety metrics over time.\n\n")
		fmt.Fprintf(stderr, "Subcommands:\n")
		fmt.Fprintf(stderr, "  record  Collect and append a metrics snapshot\n")
		fmt.Fprintf(stderr, "  show    Display the full metrics time series\n\n")
		fmt.Fprintf(stderr, "Global flags:\n")
		fs.PrintDefaults()
	}
	dir := fs.String("dir", "", "project root directory (default: current directory)")
	if code := parseFlags(fs, args); code != 0 {
		return code
	}

	projectRoot := *dir
	if projectRoot == "" {
		var err error
		projectRoot, err = os.Getwd()
		if err != nil {
			fmt.Fprintf(stderr, "gofusa metrics: get working directory: %v\n", err)
			return fusa.ExitRuntime
		}
	}

	sub := fs.Args()
	if len(sub) == 0 {
		fs.Usage()
		return fusa.ExitUsage
	}

	switch sub[0] {
	case "record":
		return runMetricsRecord(projectRoot, stdout, stderr)
	case "show":
		return runMetricsShow(sub[1:], projectRoot, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "gofusa metrics: unknown subcommand %q\n", sub[0])
		return fusa.ExitUsage
	}
}

func runMetricsRecord(projectRoot string, stdout, stderr io.Writer) int {
	ts, err := metrics.Load(projectRoot)
	if err != nil {
		fmt.Fprintf(stderr, "gofusa metrics record: load: %v\n", err)
		return fusa.ExitRuntime
	}

	snap, err := metrics.Collect(projectRoot)
	if err != nil {
		fmt.Fprintf(stderr, "gofusa metrics record: collect: %v\n", err)
		return fusa.ExitRuntime
	}

	ts = metrics.Append(ts, snap)

	path := filepath.Join(projectRoot, metrics.MetricsFile)
	if err := metrics.Save(path, ts); err != nil {
		fmt.Fprintf(stderr, "gofusa metrics record: save: %v\n", err)
		return fusa.ExitRuntime
	}

	fmt.Fprintf(stdout, "Metrics recorded: errors=%d warnings=%d infos=%d reqs=%d traced=%d coverage=%.1f%%\n",
		snap.ErrorCount, snap.WarningCount, snap.InfoCount,
		snap.TotalRequirements, snap.TracedRequirements,
		snap.CoveragePct,
	)
	fmt.Fprintf(stdout, "Time series saved to %s (%d snapshots)\n", path, len(ts.Snapshots))
	return fusa.ExitOK
}

func runMetricsShow(args []string, projectRoot string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa metrics show", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		format = fs.String("format", "text", "output format: text, json")
		output = fs.String("output", "", "write to file (default: stdout)")
	)
	if code := parseFlags(fs, args); code != 0 {
		return code
	}

	ts, err := metrics.Load(projectRoot)
	if err != nil {
		fmt.Fprintf(stderr, "gofusa metrics show: load: %v\n", err)
		return fusa.ExitRuntime
	}

	w := stdout
	if *output != "" {
		f, ferr := os.Create(*output)
		if ferr != nil {
			fmt.Fprintf(stderr, "gofusa metrics show: create %s: %v\n", *output, ferr)
			return fusa.ExitRuntime
		}
		defer func() { _ = f.Close() }()
		w = f
	}

	if err := metrics.Render(w, ts, *format); err != nil {
		fmt.Fprintf(stderr, "gofusa metrics show: render: %v\n", err)
		return fusa.ExitRuntime
	}
	return fusa.ExitOK
}
