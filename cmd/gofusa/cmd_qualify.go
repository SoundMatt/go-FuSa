package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/SoundMatt/go-FuSa/engine"
	"github.com/SoundMatt/go-FuSa/qualify"
)

func runQualify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa qualify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: gofusa qualify [flags]\n\n")
		fmt.Fprintf(stderr, "Run the built-in tool qualification suite and save a qualification report.\n")
		fmt.Fprintf(stderr, "The report can be submitted as tool confidence evidence in regulated environments.\n\n")
		fmt.Fprintf(stderr, "Flags:\n")
		fs.PrintDefaults()
	}

	var (
		outputFile = fs.String("output", "", "path for the JSON qualification report (default: ./qualify-report.json)")
	)
	if err := fs.Parse(args); err != nil {
		return 1
	}

	outPath := *outputFile
	if outPath == "" {
		wd, err := os.Getwd()
		if err != nil {
			fmt.Fprintf(stderr, "gofusa qualify: get working directory: %v\n", err)
			return 1
		}
		outPath = filepath.Join(wd, qualify.ReportFile)
	}

	fmt.Fprintf(stdout, "Running %d qualification case(s)...\n", len(qualify.BuiltinCases()))

	report, err := qualify.Run(context.Background(), engine.Default, qualify.BuiltinCases())
	if err != nil {
		fmt.Fprintf(stderr, "gofusa qualify: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "Results: %d/%d passed", report.Passed, report.Total)
	if report.HasFailures() {
		fmt.Fprintf(stdout, " (%d failed)\n", report.Failed)
		for _, r := range report.Results {
			if !r.Passed {
				fmt.Fprintf(stdout, "  FAIL  %s: %s\n", r.Case.Name, r.Error)
			}
		}
	} else {
		fmt.Fprintf(stdout, " — all passed\n")
	}

	if err := qualify.Save(outPath, report); err != nil {
		fmt.Fprintf(stderr, "gofusa qualify: save report: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "Qualification report written to %s\n", outPath)
	fmt.Fprintf(stdout, "Integrity hash: %s\n", report.Hash)

	if report.HasFailures() {
		return 1
	}
	return 0
}
