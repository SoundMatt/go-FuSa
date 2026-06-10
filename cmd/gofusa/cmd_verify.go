package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/verify"
)

func runVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: gofusa verify [flags]\n\n")
		fmt.Fprintf(stderr, "Run go test and save a test evidence bundle.\n\n")
		fmt.Fprintf(stderr, "Flags:\n")
		fs.PrintDefaults()
	}

	var (
		dir    = fs.String("dir", "", "project root directory (default: current directory)")
		output = fs.String("output", "", "evidence bundle path (default: <dir>/.fusa-evidence.json)")
	)
	if code := parseFlags(fs, args); code != 0 {
		return code
	}

	projectRoot := *dir
	if projectRoot == "" {
		var err error
		projectRoot, err = os.Getwd()
		if err != nil {
			fmt.Fprintf(stderr, "gofusa verify: get working directory: %v\n", err)
			return fusa.ExitRuntime
		}
	}

	fmt.Fprintf(stdout, "Running go test -json -count=1 ./...\n")
	results, err := verify.Run(context.Background(), projectRoot)
	if err != nil {
		fmt.Fprintf(stderr, "gofusa verify: run tests: %v\n", err)
		return fusa.ExitRuntime
	}

	bundle := verify.New(projectRoot, results)
	outPath := *output
	if outPath == "" {
		outPath = filepath.Join(projectRoot, verify.BundleFile)
	}
	if err := verify.Save(outPath, bundle); err != nil {
		fmt.Fprintf(stderr, "gofusa verify: save bundle: %v\n", err)
		return fusa.ExitRuntime
	}

	s := bundle.Summary
	fmt.Fprintf(stdout, "Tests: %d total  %d passed  %d failed  %d skipped\n",
		s.Total, s.Passed, s.Failed, s.Skipped)
	fmt.Fprintf(stdout, "Evidence bundle written to %s\n", outPath)

	if s.Failed > 0 {
		return fusa.ExitRuntime
	}
	return fusa.ExitOK
}
