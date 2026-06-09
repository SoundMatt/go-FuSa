package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/SoundMatt/go-FuSa/coverage"
)

//fusa:req REQ-CLI-COV001
func runCoverage(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa coverage", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: gofusa coverage [flags] [coverage.out]\n\n")
		fmt.Fprintf(stderr, "Produce a DO-178C structural coverage report from a Go coverage profile.\n")
		fmt.Fprintf(stderr, "Generate coverage.out with: go test -coverprofile=coverage.out ./...\n\n")
		fmt.Fprintf(stderr, "Flags:\n")
		fs.PrintDefaults()
	}

	var (
		dalFlag = fs.String("dal", "DAL-B", "design assurance level: DAL-A, DAL-B, DAL-C, DAL-D")
		format  = fs.String("format", "text", "output format: text or json")
		output  = fs.String("output", "", "write report to file (default: stdout)")
		mutate  = fs.Bool("mutate", false, "run mutation testing via go-mutesting (MC/DC-equivalent evidence for DO-178C Level A)")
	)
	if err := fs.Parse(args); err != nil {
		return 1
	}

	profilePath := coverage.CoverageFile
	if fs.NArg() > 0 {
		profilePath = fs.Arg(0)
	} else if fs.NArg() == 0 {
		// Try current directory
		if _, err := os.Stat(profilePath); err != nil {
			// Try looking in current working directory
			cwd, _ := os.Getwd()
			profilePath = filepath.Join(cwd, coverage.CoverageFile)
		}
	}

	dal := coverage.DAL(*dalFlag)
	switch dal {
	case coverage.DALA, coverage.DALB, coverage.DALC, coverage.DALD:
	default:
		fmt.Fprintf(stderr, "gofusa coverage: invalid --dal %q\n", *dalFlag)
		return 1
	}

	rep, err := coverage.BuildFromFile(profilePath, dal)
	if err != nil {
		fmt.Fprintf(stderr, "gofusa coverage: %v\n", err)
		fmt.Fprintf(stderr, "Tip: generate a profile with: go test -coverprofile=%s ./...\n", coverage.CoverageFile)
		return 1
	}

	w := stdout
	if *output != "" {
		f, err := os.Create(*output)
		if err != nil {
			fmt.Fprintf(stderr, "gofusa coverage: create output: %v\n", err)
			return 1
		}
		defer func() { _ = f.Close() }()
		w = f
	}

	if err := coverage.Render(w, rep, *format); err != nil {
		fmt.Fprintf(stderr, "gofusa coverage: render: %v\n", err)
		return 1
	}

	if *mutate {
		// Determine project root from the coverage file location or cwd.
		projectRoot := filepath.Dir(profilePath)
		if projectRoot == "." {
			var cwdErr error
			projectRoot, cwdErr = os.Getwd()
			if cwdErr != nil {
				projectRoot = "."
			}
		}
		mRep, mErr := coverage.RunMutation(projectRoot, dal)
		if mErr != nil {
			fmt.Fprintf(stderr, "gofusa coverage: mutation: %v\n", mErr)
			return 1
		}
		switch *format {
		case "json":
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			if err := enc.Encode(mRep); err != nil {
				fmt.Fprintf(stderr, "gofusa coverage: mutation json: %v\n", err)
				return 1
			}
		default:
			fmt.Fprintf(w, "\nMutation Testing\n")
			fmt.Fprintf(w, "Mutants: %d  Killed: %d  Survived: %d  Score: %.1f%%\n",
				mRep.Mutants, mRep.Killed, mRep.Survived, mRep.Score)
			fmt.Fprintf(w, "MC/DC Evidence: %s\n", mRep.MCDCEvidence)
			if mRep.Note != "" {
				fmt.Fprintf(w, "Note: %s\n", mRep.Note)
			}
		}
	}
	return 0
}
