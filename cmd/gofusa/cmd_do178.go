package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/do178"
)

//fusa:req REQ-CLI-DO178-001
func runDo178(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa do178", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: gofusa do178 [flags]\n\n")
		fmt.Fprintf(stderr, "Generate a DO-178C compliance gap report.\n")
		fmt.Fprintf(stderr, "Maps evidence to Annex A objectives and reports PASS/GAP/MANUAL/N/A.\n\n")
		fmt.Fprintf(stderr, "Flags:\n")
		fs.PrintDefaults()
	}

	var (
		dir     = fs.String("dir", "", "project root directory (default: current directory)")
		dalFlag = fs.String("dal", "DAL-B", "design assurance level: DAL-A, DAL-B, DAL-C, DAL-D")
		format  = fs.String("format", "text", "output format: text or json")
		output  = fs.String("output", "", "write report to file (default: stdout)")
	)
	if code := parseFlags(fs, args); code != 0 {
		return code
	}

	projectRoot := *dir
	if projectRoot == "" {
		var err error
		projectRoot, err = os.Getwd()
		if err != nil {
			fmt.Fprintf(stderr, "gofusa do178: get working directory: %v\n", err)
			return fusa.ExitRuntime
		}
	}

	dal := do178.DAL(*dalFlag)
	switch dal {
	case do178.DALA, do178.DALB, do178.DALC, do178.DALD:
	default:
		fmt.Fprintf(stderr, "gofusa do178: invalid --dal %q (must be DAL-A, DAL-B, DAL-C, or DAL-D)\n", *dalFlag)
		return fusa.ExitUsage
	}

	project := filepath.Base(projectRoot)
	rep, err := do178.Assess(projectRoot, project, dal)
	if err != nil {
		fmt.Fprintf(stderr, "gofusa do178: %v\n", err)
		return fusa.ExitRuntime
	}

	w := stdout
	if *output != "" {
		f, err := os.Create(*output)
		if err != nil {
			fmt.Fprintf(stderr, "gofusa do178: create output: %v\n", err)
			return fusa.ExitRuntime
		}
		defer func() { _ = f.Close() }()
		w = f
	}

	if err := do178.Render(w, rep, *format); err != nil {
		fmt.Fprintf(stderr, "gofusa do178: render: %v\n", err)
		return fusa.ExitRuntime
	}
	if rep.Gap > 0 {
		return fusa.ExitGateFail
	}
	return fusa.ExitOK
}
