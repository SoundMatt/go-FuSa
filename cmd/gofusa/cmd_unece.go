package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/unece"
)

//fusa:req REQ-CLI-UNECE-001
func runUNECE(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa unece", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: gofusa unece [flags]\n\n")
		fmt.Fprintf(stderr, "Generate a UN R.155 cybersecurity compliance gap report.\n\n")
		fmt.Fprintf(stderr, "Flags:\n")
		fs.PrintDefaults()
	}

	var (
		dir    = fs.String("dir", "", "project root directory (default: current directory)")
		format = fs.String("format", "text", "output format: text, json")
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
			fmt.Fprintf(stderr, "gofusa unece: get working directory: %v\n", err)
			return fusa.ExitRuntime
		}
	}

	rep, err := unece.Assess(projectRoot)
	if err != nil {
		fmt.Fprintf(stderr, "gofusa unece: assess: %v\n", err)
		return fusa.ExitRuntime
	}

	w := stdout
	if *output != "" {
		f, ferr := os.Create(*output)
		if ferr != nil {
			fmt.Fprintf(stderr, "gofusa unece: create %s: %v\n", *output, ferr)
			return fusa.ExitRuntime
		}
		defer func() { _ = f.Close() }()
		w = f
	}

	if err := unece.Render(w, rep, *format); err != nil {
		fmt.Fprintf(stderr, "gofusa unece: render: %v\n", err)
		return fusa.ExitRuntime
	}

	if *output != "" {
		fmt.Fprintf(stdout, "UN R.155 gap report written to %s (%d gaps)\n", *output, rep.Gap)
	}

	if rep.Gap > 0 {
		return fusa.ExitGateFail
	}
	return fusa.ExitOK
}
