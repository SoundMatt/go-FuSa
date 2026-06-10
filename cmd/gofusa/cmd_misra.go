package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/misra"
)

//fusa:req REQ-CLI-MISRA001
func runMisra(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa misra", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: gofusa misra [flags]\n\n")
		fmt.Fprintf(stderr, "Show MISRA C:2023 to Go / go-FuSa rule coverage mapping.\n\n")
		fmt.Fprintf(stderr, "Flags:\n")
		fs.PrintDefaults()
	}

	var (
		format = fs.String("format", "text", "output format: text, json")
		output = fs.String("output", "", "write report to file (default: stdout)")
	)
	if code := parseFlags(fs, args); code != 0 {
		return code
	}

	rep := misra.Assess()

	w := stdout
	if *output != "" {
		f, ferr := os.Create(*output)
		if ferr != nil {
			fmt.Fprintf(stderr, "gofusa misra: create %s: %v\n", *output, ferr)
			return fusa.ExitRuntime
		}
		defer func() { _ = f.Close() }()
		w = f
	}

	if err := misra.Render(w, rep, *format); err != nil {
		fmt.Fprintf(stderr, "gofusa misra: render: %v\n", err)
		return fusa.ExitRuntime
	}

	if *output != "" {
		fmt.Fprintf(stdout, "MISRA C:2023 coverage report written to %s (%d/%d rules covered)\n",
			*output, rep.Covered, rep.Total)
	}

	return fusa.ExitOK
}
