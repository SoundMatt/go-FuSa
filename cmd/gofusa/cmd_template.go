package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/template"
)

// runTemplate generates safety documentation templates in the target directory.
//
//fusa:req REQ-CLI010
func runTemplate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa template", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: gofusa template [flags]\n\n")
		fmt.Fprintf(stderr, "Generate safety documentation templates.\n\n")
		fmt.Fprintf(stderr, "Flags:\n")
		fs.PrintDefaults()
	}

	var (
		dir = fs.String("dir", "", "output directory (default: docs/safety)")
		typ = fs.String("type", "all", "template type: safety-plan, test-evidence, hara, all")
	)
	if code := parseFlags(fs, args); code != 0 {
		return code
	}

	outDir := *dir
	if outDir == "" {
		wd, err := os.Getwd()
		if err != nil {
			fmt.Fprintf(stderr, "gofusa template: get working directory: %v\n", err)
			return fusa.ExitRuntime
		}
		outDir = wd + "/docs/safety"
	}

	t := template.Type(*typ)
	if err := template.Generate(outDir, t); err != nil {
		fmt.Fprintf(stderr, "gofusa template: %v\n", err)
		return fusa.ExitRuntime
	}
	fmt.Fprintf(stdout, "Templates written to %s\n", outDir)
	return fusa.ExitOK
}
