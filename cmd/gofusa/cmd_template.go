package main

import (
	"flag"
	"fmt"
	"io"
	"os"

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
	if err := fs.Parse(args); err != nil {
		return 1
	}

	outDir := *dir
	if outDir == "" {
		wd, err := os.Getwd()
		if err != nil {
			fmt.Fprintf(stderr, "gofusa template: get working directory: %v\n", err)
			return 1
		}
		outDir = wd + "/docs/safety"
	}

	t := template.Type(*typ)
	if err := template.Generate(outDir, t); err != nil {
		fmt.Fprintf(stderr, "gofusa template: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "Templates written to %s\n", outDir)
	return 0
}
