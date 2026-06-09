package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/SoundMatt/go-FuSa/config"
	"github.com/SoundMatt/go-FuSa/sas"
)

//fusa:req REQ-CLI-SAS001
func runSas(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa sas", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: gofusa sas [flags]\n\n")
		fmt.Fprintf(stderr, "Generate a Software Accomplishment Summary (DO-178C §11.20).\n\n")
		fmt.Fprintf(stderr, "Flags:\n")
		fs.PrintDefaults()
	}

	var (
		dir      = fs.String("dir", "", "project root directory (default: current directory)")
		dalFlag  = fs.String("dal", "DAL-B", "design assurance level")
		prepared = fs.String("prepared-by", "", "name of the person or team preparing the SAS")
		format   = fs.String("format", "markdown", "output format: markdown or json")
		output   = fs.String("output", sas.SASFile, "write SAS to file (use - for stdout)")
	)
	if err := fs.Parse(args); err != nil {
		return 1
	}

	projectRoot := *dir
	if projectRoot == "" {
		var err error
		projectRoot, err = os.Getwd()
		if err != nil {
			fmt.Fprintf(stderr, "gofusa sas: get working directory: %v\n", err)
			return 1
		}
	}

	cfg, _ := config.Load(filepath.Join(projectRoot, config.ConfigFile))
	project := filepath.Base(projectRoot)
	version := "unknown"
	if cfg != nil {
		if cfg.Project.Name != "" {
			project = cfg.Project.Name
		}
		if cfg.Version != "" {
			version = cfg.Version
		}
	}

	doc, err := sas.Build(projectRoot, project, version, *dalFlag, *prepared)
	if err != nil {
		fmt.Fprintf(stderr, "gofusa sas: %v\n", err)
		return 1
	}

	var w io.Writer = stdout
	if *output != "" && *output != "-" {
		outPath := *output
		if !filepath.IsAbs(outPath) {
			outPath = filepath.Join(projectRoot, outPath)
		}
		f, err := os.Create(outPath)
		if err != nil {
			fmt.Fprintf(stderr, "gofusa sas: create output: %v\n", err)
			return 1
		}
		defer func() { _ = f.Close() }()
		w = f
		defer fmt.Fprintf(stdout, "SAS written to %s\n", outPath)
	}

	if err := sas.Render(w, doc, *format); err != nil {
		fmt.Fprintf(stderr, "gofusa sas: render: %v\n", err)
		return 1
	}
	if len(doc.Gaps) > 0 {
		return 1
	}
	return 0
}
