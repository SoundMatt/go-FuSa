package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/SoundMatt/go-FuSa/config"
	"github.com/SoundMatt/go-FuSa/sci"
)

//fusa:req REQ-CLI-SCI001
func runSci(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa sci", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: gofusa sci [flags]\n\n")
		fmt.Fprintf(stderr, "Generate the Software Configuration Index (DO-178C §11.16).\n\n")
		fmt.Fprintf(stderr, "Flags:\n")
		fs.PrintDefaults()
	}

	var (
		dir    = fs.String("dir", "", "project root directory (default: current directory)")
		format = fs.String("format", "json", "output format: json or markdown")
		output = fs.String("output", "", "write SCI to file (default: stdout)")
	)
	if err := fs.Parse(args); err != nil {
		return 1
	}

	projectRoot := *dir
	if projectRoot == "" {
		var err error
		projectRoot, err = os.Getwd()
		if err != nil {
			fmt.Fprintf(stderr, "gofusa sci: get working directory: %v\n", err)
			return 1
		}
	}

	cfg, _ := config.Load(filepath.Join(projectRoot, config.ConfigFile))
	project := filepath.Base(projectRoot)
	version := "unknown"
	if cfg != nil && cfg.Project.Name != "" {
		project = cfg.Project.Name
	}
	if cfg != nil && cfg.Version != "" {
		version = cfg.Version
	}

	index, err := sci.Build(projectRoot, project, version)
	if err != nil {
		fmt.Fprintf(stderr, "gofusa sci: %v\n", err)
		return 1
	}

	w := stdout
	if *output != "" {
		f, err := os.Create(*output)
		if err != nil {
			fmt.Fprintf(stderr, "gofusa sci: create output: %v\n", err)
			return 1
		}
		defer func() { _ = f.Close() }()
		w = f
	}

	if err := sci.Render(w, index, *format); err != nil {
		fmt.Fprintf(stderr, "gofusa sci: render: %v\n", err)
		return 1
	}
	present := 0
	for _, it := range index.Items {
		if it.Present {
			present++
		}
	}
	fmt.Fprintf(stdout, "SCI: %d / %d lifecycle data items present\n", present, len(index.Items))
	return 0
}
