package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/config"
	"github.com/SoundMatt/go-FuSa/coupling"
)

//fusa:req REQ-CLI-COUPLING001
func runCoupling(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa coupling", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: gofusa coupling [flags]\n\n")
		fmt.Fprintf(stderr, "Analyse data and control coupling between packages (DO-178C §6.4.4.3).\n")
		fmt.Fprintf(stderr, "Writes coupling-report.json as evidence of coupling characterisation.\n\n")
		fmt.Fprintf(stderr, "Flags:\n")
		fs.PrintDefaults()
	}
	var (
		dir    = fs.String("dir", "", "project root directory (default: current directory)")
		output = fs.String("output", "", "output file (default: <dir>/coupling-report.json)")
	)
	if code := parseFlags(fs, args); code != 0 {
		return code
	}

	projectRoot := *dir
	if projectRoot == "" {
		var err error
		projectRoot, err = os.Getwd()
		if err != nil {
			fmt.Fprintf(stderr, "gofusa coupling: get working directory: %v\n", err)
			return fusa.ExitRuntime
		}
	}

	outPath := *output
	if outPath == "" {
		outPath = filepath.Join(projectRoot, coupling.CouplingReportFile)
	}

	cfg, _ := config.Load(filepath.Join(projectRoot, ".fusa.json"))

	dataRule := coupling.NewDataCouplingRule()
	ctrlRule := coupling.NewControlCouplingRule()

	dataFindings, err := dataRule.Run(context.Background(), projectRoot, cfg)
	if err != nil {
		fmt.Fprintf(stderr, "gofusa coupling: data coupling scan: %v\n", err)
		return fusa.ExitRuntime
	}
	ctrlFindings, err := ctrlRule.Run(context.Background(), projectRoot, cfg)
	if err != nil {
		fmt.Fprintf(stderr, "gofusa coupling: control coupling scan: %v\n", err)
		return fusa.ExitRuntime
	}

	if err := coupling.SaveReport(outPath, dataFindings, ctrlFindings, projectRoot); err != nil {
		fmt.Fprintf(stderr, "gofusa coupling: save report: %v\n", err)
		return fusa.ExitRuntime
	}

	fmt.Fprintf(stdout, "Coupling report written to %s (%d data, %d control)\n",
		outPath, len(dataFindings), len(ctrlFindings))
	return fusa.ExitOK
}
