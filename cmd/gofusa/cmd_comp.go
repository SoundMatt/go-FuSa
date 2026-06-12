package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/comp"
)

//fusa:req REQ-CLI-COMP-001
func runComp(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa comp", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: gofusa comp [flags]\n\n")
		fmt.Fprintf(stderr, "Report cyclomatic complexity of all non-test Go functions (DO-178C §6.3.4).\n")
		fmt.Fprintf(stderr, "Exits 1 if any function exceeds the threshold.\n\n")
		fmt.Fprintf(stderr, "Flags:\n")
		fs.PrintDefaults()
	}
	var (
		dir       = fs.String("dir", "", "project root directory (default: current directory)")
		dalFlag   = fs.String("dal", "", "DO-178C DAL level: DAL-A, DAL-B, DAL-C, DAL-D (sets threshold)")
		threshold = fs.Int("threshold", 0, "max cyclomatic complexity (overrides --dal; default 10)")
		format    = fs.String("format", "text", "output format: text or json")
		output    = fs.String("output", "", "write report to file (default: stdout)")
	)
	if code := parseFlags(fs, args); code != 0 {
		return code
	}
	if *format != "text" && *format != "json" {
		return usageErrorf(stderr, "comp", "unsupported format %q (text or json)", *format)
	}

	projectRoot := *dir
	if projectRoot == "" {
		var err error
		projectRoot, err = os.Getwd()
		if err != nil {
			return runtimeErrorf(stderr, "comp", "get working directory: %v", err)
		}
	}

	th := *threshold
	if th == 0 {
		th = comp.ThresholdForDAL(*dalFlag)
	}

	results, err := comp.Assess(projectRoot, th)
	if err != nil {
		return runtimeErrorf(stderr, "comp", "assess: %v", err)
	}

	w := stdout
	if *output != "" {
		f, err := os.Create(filepath.Clean(*output))
		if err != nil {
			return runtimeErrorf(stderr, "comp", "create output: %v", err)
		}
		defer func() { _ = f.Close() }()
		w = f
	}

	exceeding := 0
	for _, r := range results {
		if r.Exceeds {
			exceeding++
		}
	}

	switch *format {
	case "json":
		type compReport struct {
			Kind      string                `json:"kind"`
			Tool      string                `json:"tool"`
			Threshold int                   `json:"threshold"`
			DAL       string                `json:"dal,omitempty"`
			Total     int                   `json:"total"`
			Exceeding int                   `json:"exceeding"`
			Functions []comp.FunctionResult `json:"functions"`
		}
		rep := compReport{
			Kind:      "comp-report",
			Tool:      "go-FuSa",
			Threshold: th,
			DAL:       *dalFlag,
			Total:     len(results),
			Exceeding: exceeding,
			Functions: results,
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			return runtimeErrorf(stderr, "comp", "encode: %v", err)
		}
	default:
		fmt.Fprintf(w, "Cyclomatic Complexity Report (threshold %d", th)
		if *dalFlag != "" {
			fmt.Fprintf(w, ", %s", *dalFlag)
		}
		fmt.Fprintf(w, ")\n\n")
		fmt.Fprintf(w, "%-8s  %-6s  %s\n", "COMP", "LINE", "FUNCTION")
		fmt.Fprintf(w, "%-8s  %-6s  %s\n", "--------", "------", "--------")
		for _, r := range results {
			if r.Exceeds {
				rel := r.File
				if rel2, err := filepath.Rel(projectRoot, r.File); err == nil {
					rel = rel2
				}
				fmt.Fprintf(w, "%-8d  %-6d  %s  (%s)\n", r.Complexity, r.Line, r.Name, rel)
			}
		}
		fmt.Fprintf(w, "\nTotal functions: %d  Exceeding threshold: %d\n", len(results), exceeding)
	}

	if exceeding > 0 {
		return fusa.ExitGateFail
	}
	return fusa.ExitOK
}
