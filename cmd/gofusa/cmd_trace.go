package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/SoundMatt/go-FuSa/trace"
)

//fusa:req REQ-CLI017
func runTrace(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa trace", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: gofusa trace [flags]\n\n")
		fmt.Fprintf(stderr, "Show the requirements traceability matrix.\n\n")
		fmt.Fprintf(stderr, "Flags:\n")
		fs.PrintDefaults()
	}

	var (
		dir    = fs.String("dir", "", "project root directory (default: current directory)")
		format = fs.String("format", "text", "output format: text or json")
		output = fs.String("output", "", "write output to file (default: stdout)")
		gaps   = fs.Bool("gaps", false, "show only requirements with no //fusa:test tag (test coverage gaps)")
		//fusa:req REQ-CLI-TRACE001
		secTested = fs.Int("sec-tested", 0, "exit 1 if fewer than N%% of requirements have //fusa:test tags (0 = disabled)")
	)
	if err := fs.Parse(args); err != nil {
		return 1
	}

	projectRoot := *dir
	if projectRoot == "" {
		var err error
		projectRoot, err = os.Getwd()
		if err != nil {
			fmt.Fprintf(stderr, "gofusa trace: get working directory: %v\n", err)
			return 1
		}
	}

	matrix, err := trace.Build(projectRoot)
	if err != nil {
		fmt.Fprintf(stderr, "gofusa trace: %v\n", err)
		return 1
	}

	if *gaps {
		return runTraceGaps(matrix, stdout, stderr)
	}

	if *secTested > 0 {
		return runTraceSecTested(matrix, *secTested, stdout, stderr)
	}

	w := stdout
	if *output != "" {
		f, err := os.Create(*output)
		if err != nil {
			fmt.Fprintf(stderr, "gofusa trace: create output: %v\n", err)
			return 1
		}
		defer func() { _ = f.Close() }()
		w = f
	}

	if err := trace.Render(w, matrix, *format); err != nil {
		fmt.Fprintf(stderr, "gofusa trace: render: %v\n", err)
		return 1
	}
	return 0
}

// runTraceSecTested exits 1 if test coverage is below threshold percent.
//
//fusa:req REQ-CLI-TRACE002
func runTraceSecTested(matrix *trace.Matrix, threshold int, stdout, stderr io.Writer) int {
	if len(matrix.Requirements) == 0 {
		fmt.Fprintf(stdout, "sec-tested: no requirements found\n")
		return 0
	}
	tested := make(map[string]bool)
	for _, t := range matrix.Tags {
		if t.Kind == trace.KindTest {
			tested[t.RequirementID] = true
		}
	}
	pct := len(tested) * 100 / len(matrix.Requirements)
	fmt.Fprintf(stdout, "sec-tested: %d%% (%d/%d requirements have //fusa:test tags)\n",
		pct, len(tested), len(matrix.Requirements))
	if pct < threshold {
		fmt.Fprintf(stderr, "gofusa trace: sec-tested gate failed: %d%% < required %d%%\n", pct, threshold)
		return 1
	}
	return 0
}

// runTraceGaps prints requirements that have no //fusa:test tag.
//
//fusa:req REQ-REQQ002
func runTraceGaps(matrix *trace.Matrix, stdout, _ io.Writer) int {
	tested := make(map[string]bool)
	for _, t := range matrix.Tags {
		if t.Kind == trace.KindTest {
			tested[t.RequirementID] = true
		}
	}

	var gaps []trace.Requirement
	for _, req := range matrix.Requirements {
		if !tested[req.ID] {
			gaps = append(gaps, req)
		}
	}

	fmt.Fprintf(stdout, "Test coverage gaps: %d / %d requirements untested\n\n",
		len(gaps), len(matrix.Requirements))
	for _, req := range gaps {
		fmt.Fprintf(stdout, "  %-20s  %s\n", req.ID, req.Title)
	}
	if len(gaps) > 0 {
		return 1
	}
	return 0
}
