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
		//fusa:req REQ-CLI-TRACE003
		reqCoverage = fs.Int("req-coverage", 0, "exit 1 if requirement coverage or function annotation density is below N%% (0 = disabled)")
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

	if *reqCoverage > 0 {
		return runTraceReqCoverage(projectRoot, matrix, *reqCoverage, stdout, stderr)
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

// runTraceReqCoverage reports requirement-to-source coverage (metric 1) and
// exported-function annotation density (metric 2), exiting 1 if either falls
// below threshold when the metric has data.
//
//fusa:req REQ-CLI-TRACE003
func runTraceReqCoverage(root string, matrix *trace.Matrix, threshold int, stdout, stderr io.Writer) int {
	fc, err := trace.ScanFuncCoverage(root, matrix.Tags)
	if err != nil {
		fmt.Fprintf(stderr, "gofusa trace: scan func coverage: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "Requirement Coverage Report\n\n")

	m1na := matrix.Coverage.TotalRequirements == 0
	reqPct := 0
	if m1na {
		fmt.Fprintf(stdout, "Metric 1 — Requirement traceability:  N/A (no requirements defined)\n")
	} else {
		reqPct = matrix.Coverage.TracedRequirements * 100 / matrix.Coverage.TotalRequirements
		fmt.Fprintf(stdout, "Metric 1 — Requirement traceability:  %d%% (%d/%d requirements traced)\n",
			reqPct, matrix.Coverage.TracedRequirements, matrix.Coverage.TotalRequirements)
		traced := make(map[string]bool)
		for _, t := range matrix.Tags {
			if t.Kind == trace.KindImpl {
				traced[t.RequirementID] = true
			}
		}
		for _, req := range matrix.Requirements {
			if !traced[req.ID] {
				fmt.Fprintf(stdout, "  UNTRACED  %-20s  %s\n", req.ID, req.Title)
			}
		}
	}

	m2na := fc.Total == 0
	funcPct := int(fc.Pct)
	if m2na {
		fmt.Fprintf(stdout, "\nMetric 2 — Function annotation density: N/A (no exported functions found)\n")
	} else {
		fmt.Fprintf(stdout, "\nMetric 2 — Function annotation density: %d%% (%d/%d functions in annotated files)\n",
			funcPct, fc.Covered, fc.Total)
		shown := 0
		for _, fn := range fc.Uncovered {
			if shown >= 20 {
				fmt.Fprintf(stdout, "  ... and %d more\n", len(fc.Uncovered)-shown)
				break
			}
			fmt.Fprintf(stdout, "  UNANNOTATED  %s\n", fn)
			shown++
		}
	}

	failed := false
	if !m1na && reqPct < threshold {
		fmt.Fprintf(stderr, "gofusa trace: req-coverage gate failed (metric 1: %d%% < required %d%%)\n", reqPct, threshold)
		failed = true
	}
	if !m2na && funcPct < threshold {
		fmt.Fprintf(stderr, "gofusa trace: req-coverage gate failed (metric 2: %d%% < required %d%%)\n", funcPct, threshold)
		failed = true
	}
	if failed {
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
