package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/engine"
	"github.com/SoundMatt/go-FuSa/qualify"
)

func runQualify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa qualify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: gofusa qualify [flags]\n\n")
		fmt.Fprintf(stderr, "Run the built-in tool qualification suite and save a qualification report.\n")
		fmt.Fprintf(stderr, "The report can be submitted as tool confidence evidence in regulated environments.\n\n")
		fmt.Fprintf(stderr, "Flags:\n")
		fs.PrintDefaults()
	}

	var (
		// §6: qualify accepts --dir/--format for CLI-surface parity with the
		// other §9.1 MUST commands, even though the qualification suite
		// itself always runs the same built-in synthetic cases regardless of
		// project content — --dir only affects the default --output
		// location (mirroring how other commands resolve projectRoot).
		//fusa:req REQ-QUALIFY011
		dir        = fs.String("dir", "", "project root directory (default: current directory); only affects the default --output location")
		format     = fs.String("format", "text", "output format: text, json (both write the same qualification report; controls stdout presentation)")
		outputFile = fs.String("output", "", "path for the JSON qualification report (default: ./qualify-report.json)")
		// Feature 2 — tool qualification display
		//fusa:req REQ-QUALIFY007
		qualMethod = fs.String("qualification-method", "", `qualification method: "self" or "independent"`)
		qualifier  = fs.String("qualifier", "", "name or organisation performing the qualification")
		recordURI  = fs.String("record-uri", "", "URI to the qualification dossier / evidence record")
		// Feature 4 — V&V independence
		//fusa:req REQ-QUALIFY008
		implAuthor  = fs.String("implementation-author", "", "name of the implementation author")
		indReviewer = fs.String("independent-reviewer", "", "name of the independent reviewer")
		indTestExec = fs.String("independent-test-executor", "", "name of the independent test executor")
		achieveASIL = fs.String("achievable-asil", "", "achievable ASIL level when independence requirements are met")
	)
	if code := parseFlags(fs, args); code != 0 {
		return code
	}

	switch *format {
	case "text", "json", "":
		// ok
	default:
		fmt.Fprintf(stderr, "gofusa qualify: unknown format %q (must be text or json)\n", *format)
		return fusa.ExitUsage
	}

	projectRoot := *dir
	if projectRoot == "" {
		var err error
		projectRoot, err = os.Getwd()
		if err != nil {
			fmt.Fprintf(stderr, "gofusa qualify: get working directory: %v\n", err)
			return fusa.ExitRuntime
		}
	}

	outPath := *outputFile
	if outPath == "" {
		outPath = filepath.Join(projectRoot, qualify.ReportFile)
	}

	fmt.Fprintf(stdout, "Running %d qualification case(s)...\n", len(qualify.BuiltinCases()))

	report, err := qualify.Run(context.Background(), engine.Default, qualify.BuiltinCases())
	if err != nil {
		fmt.Fprintf(stderr, "gofusa qualify: %v\n", err)
		return fusa.ExitRuntime
	}

	// Apply qualification metadata flags.
	//fusa:req REQ-QUALIFY007
	if *qualMethod != "" {
		report.QualificationMethod = *qualMethod
	}
	if *qualifier != "" {
		report.QualifierIdentity = *qualifier
	}
	if *recordURI != "" {
		report.QualificationRecordUri = *recordURI
	}
	// Apply V&V independence flags.
	//fusa:req REQ-QUALIFY008
	if *implAuthor != "" {
		report.ImplementationAuthor = *implAuthor
	}
	if *indReviewer != "" {
		report.IndependentReviewer = *indReviewer
	}
	if *indTestExec != "" {
		report.IndependentTestExecutor = *indTestExec
	}
	if *achieveASIL != "" {
		report.AchievableASIL = *achieveASIL
	}

	fmt.Fprintf(stdout, "Results: %d/%d passed", report.Passed, report.Total)
	if report.HasFailures() {
		fmt.Fprintf(stdout, " (%d failed)\n", report.Failed)
		for _, r := range report.Results {
			if !r.Passed {
				fmt.Fprintf(stdout, "  FAIL  %s: %s\n", r.Case.Name, r.Error)
			}
		}
	} else {
		fmt.Fprintf(stdout, " — all passed\n")
	}

	// Show qualification badge and independence status.
	//fusa:req REQ-QUALIFY007
	fmt.Fprintf(stdout, "Qualification badge: %s\n", report.QualificationBadge())
	//fusa:req REQ-QUALIFY008
	fmt.Fprintf(stdout, "Independence status: %s\n", report.IndependenceStatus())

	if err := qualify.Save(outPath, report); err != nil {
		fmt.Fprintf(stderr, "gofusa qualify: save report: %v\n", err)
		return fusa.ExitRuntime
	}
	fmt.Fprintf(stdout, "Qualification report written to %s\n", outPath)
	fmt.Fprintf(stdout, "Integrity hash: %s\n", report.Hash)

	if report.HasFailures() {
		return fusa.ExitRuntime
	}
	//fusa:req REQ-CLI007
	return fusa.ExitOK
}
