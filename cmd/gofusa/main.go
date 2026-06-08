// Command gofusa is the go-FuSa functional safety toolkit CLI.
//
// Usage:
//
//	gofusa <command> [flags]
//
// Commands:
//
//	init         Initialise a go-FuSa project configuration
//	check        Run all safety checks (exits 1 on ERROR findings)
//	lint         Run coding-standard checks only (LINT rules)
//	analyze      Run static analysis checks only (ANA rules)
//	report       Generate a safety compliance report
//	template     Generate safety documentation templates
//	trace        Show requirements traceability matrix
//	verify       Run tests and save a test evidence bundle
//	release      Generate SBOM (SPDX 3.0.1), provenance, and artifact manifest
//	qualify      Run the tool qualification suite
//	safety-case  Assemble a structured safety case from evidence
//	fmea         Generate a dFMEA table from exported functions
//	boundary     Generate a component boundary diagram
//	version      Print the go-FuSa version
//
// Run 'gofusa <command> --help' for per-command flags.
package main

import (
	"fmt"
	"io"
	"os"

	// Blank imports activate built-in rule sets registered via init().
	_ "github.com/SoundMatt/go-FuSa/analyze"  // v0.3 static-analysis rules
	_ "github.com/SoundMatt/go-FuSa/boundary" // v0.12 boundary-diagram rules
	_ "github.com/SoundMatt/go-FuSa/fmea"     // v0.12 dFMEA rules
	_ "github.com/SoundMatt/go-FuSa/lint"     // v0.2 coding-standard rules
	_ "github.com/SoundMatt/go-FuSa/qualify"  // v0.9 tool qualification rules
	_ "github.com/SoundMatt/go-FuSa/release"  // v0.6 release-evidence rules
	_ "github.com/SoundMatt/go-FuSa/trace"    // v0.4 traceability rules
	_ "github.com/SoundMatt/go-FuSa/verify"   // v0.5 test-evidence rules
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	//fusa:req REQ-CLI001
	if len(args) == 0 {
		usage(stdout)
		return 1
	}
	//fusa:req REQ-E2E001
	switch args[0] {
	case "init":
		return runInit(args[1:], stdout, stderr)
	case "check":
		return runCheck(args[1:], stdout, stderr)
	case "lint":
		return runLint(args[1:], stdout, stderr)
	case "analyze":
		return runAnalyze(args[1:], stdout, stderr)
	case "report":
		return runReport(args[1:], stdout, stderr)
	case "template":
		return runTemplate(args[1:], stdout, stderr)
	case "trace":
		return runTrace(args[1:], stdout, stderr)
	case "verify":
		return runVerify(args[1:], stdout, stderr)
	case "release":
		return runRelease(args[1:], stdout, stderr)
	case "qualify":
		return runQualify(args[1:], stdout, stderr)
	case "safety-case":
		return runSafetyCase(args[1:], stdout, stderr)
	case "fmea":
		return runFmea(args[1:], stdout, stderr)
	case "boundary":
		return runBoundary(args[1:], stdout, stderr)
	case "version":
		//fusa:req REQ-CLI004
		return runVersion(stdout)
	case "help", "--help", "-h":
		//fusa:req REQ-CLI003
		usage(stdout)
		return 0
	default:
		//fusa:req REQ-CLI002
		fmt.Fprintf(stderr, "gofusa: unknown command %q\n", args[0])
		fmt.Fprintf(stderr, "Run 'gofusa help' for usage.\n")
		return 1
	}
}

func usage(w io.Writer) {
	fmt.Fprintf(w, "gofusa — functional safety enablement toolkit for Go\n\n")
	fmt.Fprintf(w, "Usage:\n")
	fmt.Fprintf(w, "  gofusa <command> [flags]\n\n")
	fmt.Fprintf(w, "Commands:\n")
	fmt.Fprintf(w, "  init         Initialise a go-FuSa project configuration\n")
	fmt.Fprintf(w, "  check        Run all safety checks (exits 1 on ERROR findings)\n")
	fmt.Fprintf(w, "  lint         Run coding-standard checks only (LINT rules)\n")
	fmt.Fprintf(w, "  analyze      Run static analysis checks only (ANA rules)\n")
	fmt.Fprintf(w, "  report       Generate a safety compliance report\n")
	fmt.Fprintf(w, "  template     Generate safety documentation templates\n")
	fmt.Fprintf(w, "  trace        Show requirements traceability matrix\n")
	fmt.Fprintf(w, "  verify       Run tests and save a test evidence bundle\n")
	fmt.Fprintf(w, "  release      Generate SBOM (SPDX 3.0.1), provenance, and artifact manifest\n")
	fmt.Fprintf(w, "  qualify      Run the tool qualification suite\n")
	fmt.Fprintf(w, "  safety-case  Assemble a structured safety case from evidence\n")
	fmt.Fprintf(w, "  fmea         Generate a dFMEA table from exported functions\n")
	fmt.Fprintf(w, "  boundary     Generate a component boundary diagram\n")
	fmt.Fprintf(w, "  version      Print the go-FuSa version\n")
	fmt.Fprintf(w, "\nRun 'gofusa <command> --help' for command-specific flags.\n")
}
