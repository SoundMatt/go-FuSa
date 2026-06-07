// Command gofusa is the go-FuSa functional safety toolkit CLI.
//
// Usage:
//
//	gofusa <command> [flags]
//
// Commands:
//
//	init     Initialise a go-FuSa project configuration
//	check    Run safety checks (exits 1 on ERROR findings)
//	report   Generate a safety compliance report
//	version  Print the go-FuSa version
//
// Run 'gofusa <command> --help' for per-command flags.
package main

import (
	"fmt"
	"io"
	"os"

	// Blank imports activate built-in rule sets registered via init().
	_ "github.com/SoundMatt/go-FuSa/analyze" // v0.3 static-analysis rules
	_ "github.com/SoundMatt/go-FuSa/lint"    // v0.2 coding-standard rules
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stdout)
		return 1
	}
	switch args[0] {
	case "init":
		return runInit(args[1:], stdout, stderr)
	case "check":
		return runCheck(args[1:], stdout, stderr)
	case "report":
		return runReport(args[1:], stdout, stderr)
	case "version":
		return runVersion(stdout)
	case "help", "--help", "-h":
		usage(stdout)
		return 0
	default:
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
	fmt.Fprintf(w, "  init     Initialise a go-FuSa project configuration\n")
	fmt.Fprintf(w, "  check    Run safety checks (exits 1 on ERROR findings)\n")
	fmt.Fprintf(w, "  report   Generate a safety compliance report\n")
	fmt.Fprintf(w, "  version  Print the go-FuSa version\n")
	fmt.Fprintf(w, "\nRun 'gofusa <command> --help' for command-specific flags.\n")
}
