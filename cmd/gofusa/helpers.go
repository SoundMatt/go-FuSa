package main

import (
	"flag"
	"fmt"
	"io"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/disposition"
	"github.com/SoundMatt/go-FuSa/stubcheck"
)

// parseFlags parses a command's flag set and returns fusa.ExitUsage on error.
// Use in place of the inline `if err := fs.Parse(args); err != nil { return 1 }` pattern.
//
//fusa:req REQ-CLI-HELPERS001
func parseFlags(fs *flag.FlagSet, args []string) int {
	if err := fs.Parse(args); err != nil {
		return fusa.ExitUsage
	}
	return fusa.ExitOK
}

// usageErrorf prints a usage-error message to stderr and returns ExitUsage (2).
//
//fusa:req REQ-CLI-HELPERS002
func usageErrorf(stderr io.Writer, cmd, format string, a ...any) int {
	fmt.Fprintf(stderr, "gofusa %s: %s\n", cmd, fmt.Sprintf(format, a...))
	return fusa.ExitUsage
}

// runtimeErrorf prints a runtime-error message to stderr and returns ExitRuntime (3).
//
//fusa:req REQ-CLI-HELPERS003
func runtimeErrorf(stderr io.Writer, cmd, format string, a ...any) int {
	fmt.Fprintf(stderr, "gofusa %s: %s\n", cmd, fmt.Sprintf(format, a...))
	return fusa.ExitRuntime
}

// gateContentQuality runs the x-FuSa spec §1.6.1 content-quality scans
// (FUSA-STUB001/002) against an artifact's own extracted qualitative fields
// and prints any findings to stderr. It returns fusa.ExitGateFail when an
// undispositioned FUSA-STUB001 placeholder match was found (gating, per
// §1.6.1 rule A), or when an unsuppressed FUSA-STUB002 match was found and
// strict is true (--strict/--require-attestation, per §1.6.2); otherwise
// ExitOK. FUSA-STUB002 is suppressed when att is a valid, non-stale,
// independent §1.6.2 attestation over content — never by disposition
// (§1.6.1 rule A vs rule B use two different, deliberately non-overlapping
// escape hatches). FUSA-STUB001 is suppressed only by a per-finding
// disposition entry in projectRoot's .fusa-dispositions.json (§1.2.3/§4.1),
// never by attestation — a project that has reviewed and accepted a
// FUSA-STUB001 finding as a legitimate false positive (e.g. a hazard
// description that happens to contain a deny-listed substring) records that
// via 'gofusa disposition add --rule FUSA-STUB001 ...', the same mechanism
// `check`'s own ERROR-finding gate honours.
//
//fusa:req REQ-CLI-HELPERS004
//fusa:req REQ-STUB013
func gateContentQuality(stderr io.Writer, cmd, projectRoot, artifactFile string, fields []stubcheck.Field, att *fusa.Attestation, content interface{}, strict bool) int {
	code := fusa.ExitOK

	dispLog, dispErr := disposition.Load(projectRoot)
	if dispErr != nil || dispLog == nil {
		// Absent/unreadable dispositions log: fail-safe, nothing is
		// dispositioned, every FUSA-STUB001 match still gates.
		dispLog = &disposition.Log{}
	}
	stub001Dispositioned := disposition.IsDispositioned(dispLog, stubcheck.RuleStub001)

	placeholders := stubcheck.ScanPlaceholders(fields)
	if stub001Dispositioned {
		if len(placeholders) > 0 {
			fmt.Fprintf(stderr, "gofusa %s: %s: %d placeholder match(es) suppressed by disposition entry in %s\n",
				cmd, stubcheck.RuleStub001, len(placeholders), disposition.DispositionsFile)
		}
	} else {
		for _, m := range placeholders {
			f := stubcheck.PlaceholderFinding(artifactFile, m)
			fmt.Fprintf(stderr, "gofusa %s: %s: %s\n", cmd, f.RuleID, f.Message)
		}
		if len(placeholders) > 0 {
			code = fusa.ExitGateFail
		}
	}

	blanket := stubcheck.ScanBlanketFallback(fields)
	if len(blanket) > 0 && !stubcheck.AttestationSuppresses(att, content) {
		for _, m := range blanket {
			f := stubcheck.BlanketFallbackFinding(artifactFile, m)
			fmt.Fprintf(stderr, "gofusa %s: %s (advisory): %s\n", cmd, f.RuleID, f.Message)
		}
		if strict {
			code = fusa.ExitGateFail
		}
	}
	return code
}
