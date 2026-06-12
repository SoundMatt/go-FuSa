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
//	cyber        Run cybersecurity analysis (CYBER rules)
//	report       Generate a safety compliance report
//	template     Generate safety documentation templates
//	trace        Show requirements traceability matrix
//	verify       Run tests and save a test evidence bundle
//	release      Generate SBOM (SPDX 2.2/2.3/3.0.1), provenance, and artifact manifest
//	qualify      Run the tool qualification suite
//	safety-case  Assemble a structured safety case from evidence
//	fmea         Generate a dFMEA table from exported functions
//	boundary     Generate a component boundary diagram
//	coupling     Analyse data/control coupling and write coupling-report.json
//	tara         Generate a Threat Analysis and Risk Assessment (ISO 21434)
//	hara         Manage the Hazard Analysis and Risk Assessment (.fusa-hara.json)
//	vuln         Scan dependencies for known vulnerabilities (OSV / ISO 21434)
//	audit-pack   Bundle all evidence artifacts into a single ZIP for auditors
//	diff         Compare two check report JSON files (introduced/resolved/unchanged)
//	badge        Generate an SVG status badge from a check report
//	req          Show, import, or export requirements (CSV import/export)
//	fix          Show auto-fixable findings with remediation guidance
//	hooks        Install/remove git pre-commit hook
//	sign         Sign or verify a file with HMAC-SHA256
//	do178        Generate a DO-178C Annex A compliance gap report
//	iso21434     Generate an ISO 21434 cybersecurity compliance gap report
//	iso26262     Generate an ISO 26262 Part 6 compliance gap report
//	iec61508     Generate an IEC 61508 Parts 1-3 compliance gap report
//	iec62443     Generate an IEC 62443-4-2 IACS cybersecurity gap report
//	slsa         Generate a SLSA v1.0 supply-chain integrity gap report
//	unece        Generate a UN R.155 cybersecurity compliance gap report
//	sas          Generate a Software Accomplishment Summary (DO-178C §11.20)
//	sci          Generate a Software Configuration Index (DO-178C §11.16)
//	coverage     Analyse structural coverage from a Go coverage profile
//	pr           Manage software problem reports (DO-178C §11.17)
//	disposition  Manage finding disposition entries
//	impact       Analyse change impact on requirements and safety artefacts
//	metrics      Track safety metrics over time
//	comp         Report cyclomatic complexity of all non-test Go functions (DO-178C §6.3.4)
//	misra        Show MISRA C:2023 to Go / go-FuSa rule coverage mapping
//	version      Print the go-FuSa version
//
// Run 'gofusa <command> --help' for per-command flags.
package main

import (
	"fmt"
	"io"
	"os"

	fusa "github.com/SoundMatt/go-FuSa"

	// Blank imports activate built-in rule sets registered via init().
	_ "github.com/SoundMatt/go-FuSa/analyze"     // v0.3 static-analysis rules
	_ "github.com/SoundMatt/go-FuSa/auditpack"   // v0.13 audit-pack rules
	_ "github.com/SoundMatt/go-FuSa/boundary"    // v0.12 boundary-diagram rules
	_ "github.com/SoundMatt/go-FuSa/comp"        // v0.18 cyclomatic complexity rule
	_ "github.com/SoundMatt/go-FuSa/coupling"    // v0.18 data/control coupling rules
	_ "github.com/SoundMatt/go-FuSa/cyber"       // v0.14–v0.15 cybersecurity analysis rules
	_ "github.com/SoundMatt/go-FuSa/disposition" // v0.20 disposition rules
	_ "github.com/SoundMatt/go-FuSa/fmea"        // v0.12 dFMEA rules
	_ "github.com/SoundMatt/go-FuSa/hara"        // v0.21 HARA rules
	_ "github.com/SoundMatt/go-FuSa/iec61508"    // v0.20 IEC 61508 gap report rules
	_ "github.com/SoundMatt/go-FuSa/iec62443"    // v0.15 IEC 62443 evidence rules
	_ "github.com/SoundMatt/go-FuSa/iso21434"    // v0.23 ISO 21434 gap report rules
	_ "github.com/SoundMatt/go-FuSa/iso26262"    // v0.20 ISO 26262 gap report rules
	_ "github.com/SoundMatt/go-FuSa/lint"        // v0.2 coding-standard rules
	_ "github.com/SoundMatt/go-FuSa/pr"          // v0.18 problem report rule
	_ "github.com/SoundMatt/go-FuSa/qualify"     // v0.9 tool qualification rules
	_ "github.com/SoundMatt/go-FuSa/release"     // v0.6 release-evidence rules
	_ "github.com/SoundMatt/go-FuSa/slsa"        // v0.15 SLSA supply-chain rules
	_ "github.com/SoundMatt/go-FuSa/tara"        // v0.15 TARA engine rule
	_ "github.com/SoundMatt/go-FuSa/trace"       // v0.4 traceability rules
	_ "github.com/SoundMatt/go-FuSa/unece"       // v0.23 UN R.155 gap report rules
	_ "github.com/SoundMatt/go-FuSa/verify"      // v0.5 test-evidence rules
	_ "github.com/SoundMatt/go-FuSa/vuln"        // v0.13–v0.15 vulnerability rules
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	// Strip --no-color before dispatch; renderers check os.Getenv("NO_COLOR").
	args = stripNoColor(args)

	//fusa:req REQ-CLI001
	if len(args) == 0 {
		usage(stdout)
		return fusa.ExitUsage
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
	case "cyber":
		return runCyber(args[1:], stdout, stderr)
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
	case "coupling":
		return runCoupling(args[1:], stdout, stderr)
	case "tara":
		return runTara(args[1:], stdout, stderr)
	case "hara":
		return runHara(args[1:], stdout, stderr)
	case "vuln":
		return runVuln(args[1:], stdout, stderr)
	case "audit-pack":
		return runAuditPack(args[1:], stdout, stderr)
	case "diff":
		return runDiff(args[1:], stdout, stderr)
	case "badge":
		return runBadge(args[1:], stdout, stderr)
	case "req":
		return runReq(args[1:], stdout, stderr)
	case "fix":
		return runFix(args[1:], stdout, stderr)
	case "hooks":
		return runHooks(args[1:], stdout, stderr)
	case "sign":
		return runSign(args[1:], stdout, stderr)
	case "do178":
		return runDo178(args[1:], stdout, stderr)
	case "iso21434":
		return runISO21434(args[1:], stdout, stderr)
	case "iso26262":
		return runISO26262(args[1:], stdout, stderr)
	case "iec61508":
		return runIEC61508(args[1:], stdout, stderr)
	case "iec62443":
		return runIEC62443(args[1:], stdout, stderr)
	case "slsa":
		return runSLSA(args[1:], stdout, stderr)
	case "unece":
		return runUNECE(args[1:], stdout, stderr)
	case "sas":
		return runSas(args[1:], stdout, stderr)
	case "sci":
		return runSci(args[1:], stdout, stderr)
	case "coverage":
		return runCoverage(args[1:], stdout, stderr)
	case "pr":
		return runPR(args[1:], stdout, stderr)
	case "disposition":
		return runDisposition(args[1:], stdout, stderr)
	case "impact":
		return runImpact(args[1:], stdout, stderr)
	case "metrics":
		return runMetrics(args[1:], stdout, stderr)
	case "comp":
		return runComp(args[1:], stdout, stderr)
	case "misra":
		return runMisra(args[1:], stdout, stderr)
	case "capabilities":
		return runCapabilities(args[1:], stdout, stderr)
	case "version":
		//fusa:req REQ-CLI004
		return runVersion(args[1:], stdout, stderr)
	case "help", "--help", "-h":
		//fusa:req REQ-CLI003
		usage(stdout)
		return fusa.ExitOK
	default:
		//fusa:req REQ-CLI002
		fmt.Fprintf(stderr, "gofusa: unknown command %q\n", args[0])
		fmt.Fprintf(stderr, "Run 'gofusa help' for usage.\n")
		return fusa.ExitUsage
	}
}

// stripNoColor removes --no-color from args and sets NO_COLOR env var (§2.6).
func stripNoColor(args []string) []string {
	out := args[:0:len(args)]
	for _, a := range args {
		if a == "--no-color" || a == "-no-color" {
			_ = os.Setenv("NO_COLOR", "1")
		} else {
			out = append(out, a)
		}
	}
	return out
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
	fmt.Fprintf(w, "  cyber        Run cybersecurity analysis (CYBER001–CYBER020)\n")
	fmt.Fprintf(w, "  report       Generate a safety compliance report\n")
	fmt.Fprintf(w, "  template     Generate safety documentation templates\n")
	fmt.Fprintf(w, "  trace        Show requirements traceability matrix\n")
	fmt.Fprintf(w, "  verify       Run tests and save a test evidence bundle\n")
	fmt.Fprintf(w, "  release      Generate SBOM (SPDX 2.2/2.3/3.0.1), provenance, and artifact manifest\n")
	fmt.Fprintf(w, "  qualify      Run the tool qualification suite\n")
	fmt.Fprintf(w, "  safety-case  Assemble a structured safety case from evidence\n")
	fmt.Fprintf(w, "  fmea         Generate a dFMEA table from exported functions\n")
	fmt.Fprintf(w, "  boundary     Generate a component boundary diagram\n")
	fmt.Fprintf(w, "  coupling     Analyse data/control coupling and write coupling-report.json\n")
	fmt.Fprintf(w, "  tara         Generate a Threat Analysis and Risk Assessment (ISO 21434)\n")
	fmt.Fprintf(w, "  hara         Manage the Hazard Analysis and Risk Assessment (.fusa-hara.json)\n")
	fmt.Fprintf(w, "  vuln         Scan dependencies for known vulnerabilities (OSV / ISO 21434)\n")
	fmt.Fprintf(w, "  audit-pack   Bundle all evidence artifacts into a single ZIP for auditors\n")
	fmt.Fprintf(w, "  diff         Compare two check report JSON files (introduced/resolved/unchanged)\n")
	fmt.Fprintf(w, "  badge        Generate an SVG status badge from a check report\n")
	fmt.Fprintf(w, "  req          Show, import, or export requirements (CSV import/export)\n")
	fmt.Fprintf(w, "  fix          Show auto-fixable findings with remediation guidance\n")
	fmt.Fprintf(w, "  hooks        Install/remove git pre-commit hook\n")
	fmt.Fprintf(w, "  sign         Sign or verify a file with HMAC-SHA256\n")
	fmt.Fprintf(w, "  do178        Generate a DO-178C Annex A compliance gap report\n")
	fmt.Fprintf(w, "  iso21434     Generate an ISO 21434 cybersecurity compliance gap report\n")
	fmt.Fprintf(w, "  iso26262     Generate an ISO 26262 Part 6 compliance gap report\n")
	fmt.Fprintf(w, "  iec61508     Generate an IEC 61508 Parts 1-3 compliance gap report\n")
	fmt.Fprintf(w, "  iec62443     Generate an IEC 62443-4-2 IACS cybersecurity gap report\n")
	fmt.Fprintf(w, "  slsa         Generate a SLSA v1.0 supply-chain integrity gap report\n")
	fmt.Fprintf(w, "  unece        Generate a UN R.155 cybersecurity compliance gap report\n")
	fmt.Fprintf(w, "  sas          Generate a Software Accomplishment Summary (DO-178C §11.20)\n")
	fmt.Fprintf(w, "  sci          Generate a Software Configuration Index (DO-178C §11.16)\n")
	fmt.Fprintf(w, "  coverage     Analyse structural coverage from a Go coverage profile\n")
	fmt.Fprintf(w, "  pr           Manage software problem reports (DO-178C §11.17)\n")
	fmt.Fprintf(w, "  disposition  Manage finding disposition entries\n")
	fmt.Fprintf(w, "  impact       Analyse change impact on requirements and safety artefacts\n")
	fmt.Fprintf(w, "  metrics      Track safety metrics over time\n")
	fmt.Fprintf(w, "  comp         Report cyclomatic complexity of non-test functions (DO-178C §6.3.4)\n")
	fmt.Fprintf(w, "  misra        Show MISRA C:2023 to Go / go-FuSa rule coverage mapping\n")
	fmt.Fprintf(w, "  capabilities Report tool capabilities (commands, formats, standards)\n")
	fmt.Fprintf(w, "  version      Print the go-FuSa version\n")
	fmt.Fprintf(w, "\nRun 'gofusa <command> --help' for command-specific flags.\n")
}
