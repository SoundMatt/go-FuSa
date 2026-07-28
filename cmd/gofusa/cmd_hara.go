package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/hara"
	"github.com/SoundMatt/go-FuSa/stubcheck"
	"github.com/SoundMatt/go-FuSa/trace"
)

//fusa:req REQ-CLI-HARA001
func runHara(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa hara", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: gofusa hara <subcommand> [flags]\n\n")
		fmt.Fprintf(stderr, "Manage the Hazard Analysis and Risk Assessment (.fusa-hara.json).\n\n")
		fmt.Fprintf(stderr, "Subcommands:\n")
		fmt.Fprintf(stderr, "  show    Display HARA as text or JSON (default)\n")
		fmt.Fprintf(stderr, "  init    Create a starter .fusa-hara.json\n")
		fmt.Fprintf(stderr, "  asil    Derive ASIL from S/E/C parameters\n")
		fmt.Fprintf(stderr, "\nFlags:\n")
		fs.PrintDefaults()
	}
	dir := fs.String("dir", "", "project root directory (default: current directory)")
	if code := parseFlags(fs, args); code != 0 {
		return code
	}

	projectRoot := *dir
	if projectRoot == "" {
		var err error
		projectRoot, err = os.Getwd()
		if err != nil {
			fmt.Fprintf(stderr, "gofusa hara: get working directory: %v\n", err)
			return fusa.ExitRuntime
		}
	}

	sub := fs.Arg(0)
	subArgs := fs.Args()
	if len(subArgs) > 0 {
		subArgs = subArgs[1:]
	}

	switch sub {
	case "", "show":
		return runHaraShow(subArgs, projectRoot, stdout, stderr)
	case "init":
		return runHaraInit(subArgs, projectRoot, stdout, stderr)
	case "asil":
		return runHaraASIL(subArgs, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "gofusa hara: unknown subcommand %q\n", sub)
		fmt.Fprintf(stderr, "Run 'gofusa hara --help' for usage.\n")
		return fusa.ExitUsage
	}
}

func runHaraShow(args []string, projectRoot string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa hara show", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "text", "output format: text, json, markdown")
	output := fs.String("output", "", "write output to file (default: stdout)")
	//fusa:req REQ-HARA022
	strict := fs.Bool("strict", false, "escalate an unsuppressed FUSA-STUB002 finding to exit 1 (implies --require-attestation)")
	requireAttestation := fs.Bool("require-attestation", false, "escalate an unsuppressed FUSA-STUB002 finding to exit 1")
	if code := parseFlags(fs, args); code != 0 {
		return code
	}

	h, err := hara.Load(projectRoot)
	if err != nil {
		fmt.Fprintf(stderr, "gofusa hara show: %v\n", err)
		return fusa.ExitRuntime
	}

	w := stdout
	if *format == "json" {
		reqIDs := loadReqIDs(projectRoot)
		report := hara.BuildReport(h, reqIDs)
		if *output != "" {
			f, ferr := os.Create(*output)
			if ferr != nil {
				fmt.Fprintf(stderr, "gofusa hara show: create %s: %v\n", *output, ferr)
				return fusa.ExitRuntime
			}
			defer func() { _ = f.Close() }()
			w = f
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fmt.Fprintf(stderr, "gofusa hara show: render: %v\n", err)
			return fusa.ExitRuntime
		}
	} else {
		if *output != "" {
			f, ferr := os.Create(*output)
			if ferr != nil {
				fmt.Fprintf(stderr, "gofusa hara show: create %s: %v\n", *output, ferr)
				return fusa.ExitRuntime
			}
			defer func() { _ = f.Close() }()
			w = f
		}
		if err := hara.Render(w, h, *format); err != nil {
			fmt.Fprintf(stderr, "gofusa hara show: render: %v\n", err)
			return fusa.ExitRuntime
		}
	}

	findings := hara.Validate(h)
	if len(findings) > 0 && *output != "" {
		fmt.Fprintf(stderr, "gofusa hara: %d gap(s) found — run 'gofusa hara show' for details\n", len(findings))
	}

	return gateContentQuality(stderr, "hara", hara.HARAFile, stubcheck.HaraFields(h), h.Attestation, struct {
		Situations  interface{} `json:"operationalSituations"`
		Hazards     interface{} `json:"hazards"`
		SafetyGoals interface{} `json:"safetyGoals"`
	}{h.Situations, h.Hazards, h.SafetyGoals}, *strict || *requireAttestation)
}

// loadReqIDs returns the set of requirement ids in projectRoot's
// .fusa-reqs.json, or nil if it is absent/unreadable.
func loadReqIDs(projectRoot string) map[string]bool {
	reqs, err := trace.LoadRequirements(projectRoot)
	if err != nil {
		return nil
	}
	out := make(map[string]bool, len(reqs))
	for _, r := range reqs {
		out[r.ID] = true
	}
	return out
}

func runHaraInit(args []string, projectRoot string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa hara init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	project := fs.String("project", "", "project name (default: directory name)")
	// x-FuSa spec §2.4.1: standard is a canonical lowercase id, never a
	// display string ("iso26262", not "ISO 26262").
	standard := fs.String("standard", "iso26262", "safety standard canonical id (e.g. 'iso26262', 'iec61508')")
	if code := parseFlags(fs, args); code != 0 {
		return code
	}

	path := filepath.Join(projectRoot, hara.HARAFile)
	if _, err := os.Stat(path); err == nil {
		fmt.Fprintf(stderr, "gofusa hara init: %s already exists — delete it first to reinitialise\n", hara.HARAFile)
		return fusa.ExitUsage
	}

	name := *project
	if name == "" {
		name = filepath.Base(projectRoot)
	}

	// x-FuSa spec §1.2.5/§1.6 rule 1: --init scaffolds EMPTY collections,
	// never dummy/placeholder rows — a fabricated example hazard asserts a
	// false completeness that an honestly-empty array does not.
	h := &hara.HARA{
		Project:     name,
		Standard:    *standard,
		CreatedAt:   time.Now().UTC(),
		Situations:  []hara.OperationalSituation{},
		Hazards:     []hara.Hazard{},
		SafetyGoals: []hara.SafetyGoal{},
	}

	if err := hara.Save(path, h); err != nil {
		fmt.Fprintf(stderr, "gofusa hara init: %v\n", err)
		return fusa.ExitRuntime
	}

	fmt.Fprintf(stdout, "Created %s (project=%s standard=%q)\n", path, name, *standard)
	fmt.Fprintf(stdout, "Edit %s to document project-specific operational situations, hazards, and safety goals.\n", hara.HARAFile)
	return fusa.ExitOK
}

func runHaraASIL(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa hara asil", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: gofusa hara asil [flags]\n\n")
		fmt.Fprintf(stderr, "Derive ASIL from ISO 26262-3:2018 Table 4.\n\n")
		fmt.Fprintf(stderr, "Flags:\n")
		fs.PrintDefaults()
		fmt.Fprintf(stderr, "\nExample: gofusa hara asil -s S2 -e E3 -c C2\n")
	}
	s := fs.String("s", "", "Severity: S0, S1, S2, S3 (required)")
	e := fs.String("e", "", "Exposure: E0, E1, E2, E3, E4 (required)")
	c := fs.String("c", "", "Controllability: C0, C1, C2, C3 (required)")
	if code := parseFlags(fs, args); code != 0 {
		return code
	}

	if *s == "" || *e == "" || *c == "" {
		fmt.Fprintf(stderr, "gofusa hara asil: -s, -e, and -c are required\n")
		fs.Usage()
		return fusa.ExitUsage
	}

	asil := hara.DetermineASIL(hara.Severity(*s), hara.Exposure(*e), hara.Controllability(*c))
	fmt.Fprintf(stdout, "S=%s  E=%s  C=%s  →  %s\n", *s, *e, *c, asil)
	return fusa.ExitOK
}
