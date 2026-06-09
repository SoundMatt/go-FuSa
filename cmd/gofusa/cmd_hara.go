package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/SoundMatt/go-FuSa/hara"
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
	if err := fs.Parse(args); err != nil {
		return 1
	}

	projectRoot := *dir
	if projectRoot == "" {
		var err error
		projectRoot, err = os.Getwd()
		if err != nil {
			fmt.Fprintf(stderr, "gofusa hara: get working directory: %v\n", err)
			return 1
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
		return 1
	}
}

func runHaraShow(args []string, projectRoot string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa hara show", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "text", "output format: text, json, markdown")
	output := fs.String("output", "", "write output to file (default: stdout)")
	if err := fs.Parse(args); err != nil {
		return 1
	}

	h, err := hara.Load(projectRoot)
	if err != nil {
		fmt.Fprintf(stderr, "gofusa hara show: %v\n", err)
		return 1
	}

	w := stdout
	if *output != "" {
		f, ferr := os.Create(*output)
		if ferr != nil {
			fmt.Fprintf(stderr, "gofusa hara show: create %s: %v\n", *output, ferr)
			return 1
		}
		defer func() { _ = f.Close() }()
		w = f
	}

	if err := hara.Render(w, h, *format); err != nil {
		fmt.Fprintf(stderr, "gofusa hara show: render: %v\n", err)
		return 1
	}

	findings := hara.Validate(h)
	if len(findings) > 0 && *output != "" {
		fmt.Fprintf(stderr, "gofusa hara: %d gap(s) found — run 'gofusa hara show' for details\n", len(findings))
	}
	return 0
}

func runHaraInit(args []string, projectRoot string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa hara init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	project := fs.String("project", "", "project name (default: directory name)")
	standard := fs.String("standard", "ISO 26262", "safety standard (e.g. 'ISO 26262', 'IEC 61508')")
	if err := fs.Parse(args); err != nil {
		return 1
	}

	path := filepath.Join(projectRoot, hara.HARAFile)
	if _, err := os.Stat(path); err == nil {
		fmt.Fprintf(stderr, "gofusa hara init: %s already exists — delete it first to reinitialise\n", hara.HARAFile)
		return 1
	}

	name := *project
	if name == "" {
		name = filepath.Base(projectRoot)
	}

	h := &hara.HARA{
		Project:   name,
		Standard:  *standard,
		CreatedAt: time.Now().UTC(),
		Situations: []hara.OperationalSituation{
			{ID: "OS-001", Description: "Normal operation"},
		},
		Hazards: []hara.Hazard{
			{
				ID:          "H-001",
				Description: "Example hazard — replace with project-specific hazard",
				Situations:  []string{"OS-001"},
				Risk: hara.RiskRating{
					Severity:        hara.SeverityS2,
					Exposure:        hara.ExposureE3,
					Controllability: hara.ControllabilityC2,
					ASIL:            hara.DetermineASIL(hara.SeverityS2, hara.ExposureE3, hara.ControllabilityC2),
				},
				SafetyGoals: []string{"SG-001"},
			},
		},
		SafetyGoals: []hara.SafetyGoal{
			{
				ID:          "SG-001",
				Description: "Example safety goal — replace with project-specific goal",
				HazardIDs:   []string{"H-001"},
				ASIL:        hara.DetermineASIL(hara.SeverityS2, hara.ExposureE3, hara.ControllabilityC2),
				SafeState:   "safe state description",
			},
		},
	}

	if err := hara.Save(path, h); err != nil {
		fmt.Fprintf(stderr, "gofusa hara init: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "Created %s (project=%s standard=%q)\n", path, name, *standard)
	fmt.Fprintf(stdout, "Edit %s to document project hazards and safety goals.\n", hara.HARAFile)
	return 0
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
	if err := fs.Parse(args); err != nil {
		return 1
	}

	if *s == "" || *e == "" || *c == "" {
		fmt.Fprintf(stderr, "gofusa hara asil: -s, -e, and -c are required\n")
		fs.Usage()
		return 1
	}

	asil := hara.DetermineASIL(hara.Severity(*s), hara.Exposure(*e), hara.Controllability(*c))
	fmt.Fprintf(stdout, "S=%s  E=%s  C=%s  →  %s\n", *s, *e, *c, asil)
	return 0
}
