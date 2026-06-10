package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/disposition"
)

//fusa:req REQ-CLI-DISP001
func runDisposition(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa disposition", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: gofusa disposition <subcommand> [flags]\n\n")
		fmt.Fprintf(stderr, "Manage finding disposition entries.\n\n")
		fmt.Fprintf(stderr, "Subcommands:\n")
		fmt.Fprintf(stderr, "  add   Add a new disposition entry\n")
		fmt.Fprintf(stderr, "  list  List all disposition entries\n")
		fmt.Fprintf(stderr, "  show  Show the disposition entry for a specific rule\n\n")
		fmt.Fprintf(stderr, "Global flags:\n")
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
			fmt.Fprintf(stderr, "gofusa disposition: get working directory: %v\n", err)
			return fusa.ExitRuntime
		}
	}

	sub := fs.Args()
	if len(sub) == 0 {
		fs.Usage()
		return fusa.ExitUsage
	}

	switch sub[0] {
	case "add":
		return runDispositionAdd(sub[1:], projectRoot, stdout, stderr)
	case "list":
		return runDispositionList(sub[1:], projectRoot, stdout, stderr)
	case "show":
		return runDispositionShow(sub[1:], projectRoot, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "gofusa disposition: unknown subcommand %q\n", sub[0])
		return fusa.ExitUsage
	}
}

func runDispositionAdd(args []string, projectRoot string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa disposition add", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		ruleID    = fs.String("rule", "", "rule ID to disposition (required)")
		action    = fs.String("action", "accept", "action: accept or fix")
		reviewer  = fs.String("reviewer", "", "reviewer name (required)")
		rationale = fs.String("rationale", "", "rationale for disposition (required)")
		ref       = fs.String("ref", "", "optional reference (issue, ticket, etc)")
	)
	if code := parseFlags(fs, args); code != 0 {
		return code
	}

	if *ruleID == "" {
		fmt.Fprintf(stderr, "gofusa disposition add: --rule is required\n")
		return fusa.ExitUsage
	}
	if *reviewer == "" {
		fmt.Fprintf(stderr, "gofusa disposition add: --reviewer is required\n")
		return fusa.ExitUsage
	}
	if *rationale == "" {
		fmt.Fprintf(stderr, "gofusa disposition add: --rationale is required\n")
		return fusa.ExitUsage
	}
	if *action != "accept" && *action != "fix" {
		fmt.Fprintf(stderr, "gofusa disposition add: --action must be 'accept' or 'fix'\n")
		return fusa.ExitUsage
	}

	log, err := disposition.Load(projectRoot)
	if err != nil {
		fmt.Fprintf(stderr, "gofusa disposition add: load: %v\n", err)
		return fusa.ExitRuntime
	}

	entry := disposition.Entry{
		RuleID:    *ruleID,
		Rationale: *rationale,
		Reviewer:  *reviewer,
		Date:      time.Now().UTC(),
		Action:    disposition.Action(*action),
		Reference: *ref,
	}
	log = disposition.Add(log, entry)

	path := filepath.Join(projectRoot, disposition.DispositionsFile)
	if err := disposition.Save(path, log); err != nil {
		fmt.Fprintf(stderr, "gofusa disposition add: save: %v\n", err)
		return fusa.ExitRuntime
	}

	fmt.Fprintf(stdout, "Disposition added: rule=%s action=%s reviewer=%s\n",
		entry.RuleID, entry.Action, entry.Reviewer)
	return fusa.ExitOK
}

func runDispositionList(args []string, projectRoot string, stdout, stderr io.Writer) int {
	_ = args // no additional flags
	log, err := disposition.Load(projectRoot)
	if err != nil {
		fmt.Fprintf(stderr, "gofusa disposition list: %v\n", err)
		return fusa.ExitRuntime
	}
	if err := disposition.RenderEntries(stdout, log); err != nil {
		fmt.Fprintf(stderr, "gofusa disposition list: render: %v\n", err)
		return fusa.ExitRuntime
	}
	return fusa.ExitOK
}

func runDispositionShow(args []string, projectRoot string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa disposition show", flag.ContinueOnError)
	fs.SetOutput(stderr)
	ruleID := fs.String("rule", "", "rule ID to show (required)")
	if code := parseFlags(fs, args); code != 0 {
		return code
	}
	if *ruleID == "" {
		fmt.Fprintf(stderr, "gofusa disposition show: --rule is required\n")
		return fusa.ExitUsage
	}

	log, err := disposition.Load(projectRoot)
	if err != nil {
		fmt.Fprintf(stderr, "gofusa disposition show: %v\n", err)
		return fusa.ExitRuntime
	}

	for _, e := range log.Entries {
		if e.RuleID == *ruleID {
			fmt.Fprintf(stdout, "Rule:      %s\n", e.RuleID)
			fmt.Fprintf(stdout, "Action:    %s\n", e.Action)
			fmt.Fprintf(stdout, "Reviewer:  %s\n", e.Reviewer)
			fmt.Fprintf(stdout, "Date:      %s\n", e.Date.Format("2006-01-02"))
			fmt.Fprintf(stdout, "Rationale: %s\n", e.Rationale)
			if e.Reference != "" {
				fmt.Fprintf(stdout, "Reference: %s\n", e.Reference)
			}
			return fusa.ExitOK
		}
	}

	fmt.Fprintf(stderr, "gofusa disposition show: no disposition found for rule %q\n", *ruleID)
	return fusa.ExitUsage
}
