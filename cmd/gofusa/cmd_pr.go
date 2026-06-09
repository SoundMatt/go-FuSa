package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/SoundMatt/go-FuSa/pr"
)

//fusa:req REQ-CLI-PR001
func runPR(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa pr", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: gofusa pr <subcommand> [flags]\n\n")
		fmt.Fprintf(stderr, "Manage software problem reports (DO-178C §11.17).\n\n")
		fmt.Fprintf(stderr, "Subcommands:\n")
		fmt.Fprintf(stderr, "  init    Create an empty .fusa-problems.json\n")
		fmt.Fprintf(stderr, "  add     Add a new problem report\n")
		fmt.Fprintf(stderr, "  list    List all problem reports\n")
		fmt.Fprintf(stderr, "  close   Close a problem report\n\n")
		fmt.Fprintf(stderr, "Flags:\n")
		fs.PrintDefaults()
	}

	dir := fs.String("dir", "", "project root directory (default: current directory)")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if fs.NArg() == 0 {
		fs.Usage()
		return 1
	}

	projectRoot := *dir
	if projectRoot == "" {
		var err error
		projectRoot, err = os.Getwd()
		if err != nil {
			fmt.Fprintf(stderr, "gofusa pr: get working directory: %v\n", err)
			return 1
		}
	}

	logPath := filepath.Join(projectRoot, pr.ProblemsFile)

	switch fs.Arg(0) {
	case "init":
		return prInit(logPath, stdout, stderr)
	case "add":
		return prAdd(logPath, fs.Args()[1:], stdout, stderr)
	case "list":
		return prList(logPath, stdout, stderr)
	case "close":
		return prClose(logPath, fs.Args()[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "gofusa pr: unknown subcommand %q\n", fs.Arg(0))
		fs.Usage()
		return 1
	}
}

func prInit(logPath string, stdout, stderr io.Writer) int {
	if _, err := os.Stat(logPath); err == nil {
		fmt.Fprintf(stderr, "gofusa pr: %s already exists\n", logPath)
		return 1
	}
	log := &pr.Log{Project: filepath.Base(filepath.Dir(logPath))}
	if err := pr.Save(logPath, log); err != nil {
		fmt.Fprintf(stderr, "gofusa pr: init: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "Problem report log created: %s\n", logPath)
	return 0
}

func prAdd(logPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa pr add", flag.ContinueOnError)
	fs.SetOutput(stderr)
	id := fs.String("id", "", "problem report ID (required)")
	title := fs.String("title", "", "short description (required)")
	desc := fs.String("desc", "", "detailed description")
	phase := fs.String("phase", string(pr.PhaseDevelopment), "phase found: planning/development/verification/integration/operation")
	severity := fs.String("severity", string(pr.PRSeverityMinor), "severity: critical/major/minor")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *id == "" || *title == "" {
		fmt.Fprintf(stderr, "gofusa pr add: --id and --title are required\n")
		return 1
	}
	report := pr.ProblemReport{
		ID:          *id,
		Title:       *title,
		Description: *desc,
		PhaseFound:  pr.Phase(*phase),
		Severity:    pr.PRSeverity(*severity),
		Status:      pr.StatusOpen,
		Created:     time.Now().UTC(),
		Updated:     time.Now().UTC(),
	}
	if err := pr.Add(logPath, report); err != nil {
		fmt.Fprintf(stderr, "gofusa pr add: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "Problem report %s added to %s\n", *id, logPath)
	return 0
}

func prList(logPath string, stdout, stderr io.Writer) int {
	log, err := pr.Load(logPath)
	if err != nil {
		fmt.Fprintf(stderr, "gofusa pr list: %v\n", err)
		return 1
	}
	if err := pr.Render(stdout, log, "text"); err != nil {
		fmt.Fprintf(stderr, "gofusa pr list: %v\n", err)
		return 1
	}
	return 0
}

func prClose(logPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa pr close", flag.ContinueOnError)
	fs.SetOutput(stderr)
	id := fs.String("id", "", "problem report ID to close (required)")
	resolution := fs.String("resolution", "", "resolution description")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *id == "" {
		fmt.Fprintf(stderr, "gofusa pr close: --id is required\n")
		return 1
	}
	if err := pr.Close(logPath, *id, *resolution); err != nil {
		fmt.Fprintf(stderr, "gofusa pr close: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "Problem report %s closed\n", *id)
	return 0
}
