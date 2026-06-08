package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/SoundMatt/go-FuSa/trace"
)

//fusa:req REQ-CLI-REQ001
func runReq(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa req", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: gofusa req [flags] [REQ-ID ...]\n\n")
		fmt.Fprintf(stderr, "Show requirements and their source/test locations.\n")
		fmt.Fprintf(stderr, "With no IDs, lists all requirements.\n\n")
		fmt.Fprintf(stderr, "Flags:\n")
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
			fmt.Fprintf(stderr, "gofusa req: get working directory: %v\n", err)
			return 1
		}
	}

	matrix, err := trace.Build(projectRoot)
	if err != nil {
		fmt.Fprintf(stderr, "gofusa req: %v\n", err)
		return 1
	}

	// Index tags by requirement ID.
	impls := make(map[string][]trace.Tag)
	tests := make(map[string][]trace.Tag)
	for _, t := range matrix.Tags {
		switch t.Kind {
		case trace.KindImpl:
			impls[t.RequirementID] = append(impls[t.RequirementID], t)
		case trace.KindTest, trace.KindSecTest:
			tests[t.RequirementID] = append(tests[t.RequirementID], t)
		}
	}

	filter := make(map[string]bool)
	for _, id := range fs.Args() {
		filter[id] = true
	}

	printed := 0
	for _, req := range matrix.Requirements {
		if len(filter) > 0 && !filter[req.ID] {
			continue
		}
		printed++
		fmt.Fprintf(stdout, "%s  %s\n", req.ID, req.Title)
		if req.Text != "" {
			fmt.Fprintf(stdout, "  %s\n", req.Text)
		}
		if req.Standard != "" {
			fmt.Fprintf(stdout, "  Standard: %s", req.Standard)
			if req.Level != "" {
				fmt.Fprintf(stdout, "  Level: %s", req.Level)
			}
			fmt.Fprintln(stdout)
		}
		for _, t := range impls[req.ID] {
			fmt.Fprintf(stdout, "  impl   %s:%d\n", t.File, t.Line)
		}
		for _, t := range tests[req.ID] {
			fmt.Fprintf(stdout, "  test   %s:%d\n", t.File, t.Line)
		}
		if len(impls[req.ID]) == 0 && len(tests[req.ID]) == 0 {
			fmt.Fprintf(stdout, "  (no annotations found)\n")
		}
		fmt.Fprintln(stdout)
	}

	if len(filter) > 0 && printed == 0 {
		for id := range filter {
			fmt.Fprintf(stderr, "gofusa req: requirement %q not found\n", id)
		}
		return 1
	}
	return 0
}
