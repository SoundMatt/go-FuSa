package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/SoundMatt/go-FuSa/impact"
)

//fusa:req REQ-CLI-IMPACT001
func runImpact(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa impact", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: gofusa impact [flags]\n\n")
		fmt.Fprintf(stderr, "Analyse the impact of source changes on requirements and safety artefacts.\n\n")
		fmt.Fprintf(stderr, "Flags:\n")
		fs.PrintDefaults()
	}

	var (
		dir    = fs.String("dir", "", "project root directory (default: current directory)")
		from   = fs.String("from", "", "from git ref (default: diff working tree vs HEAD)")
		to     = fs.String("to", "", "to git ref (default: HEAD)")
		format = fs.String("format", "text", "output format: text, json")
		output = fs.String("output", "", "write report to file (default: stdout)")
	)
	if err := fs.Parse(args); err != nil {
		return 1
	}

	projectRoot := *dir
	if projectRoot == "" {
		var err error
		projectRoot, err = os.Getwd()
		if err != nil {
			fmt.Fprintf(stderr, "gofusa impact: get working directory: %v\n", err)
			return 1
		}
	}

	rep, err := impact.Analyse(projectRoot, *from, *to)
	if err != nil {
		fmt.Fprintf(stderr, "gofusa impact: analyse: %v\n", err)
		return 1
	}

	var w io.Writer = stdout
	if *output != "" {
		f, ferr := os.Create(*output)
		if ferr != nil {
			fmt.Fprintf(stderr, "gofusa impact: create %s: %v\n", *output, ferr)
			return 1
		}
		defer func() { _ = f.Close() }()
		w = f
	}

	if err := impact.Render(w, rep, *format); err != nil {
		fmt.Fprintf(stderr, "gofusa impact: render: %v\n", err)
		return 1
	}

	if *output != "" {
		stale := 0
		for _, a := range rep.StaleArtifacts {
			if a.Stale {
				stale++
			}
		}
		fmt.Fprintf(stdout, "Impact report written to %s (%d changed files, %d impacted reqs, %d stale artefacts)\n",
			*output, len(rep.ChangedFiles), len(rep.ImpactedReqs), stale)
	}

	return 0
}
