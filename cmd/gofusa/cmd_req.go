package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/SoundMatt/go-FuSa/trace"
)

//fusa:req REQ-CLI-REQ001
func runReq(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa req", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: gofusa req [subcommand] [flags] [REQ-ID ...]\n\n")
		fmt.Fprintf(stderr, "Show, import, or export requirements.\n\n")
		fmt.Fprintf(stderr, "Subcommands:\n")
		fmt.Fprintf(stderr, "  (none)  Show requirements and their source/test locations\n")
		fmt.Fprintf(stderr, "  import  Import requirements from a CSV file\n")
		fmt.Fprintf(stderr, "  export  Export requirements to CSV\n\n")
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

	remaining := fs.Args()
	if len(remaining) > 0 {
		switch remaining[0] {
		case "import":
			return runReqImport(remaining[1:], projectRoot, stdout, stderr)
		case "export":
			return runReqExport(remaining[1:], projectRoot, stdout, stderr)
		}
	}

	// Default: show requirements
	return runReqShow(remaining, projectRoot, stdout, stderr)
}

func runReqShow(ids []string, projectRoot string, stdout, stderr io.Writer) int {
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
	for _, id := range ids {
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

//fusa:req REQ-CLI-REQ002
func runReqImport(args []string, projectRoot string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa req import", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		format = fs.String("format", "csv", "import format: csv")
		file   = fs.String("file", "", "input file path (required)")
	)
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *file == "" {
		fmt.Fprintf(stderr, "gofusa req import: --file is required\n")
		return 1
	}
	if *format != "csv" {
		fmt.Fprintf(stderr, "gofusa req import: unsupported format %q (only csv is supported)\n", *format)
		return 1
	}

	// Load existing requirements
	existing, err := trace.LoadRequirements(projectRoot)
	if err != nil {
		// No existing file is fine
		existing = nil
	}
	existingIDs := make(map[string]bool)
	for _, r := range existing {
		existingIDs[r.ID] = true
	}

	// Read CSV
	f, err := os.Open(*file)
	if err != nil {
		fmt.Fprintf(stderr, "gofusa req import: open %s: %v\n", *file, err)
		return 1
	}
	defer func() { _ = f.Close() }()

	r := csv.NewReader(f)
	records, err := r.ReadAll()
	if err != nil {
		fmt.Fprintf(stderr, "gofusa req import: read csv: %v\n", err)
		return 1
	}

	if len(records) == 0 {
		fmt.Fprintf(stderr, "gofusa req import: CSV file is empty\n")
		return 1
	}

	// Validate header row
	header := records[0]
	if len(header) < 2 || strings.ToLower(header[0]) != "id" {
		fmt.Fprintf(stderr, "gofusa req import: CSV must have header row starting with: id,title,text,standard,level\n")
		return 1
	}

	imported := 0
	skipped := 0
	for _, row := range records[1:] {
		if len(row) == 0 {
			continue
		}
		id := strings.TrimSpace(row[0])
		if id == "" {
			continue
		}
		if existingIDs[id] {
			skipped++
			continue
		}
		req := trace.Requirement{ID: id}
		if len(row) > 1 {
			req.Title = strings.TrimSpace(row[1])
		}
		if len(row) > 2 {
			req.Text = strings.TrimSpace(row[2])
		}
		if len(row) > 3 {
			req.Standard = strings.TrimSpace(row[3])
		}
		if len(row) > 4 {
			req.Level = strings.TrimSpace(row[4])
		}
		existing = append(existing, req)
		existingIDs[id] = true
		imported++
	}

	if err := trace.SaveRequirements(projectRoot, existing); err != nil {
		fmt.Fprintf(stderr, "gofusa req import: save: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "Imported %d requirements (%d skipped as duplicates)\n", imported, skipped)
	return 0
}

//fusa:req REQ-CLI-REQ003
func runReqExport(args []string, projectRoot string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa req export", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		format = fs.String("format", "csv", "export format: csv")
		output = fs.String("output", "", "output file (default: stdout)")
	)
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *format != "csv" {
		fmt.Fprintf(stderr, "gofusa req export: unsupported format %q (only csv is supported)\n", *format)
		return 1
	}

	reqs, err := trace.LoadRequirements(projectRoot)
	if err != nil {
		fmt.Fprintf(stderr, "gofusa req export: load requirements: %v\n", err)
		return 1
	}

	w := stdout
	if *output != "" {
		f, ferr := os.Create(filepath.Join(projectRoot, *output))
		if ferr != nil {
			// try as absolute path
			f, ferr = os.Create(*output)
			if ferr != nil {
				fmt.Fprintf(stderr, "gofusa req export: create %s: %v\n", *output, ferr)
				return 1
			}
		}
		defer func() { _ = f.Close() }()
		w = f
	}

	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"id", "title", "text", "standard", "level"}); err != nil {
		fmt.Fprintf(stderr, "gofusa req export: write header: %v\n", err)
		return 1
	}
	for _, req := range reqs {
		if err := cw.Write([]string{req.ID, req.Title, req.Text, req.Standard, req.Level}); err != nil {
			fmt.Fprintf(stderr, "gofusa req export: write row: %v\n", err)
			return 1
		}
	}
	cw.Flush()
	if err := cw.Error(); err != nil {
		fmt.Fprintf(stderr, "gofusa req export: flush: %v\n", err)
		return 1
	}
	return 0
}
