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
		format = fs.String("format", "csv", "import format: csv, doors, polarion, codebeamer, jama")
		file   = fs.String("file", "", "input file path (required)")
	)
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *file == "" {
		fmt.Fprintf(stderr, "gofusa req import: --file is required\n")
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

	var imported []trace.Requirement

	switch *format {
	case "doors", "polarion", "codebeamer", "jama":
		data, ferr := os.ReadFile(*file)
		if ferr != nil {
			fmt.Fprintf(stderr, "gofusa req import: read %s: %v\n", *file, ferr)
			return 1
		}
		var parseErr error
		switch *format {
		case "doors":
			imported, parseErr = trace.ParseDOORS(data)
		case "polarion":
			imported, parseErr = trace.ParsePolarion(data)
		case "codebeamer":
			imported, parseErr = trace.ParseCodebeamer(data)
		case "jama":
			imported, parseErr = trace.ParseJama(data)
		}
		if parseErr != nil {
			fmt.Fprintf(stderr, "gofusa req import: parse: %v\n", parseErr)
			return 1
		}
	default: // csv
		f, ferr := os.Open(*file)
		if ferr != nil {
			fmt.Fprintf(stderr, "gofusa req import: open %s: %v\n", *file, ferr)
			return 1
		}
		defer func() { _ = f.Close() }()

		r := csv.NewReader(f)
		records, rerr := r.ReadAll()
		if rerr != nil {
			fmt.Fprintf(stderr, "gofusa req import: read csv: %v\n", rerr)
			return 1
		}

		if len(records) == 0 {
			fmt.Fprintf(stderr, "gofusa req import: CSV file is empty\n")
			return 1
		}

		header := records[0]
		if len(header) < 2 || strings.ToLower(header[0]) != "id" {
			fmt.Fprintf(stderr, "gofusa req import: CSV must have header row starting with: id,title,text,standard,level\n")
			return 1
		}

		for _, row := range records[1:] {
			if len(row) == 0 {
				continue
			}
			id := strings.TrimSpace(row[0])
			if id == "" {
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
			imported = append(imported, req)
		}
	}

	added := 0
	skipped := 0
	for _, req := range imported {
		if existingIDs[req.ID] {
			skipped++
			continue
		}
		existing = append(existing, req)
		existingIDs[req.ID] = true
		added++
	}

	if err := trace.SaveRequirements(projectRoot, existing); err != nil {
		fmt.Fprintf(stderr, "gofusa req import: save: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "Imported %d requirements (%d skipped as duplicates)\n", added, skipped)
	return 0
}

//fusa:req REQ-CLI-REQ003
func runReqExport(args []string, projectRoot string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa req export", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		format = fs.String("format", "csv", "export format: csv, doors, polarion, codebeamer, jama")
		output = fs.String("output", "", "output file (default: stdout)")
	)
	if err := fs.Parse(args); err != nil {
		return 1
	}

	reqs, err := trace.LoadRequirements(projectRoot)
	if err != nil {
		fmt.Fprintf(stderr, "gofusa req export: load requirements: %v\n", err)
		return 1
	}

	openOutput := func() (io.Writer, func(), error) {
		if *output == "" {
			return stdout, func() {}, nil
		}
		// Try relative to projectRoot first, then as absolute path.
		path := filepath.Join(projectRoot, *output)
		f, ferr := os.Create(path)
		if ferr != nil {
			f, ferr = os.Create(*output)
			if ferr != nil {
				return nil, nil, ferr
			}
		}
		return f, func() { _ = f.Close() }, nil
	}

	switch *format {
	case "doors", "polarion", "codebeamer", "jama":
		var data []byte
		var exportErr error
		switch *format {
		case "doors":
			data, exportErr = trace.ExportDOORS(reqs)
		case "polarion":
			data, exportErr = trace.ExportPolarion(reqs)
		case "codebeamer":
			data, exportErr = trace.ExportCodebeamer(reqs)
		case "jama":
			data, exportErr = trace.ExportJama(reqs)
		}
		if exportErr != nil {
			fmt.Fprintf(stderr, "gofusa req export: %v\n", exportErr)
			return 1
		}
		w, closeFn, openErr := openOutput()
		if openErr != nil {
			fmt.Fprintf(stderr, "gofusa req export: create %s: %v\n", *output, openErr)
			return 1
		}
		defer closeFn()
		if _, werr := w.Write(data); werr != nil {
			fmt.Fprintf(stderr, "gofusa req export: write: %v\n", werr)
			return 1
		}
	default: // csv
		w, closeFn, openErr := openOutput()
		if openErr != nil {
			fmt.Fprintf(stderr, "gofusa req export: create %s: %v\n", *output, openErr)
			return 1
		}
		defer closeFn()
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
	}
	return 0
}
