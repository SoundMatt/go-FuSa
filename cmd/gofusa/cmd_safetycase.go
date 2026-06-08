package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/SoundMatt/go-FuSa/safetycase"
)

// runSafetyCase assembles and writes the project safety case.
//
//fusa:req REQ-CLI012
func runSafetyCase(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa safety-case", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: gofusa safety-case [flags]\n\n")
		fmt.Fprintf(stderr, "Assemble a structured safety case from existing evidence files.\n\n")
		fmt.Fprintf(stderr, "Generates safety-case.json, safety-case.md, and safety-case.mermaid\n")
		fmt.Fprintf(stderr, "in the output directory.\n\n")
		fmt.Fprintf(stderr, "Flags:\n")
		fs.PrintDefaults()
	}

	var (
		dir       = fs.String("dir", "", "project root directory (default: current directory)")
		outputDir = fs.String("output-dir", "", "output directory (default: project root)")
		standard  = fs.String("standard", "", "safety standard: iso26262, iec61508, iso21434, generic (default: from config or generic)")
	)
	if err := fs.Parse(args); err != nil {
		return 1
	}

	projectRoot := *dir
	if projectRoot == "" {
		var err error
		projectRoot, err = os.Getwd()
		if err != nil {
			fmt.Fprintf(stderr, "gofusa safety-case: get working directory: %v\n", err)
			return 1
		}
	}

	outDir := *outputDir
	if outDir == "" {
		outDir = projectRoot
	}

	sc, err := safetycase.Build(projectRoot, *standard)
	if err != nil {
		fmt.Fprintf(stderr, "gofusa safety-case: build: %v\n", err)
		return 1
	}

	if err := os.MkdirAll(outDir, 0o750); err != nil {
		fmt.Fprintf(stderr, "gofusa safety-case: mkdir: %v\n", err)
		return 1
	}

	// Write safety-case.json
	jsonPath := filepath.Join(outDir, "safety-case.json")
	if err := writeFormatted(jsonPath, sc, "json"); err != nil {
		fmt.Fprintf(stderr, "gofusa safety-case: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "Safety case written to %s\n", jsonPath)

	// Write safety-case.md
	mdPath := filepath.Join(outDir, "safety-case.md")
	if err := writeFormatted(mdPath, sc, "text"); err != nil {
		fmt.Fprintf(stderr, "gofusa safety-case: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "Safety case written to %s\n", mdPath)

	// Write safety-case.mermaid
	mermaidPath := filepath.Join(outDir, "safety-case.mermaid")
	if err := writeFormatted(mermaidPath, sc, "mermaid"); err != nil {
		fmt.Fprintf(stderr, "gofusa safety-case: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "Safety case written to %s\n", mermaidPath)

	// Print evidence summary
	fmt.Fprintf(stdout, "\nEvidence summary:\n")
	for _, it := range sc.Evidence {
		mark := "✓"
		if it.Status == safetycase.StatusAbsent {
			mark = "✗"
		}
		detail := it.Detail
		if detail == "" {
			detail = it.File
		}
		fmt.Fprintf(stdout, "  %s %-30s %s\n", mark, it.Description, detail)
	}

	if len(sc.Gaps) == 0 {
		fmt.Fprintf(stdout, "\nGaps: none\n")
	} else {
		fmt.Fprintf(stdout, "\nGaps: %d — %s\n", len(sc.Gaps), joinGaps(sc.Gaps))
	}

	// Write safety-case.json to project root (as the canonical evidence file
	// checked by SAFETYCASE001) when outputDir is different from projectRoot.
	if outDir != projectRoot {
		canonPath := filepath.Join(projectRoot, "safety-case.json")
		if err := writeFormatted(canonPath, sc, "json"); err != nil {
			fmt.Fprintf(stderr, "gofusa safety-case: write canonical: %v\n", err)
			return 1
		}
	}

	return 0
}

func writeFormatted(path string, sc *safetycase.SafetyCase, format string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	if err := safetycase.Render(f, sc, format); err != nil {
		return fmt.Errorf("render %s: %w", path, err)
	}
	return nil
}

func joinGaps(gaps []string) string {
	b, _ := json.Marshal(gaps)
	return string(b)
}
