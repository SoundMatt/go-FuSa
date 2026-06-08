package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/SoundMatt/go-FuSa/boundary"
)

// runBoundary generates the component boundary diagram for the project.
//
//fusa:req REQ-CLI014
func runBoundary(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa boundary", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: gofusa boundary [flags]\n\n")
		fmt.Fprintf(stderr, "Generate a component boundary diagram from the project's package\n")
		fmt.Fprintf(stderr, "structure, showing trust boundaries and data flows.\n\n")
		fmt.Fprintf(stderr, "Generates boundary.mermaid and boundary.dot in the output directory.\n\n")
		fmt.Fprintf(stderr, "Flags:\n")
		fs.PrintDefaults()
	}

	var (
		dir       = fs.String("dir", "", "project root directory (default: current directory)")
		outputDir = fs.String("output-dir", "", "output directory (default: project root)")
	)
	if err := fs.Parse(args); err != nil {
		return 1
	}

	projectRoot := *dir
	if projectRoot == "" {
		var err error
		projectRoot, err = os.Getwd()
		if err != nil {
			fmt.Fprintf(stderr, "gofusa boundary: get working directory: %v\n", err)
			return 1
		}
	}

	outDir := *outputDir
	if outDir == "" {
		outDir = projectRoot
	}

	diagram, err := boundary.Scan(projectRoot)
	if err != nil {
		fmt.Fprintf(stderr, "gofusa boundary: scan: %v\n", err)
		return 1
	}

	if err := os.MkdirAll(outDir, 0o750); err != nil {
		fmt.Fprintf(stderr, "gofusa boundary: mkdir: %v\n", err)
		return 1
	}

	// Write boundary.mermaid
	mermaidPath := filepath.Join(outDir, boundary.BoundaryFile)
	if err := writeBoundary(mermaidPath, diagram, "mermaid"); err != nil {
		fmt.Fprintf(stderr, "gofusa boundary: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "Boundary diagram written to %s\n", mermaidPath)

	// Write boundary.dot
	dotPath := filepath.Join(outDir, boundary.BoundaryDOTFile)
	if err := writeBoundary(dotPath, diagram, "dot"); err != nil {
		fmt.Fprintf(stderr, "gofusa boundary: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "Boundary diagram written to %s\n", dotPath)

	fmt.Fprintf(stdout, "\nPackages: %d  Edges: %d\n",
		len(diagram.Nodes), len(diagram.Edges))

	return 0
}

func writeBoundary(path string, d *boundary.Diagram, format string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	if err := boundary.Render(f, d, format); err != nil {
		return fmt.Errorf("render %s: %w", path, err)
	}
	return nil
}
