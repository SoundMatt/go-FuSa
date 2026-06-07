package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/SoundMatt/go-FuSa/release"
)

func runRelease(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa release", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: gofusa release [flags]\n\n")
		fmt.Fprintf(stderr, "Generate SBOM and build provenance records.\n\n")
		fmt.Fprintf(stderr, "Flags:\n")
		fs.PrintDefaults()
	}

	var (
		dir       = fs.String("dir", "", "project root directory (default: current directory)")
		outputDir = fs.String("output-dir", "", "directory for generated files (default: project root)")
	)
	if err := fs.Parse(args); err != nil {
		return 1
	}

	projectRoot := *dir
	if projectRoot == "" {
		var err error
		projectRoot, err = os.Getwd()
		if err != nil {
			fmt.Fprintf(stderr, "gofusa release: get working directory: %v\n", err)
			return 1
		}
	}

	outDir := *outputDir
	if outDir == "" {
		outDir = projectRoot
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fmt.Fprintf(stderr, "gofusa release: create output directory: %v\n", err)
		return 1
	}

	sbom, err := release.BuildSBOM(projectRoot)
	if err != nil {
		fmt.Fprintf(stderr, "gofusa release: build SBOM: %v\n", err)
		return 1
	}
	sbomPath := filepath.Join(outDir, release.SBOMFile)
	err = release.SaveJSON(sbomPath, sbom)
	if err != nil {
		fmt.Fprintf(stderr, "gofusa release: save SBOM: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "SBOM written to %s (%d components)\n", sbomPath, len(sbom.Components))

	prov, err := release.BuildProvenance(context.Background(), projectRoot)
	if err != nil {
		fmt.Fprintf(stderr, "gofusa release: build provenance: %v\n", err)
		return 1
	}
	provPath := filepath.Join(outDir, release.ProvenanceFile)
	err = release.SaveJSON(provPath, prov)
	if err != nil {
		fmt.Fprintf(stderr, "gofusa release: save provenance: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "Provenance written to %s\n", provPath)
	return 0
}
