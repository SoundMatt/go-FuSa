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
		fmt.Fprintf(stderr, "Generate SBOM (SPDX 3.0.1), build provenance, and artifact manifest.\n\n")
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
	//fusa:req REQ-RELEASE007
	if err = release.SaveJSON(sbomPath, release.ToSPDX31(sbom)); err != nil {
		fmt.Fprintf(stderr, "gofusa release: save SBOM: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "SBOM written to %s (%d components, SPDX 3.0.1)\n", sbomPath, len(sbom.Components))

	prov, err := release.BuildProvenance(context.Background(), projectRoot)
	if err != nil {
		fmt.Fprintf(stderr, "gofusa release: build provenance: %v\n", err)
		return 1
	}
	provPath := filepath.Join(outDir, release.ProvenanceFile)
	if err = release.SaveJSON(provPath, prov); err != nil {
		fmt.Fprintf(stderr, "gofusa release: save provenance: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "Provenance written to %s\n", provPath)

	//fusa:req REQ-RELEASE008
	manifest, err := release.BuildManifest([]string{sbomPath, provPath})
	if err != nil {
		fmt.Fprintf(stderr, "gofusa release: build manifest: %v\n", err)
		return 1
	}
	manifestPath := filepath.Join(outDir, release.ManifestFile)
	if err = release.SaveJSON(manifestPath, manifest); err != nil {
		fmt.Fprintf(stderr, "gofusa release: save manifest: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "Artifact manifest written to %s (%d artifacts)\n", manifestPath, len(manifest.Artifacts))
	return 0
}
