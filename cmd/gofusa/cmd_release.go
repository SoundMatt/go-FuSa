package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/SoundMatt/go-FuSa/auditpack"
	"github.com/SoundMatt/go-FuSa/boundary"
	"github.com/SoundMatt/go-FuSa/fmea"
	"github.com/SoundMatt/go-FuSa/release"
	"github.com/SoundMatt/go-FuSa/vuln"
)

func runRelease(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa release", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: gofusa release [flags]\n\n")
		fmt.Fprintf(stderr, "Generate SBOM (SPDX 3.0.1), build provenance, and artifact manifest.\n")
		fmt.Fprintf(stderr, "With --full, also runs fmea, boundary, vuln, and audit-pack.\n\n")
		fmt.Fprintf(stderr, "Flags:\n")
		fs.PrintDefaults()
	}

	var (
		dir       = fs.String("dir", "", "project root directory (default: current directory)")
		outputDir = fs.String("output-dir", "", "directory for generated files (default: project root)")
		full      = fs.Bool("full", false, "also run fmea, boundary, vuln scan, and audit-pack")
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

	if *full {
		return runReleaseFullBundle(projectRoot, outDir, stdout, stderr)
	}
	return 0
}

// runReleaseFullBundle generates the additional safety evidence artifacts.
//
//fusa:req REQ-CLI016
func runReleaseFullBundle(projectRoot, outDir string, stdout, stderr io.Writer) int {
	// dFMEA
	fmeaReport, err := fmea.Scan(projectRoot)
	if err != nil {
		fmt.Fprintf(stderr, "gofusa release --full: fmea scan: %v\n", err)
		return 1
	}
	for _, pair := range []struct{ path, format string }{
		{filepath.Join(outDir, fmea.FMEAFile), "json"},
		{filepath.Join(outDir, fmea.FMEACSVFile), "csv"},
	} {
		f, ferr := os.Create(pair.path)
		if ferr != nil {
			fmt.Fprintf(stderr, "gofusa release --full: create %s: %v\n", pair.path, ferr)
			return 1
		}
		if werr := fmea.Render(f, fmeaReport, pair.format); werr != nil {
			_ = f.Close()
			fmt.Fprintf(stderr, "gofusa release --full: render fmea %s: %v\n", pair.format, werr)
			return 1
		}
		_ = f.Close()
		fmt.Fprintf(stdout, "FMEA written to %s\n", pair.path)
	}

	// Boundary diagram
	boundaryDiagram, err := boundary.Scan(projectRoot)
	if err != nil {
		fmt.Fprintf(stderr, "gofusa release --full: boundary scan: %v\n", err)
		return 1
	}
	for _, pair := range []struct{ path, format string }{
		{filepath.Join(outDir, boundary.BoundaryFile), "mermaid"},
		{filepath.Join(outDir, boundary.BoundaryDOTFile), "dot"},
	} {
		f, ferr := os.Create(pair.path)
		if ferr != nil {
			fmt.Fprintf(stderr, "gofusa release --full: create %s: %v\n", pair.path, ferr)
			return 1
		}
		if werr := boundary.Render(f, boundaryDiagram, pair.format); werr != nil {
			_ = f.Close()
			fmt.Fprintf(stderr, "gofusa release --full: render boundary %s: %v\n", pair.format, werr)
			return 1
		}
		_ = f.Close()
		fmt.Fprintf(stdout, "Boundary diagram written to %s\n", pair.path)
	}

	// Vulnerability scan
	vulnReport, err := vuln.Scan(projectRoot)
	if err != nil {
		fmt.Fprintf(stderr, "gofusa release --full: vuln scan: %v (skipping)\n", err)
	} else {
		vulnPath := filepath.Join(outDir, vuln.VulnFile)
		f, ferr := os.Create(vulnPath)
		if ferr != nil {
			fmt.Fprintf(stderr, "gofusa release --full: create %s: %v\n", vulnPath, ferr)
			return 1
		}
		if werr := vuln.Render(f, vulnReport, "json"); werr != nil {
			_ = f.Close()
			fmt.Fprintf(stderr, "gofusa release --full: write vuln.json: %v\n", werr)
			return 1
		}
		_ = f.Close()
		fmt.Fprintf(stdout, "Vulnerability report written to %s (%d findings)\n", vulnPath, len(vulnReport.Findings))
	}

	// Audit pack
	auditPath := filepath.Join(outDir, auditpack.AuditPackFile)
	auditManifest, err := auditpack.Pack(projectRoot, auditPath)
	if err != nil {
		fmt.Fprintf(stderr, "gofusa release --full: audit-pack: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "Audit pack written to %s (%d files)\n", auditPath, len(auditManifest.Files))

	return 0
}
