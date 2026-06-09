package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/auditpack"
	"github.com/SoundMatt/go-FuSa/boundary"
	"github.com/SoundMatt/go-FuSa/config"
	"github.com/SoundMatt/go-FuSa/cyber"
	"github.com/SoundMatt/go-FuSa/fmea"
	"github.com/SoundMatt/go-FuSa/release"
	"github.com/SoundMatt/go-FuSa/report"
	"github.com/SoundMatt/go-FuSa/tara"
	"github.com/SoundMatt/go-FuSa/vuln"
)

func runRelease(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa release", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: gofusa release [flags]\n\n")
		fmt.Fprintf(stderr, "Generate SBOM, build provenance, and artifact manifest.\n")
		fmt.Fprintf(stderr, "With --full, also runs fmea, boundary, vuln, and audit-pack.\n\n")
		fmt.Fprintf(stderr, "Flags:\n")
		fs.PrintDefaults()
	}

	var (
		dir         = fs.String("dir", "", "project root directory (default: current directory)")
		outputDir   = fs.String("output-dir", "", "directory for generated files (default: project root)")
		full        = fs.Bool("full", false, "also run fmea, boundary, vuln scan, and audit-pack")
		spdxVersion = fs.String("spdx-version", "3.0.1", "SPDX version for SBOM output: 2.2, 2.3, or 3.0.1")
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

	if err := os.MkdirAll(outDir, 0o750); err != nil {
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
	var sbomDoc any
	sbomVersionLabel := *spdxVersion
	switch *spdxVersion {
	case "2.2":
		sbomDoc = release.ToSPDX22(sbom)
	case "2.3":
		sbomDoc = release.ToSPDX23(sbom)
	case "", "3.0.1":
		sbomDoc = release.ToSPDX31(sbom)
		sbomVersionLabel = "3.0.1"
	default:
		fmt.Fprintf(stderr, "gofusa release: unsupported --spdx-version %q (use 2.2, 2.3, or 3.0.1)\n", *spdxVersion)
		return 1
	}
	if err = release.SaveJSON(sbomPath, sbomDoc); err != nil {
		fmt.Fprintf(stderr, "gofusa release: save SBOM: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "SBOM written to %s (%d components, SPDX %s)\n", sbomPath, len(sbom.Components), sbomVersionLabel)

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

	// Cyber scan + TARA
	cfg, cfgErr := config.Load(filepath.Join(projectRoot, ".fusa.json"))
	if cfgErr != nil && !errors.Is(cfgErr, fusa.ErrNoConfig) {
		fmt.Fprintf(stderr, "gofusa release --full: load config: %v\n", cfgErr)
		return 1
	}
	if cfg == nil {
		cfg = config.Default("", filepath.Base(projectRoot))
	}
	cyberFindings, cyberErr := cyber.Scan(context.Background(), projectRoot, cfg)
	if cyberErr != nil {
		fmt.Fprintf(stderr, "gofusa release --full: cyber scan: %v (skipping)\n", cyberErr)
	} else {
		cyberPath := filepath.Join(outDir, "cyber-report.json")
		if cyberWriteErr := writeCyberReport(cyberPath, cyberFindings, projectRoot); cyberWriteErr != nil {
			fmt.Fprintf(stderr, "gofusa release --full: write cyber-report.json: %v\n", cyberWriteErr)
		} else {
			fmt.Fprintf(stdout, "Cyber report written to %s (%d findings)\n", cyberPath, len(cyberFindings))
		}

		taraReport, taraErr := tara.Scan(projectRoot, cyberFindings)
		if taraErr != nil {
			fmt.Fprintf(stderr, "gofusa release --full: tara scan: %v (skipping)\n", taraErr)
		} else {
			taraJSONPath := filepath.Join(outDir, tara.TARAFile)
			if taraJSONErr := writeFile(taraJSONPath, func(f io.Writer) error {
				return tara.Render(f, taraReport, "json")
			}); taraJSONErr != nil {
				fmt.Fprintf(stderr, "gofusa release --full: write tara.json: %v\n", taraJSONErr)
			} else {
				fmt.Fprintf(stdout, "TARA report written to %s (%d threats)\n", taraJSONPath, len(taraReport.Entries))
			}
			taraMDPath := filepath.Join(outDir, tara.TARAMarkdownFile)
			if taraMDErr := writeFile(taraMDPath, func(f io.Writer) error {
				return tara.Render(f, taraReport, "markdown")
			}); taraMDErr != nil {
				fmt.Fprintf(stderr, "gofusa release --full: write tara.md: %v\n", taraMDErr)
			} else {
				fmt.Fprintf(stdout, "TARA markdown written to %s\n", taraMDPath)
			}
		}
	}

	// Audit pack
	auditPath := filepath.Join(outDir, auditpack.AuditPackFile)
	auditManifest, err := auditpack.Pack(projectRoot, auditPath)
	if err != nil {
		fmt.Fprintf(stderr, "gofusa release --full: audit-pack: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "Audit pack written to %s (%d files)\n", auditPath, len(auditManifest.Files))

	// HTML evidence bundle
	htmlPath := filepath.Join(outDir, "evidence.html")
	f, htmlErr := os.Create(htmlPath)
	if htmlErr != nil {
		fmt.Fprintf(stderr, "gofusa release --full: create evidence.html: %v\n", htmlErr)
	} else {
		if werr := report.RenderEvidenceHTML(f, projectRoot); werr != nil {
			fmt.Fprintf(stderr, "gofusa release --full: render evidence.html: %v\n", werr)
		} else {
			fmt.Fprintf(stdout, "evidence.html written to %s\n", htmlPath)
		}
		_ = f.Close()
	}

	return 0
}
