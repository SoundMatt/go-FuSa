package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/SoundMatt/go-FuSa/auditpack"
)

// runAuditPack bundles all evidence artifacts into a single ZIP for auditors.
//
//fusa:req REQ-CLI016
func runAuditPack(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa audit-pack", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: gofusa audit-pack [flags]\n\n")
		fmt.Fprintf(stderr, "Bundle all go-FuSa evidence artifacts into a single audit-pack.zip\n")
		fmt.Fprintf(stderr, "for submission to functional safety auditors.\n\n")
		fmt.Fprintf(stderr, "Included files (if present):\n")
		for _, f := range auditpack.EvidenceFiles {
			fmt.Fprintf(stderr, "  %s\n", f)
		}
		fmt.Fprintf(stderr, "\nFlags:\n")
		fs.PrintDefaults()
	}

	var (
		dir    = fs.String("dir", "", "project root directory (default: current directory)")
		output = fs.String("output", "", "output path for audit-pack.zip (default: <project-root>/audit-pack.zip)")
	)
	if err := fs.Parse(args); err != nil {
		return 1
	}

	projectRoot := *dir
	if projectRoot == "" {
		var err error
		projectRoot, err = os.Getwd()
		if err != nil {
			fmt.Fprintf(stderr, "gofusa audit-pack: get working directory: %v\n", err)
			return 1
		}
	}

	outPath := *output
	if outPath == "" {
		outPath = filepath.Join(projectRoot, auditpack.AuditPackFile)
	}

	outDir := filepath.Dir(outPath)
	if err := os.MkdirAll(outDir, 0o750); err != nil {
		fmt.Fprintf(stderr, "gofusa audit-pack: mkdir: %v\n", err)
		return 1
	}

	manifest, err := auditpack.Pack(projectRoot, outPath)
	if err != nil {
		fmt.Fprintf(stderr, "gofusa audit-pack: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "Audit pack written to %s\n", outPath)
	fmt.Fprintf(stdout, "Module: %s\n", manifest.Module)
	fmt.Fprintf(stdout, "Files packed: %d\n\n", len(manifest.Files))
	for _, entry := range manifest.Files {
		fmt.Fprintf(stdout, "  %-40s  %s\n", entry.Path, entry.SHA256[:16]+"…")
	}
	return 0
}
