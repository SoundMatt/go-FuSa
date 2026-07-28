package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/config"
	"github.com/SoundMatt/go-FuSa/sas"
	"github.com/SoundMatt/go-FuSa/stubcheck"
)

//fusa:req REQ-CLI-SAS001
func runSas(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa sas", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: gofusa sas [flags]\n\n")
		fmt.Fprintf(stderr, "Generate a Software Accomplishment Summary (DO-178C §11.20).\n\n")
		fmt.Fprintf(stderr, "Flags:\n")
		fs.PrintDefaults()
	}

	var (
		dir      = fs.String("dir", "", "project root directory (default: current directory)")
		dalFlag  = fs.String("dal", "DAL-B", "design assurance level")
		prepared = fs.String("prepared-by", "", "name of the person or team preparing the SAS")
		format   = fs.String("format", "markdown", "output format: markdown or json")
		output   = fs.String("output", sas.SASFile, "write SAS to file (use - for stdout)")
		//fusa:req REQ-SAS007
		strict             = fs.Bool("strict", false, "escalate an unsuppressed FUSA-STUB002 finding to exit 1 (implies --require-attestation)")
		requireAttestation = fs.Bool("require-attestation", false, "escalate an unsuppressed FUSA-STUB002 finding to exit 1")
	)
	if code := parseFlags(fs, args); code != 0 {
		return code
	}

	projectRoot := *dir
	if projectRoot == "" {
		var err error
		projectRoot, err = os.Getwd()
		if err != nil {
			fmt.Fprintf(stderr, "gofusa sas: get working directory: %v\n", err)
			return fusa.ExitRuntime
		}
	}

	cfg, _ := config.Load(filepath.Join(projectRoot, config.ConfigFile))
	project := filepath.Base(projectRoot)
	version := "unknown"
	if cfg != nil {
		if cfg.Project.Name != "" {
			project = cfg.Project.Name
		}
		if cfg.Version != "" {
			version = cfg.Version
		}
	}

	doc, err := sas.Build(projectRoot, project, version, *dalFlag, *prepared)
	if err != nil {
		fmt.Fprintf(stderr, "gofusa sas: %v\n", err)
		return fusa.ExitRuntime
	}

	w := stdout
	outPath := ""
	if *output != "" && *output != "-" {
		outPath = *output
		if !filepath.IsAbs(outPath) {
			outPath = filepath.Join(projectRoot, outPath)
		}
		f, err := os.Create(outPath)
		if err != nil {
			fmt.Fprintf(stderr, "gofusa sas: create output: %v\n", err)
			return fusa.ExitRuntime
		}
		defer func() { _ = f.Close() }()
		w = f
		defer fmt.Fprintf(stdout, "SAS written to %s\n", outPath)
	}

	if err := sas.Render(w, doc, *format); err != nil {
		fmt.Fprintf(stderr, "gofusa sas: render: %v\n", err)
		return fusa.ExitRuntime
	}

	// x-FuSa spec §9.3: sas.json is not a replacement for sas.md — a tool
	// MUST also write the human-readable companion, alongside the primary
	// output file (not necessarily projectRoot — --output may point
	// elsewhere entirely). Write whichever of the two the primary
	// --format/--output above didn't produce.
	if outPath != "" {
		companion := sas.SASJSONFile
		companionFormat := "json"
		if *format == "json" {
			companion = sas.SASFile
			companionFormat = "markdown"
		}
		companionPath := filepath.Join(filepath.Dir(outPath), companion)
		if err := writeFormattedSAS(companionPath, doc, companionFormat); err != nil {
			fmt.Fprintf(stderr, "gofusa sas: write companion %s: %v\n", companion, err)
			return fusa.ExitRuntime
		}
		fmt.Fprintf(stdout, "SAS companion written to %s\n", companionPath)
	}

	code := fusa.ExitOK
	if len(doc.Gaps) > 0 {
		code = fusa.ExitGateFail
	}
	if sc := gateContentQuality(stderr, "sas", projectRoot, sas.SASJSONFile, stubcheck.SasFields(doc), doc.Attestation, doc.Deviations, *strict || *requireAttestation); sc != fusa.ExitOK {
		code = sc
	}
	return code
}

func writeFormattedSAS(path string, doc *sas.SAS, format string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return sas.Render(f, doc, format)
}
