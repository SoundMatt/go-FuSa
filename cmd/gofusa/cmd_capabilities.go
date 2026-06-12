package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"time"

	fusa "github.com/SoundMatt/go-FuSa"
)

// capabilities is the §9.1 discovery document (kind: "capabilities").
type capabilities struct {
	SchemaVersion string              `json:"schemaVersion"`
	Kind          string              `json:"kind"`
	Tool          string              `json:"tool"`
	ToolVersion   string              `json:"toolVersion"`
	Language      string              `json:"language"`
	GeneratedAt   time.Time           `json:"generatedAt"`
	SpecVersion   string              `json:"specVersion"`
	Commands      []string            `json:"commands"`
	Formats       map[string][]string `json:"formats"`
	Standards     []string            `json:"standards"`
}

//fusa:req REQ-CLI-CAP001
func runCapabilities(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa capabilities", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: gofusa capabilities [--format json]\n\n")
		fmt.Fprintf(stderr, "Report the tool's supported commands, formats, and standards.\n\n")
		fmt.Fprintf(stderr, "Flags:\n")
		fs.PrintDefaults()
	}
	format := fs.String("format", "json", "output format: json")
	if code := parseFlags(fs, args); code != 0 {
		return code
	}
	if *format != "json" && *format != "" {
		return usageErrorf(stderr, "capabilities", "unsupported format %q (only json)", *format)
	}

	cap := &capabilities{
		SchemaVersion: fusa.SpecVersion,
		Kind:          "capabilities",
		Tool:          "go-FuSa",
		ToolVersion:   fusa.Version,
		Language:      "go",
		GeneratedAt:   time.Now().UTC(),
		SpecVersion:   fusa.SpecVersion,
		Commands: []string{
			"version", "capabilities", "init", "check", "trace", "qualify",
			"release", "audit-pack", "report",
			"verify", "hara", "tara", "fmea", "safety-case", "coupling",
			"cyber", "vuln", "boundary", "coverage", "diff",
			"iso26262", "iec61508", "iec62443", "slsa", "do178", "iso21434", "unece",
			"lint", "analyze", "badge", "disposition", "sign",
			"sas", "sci", "pr", "req", "fix", "hooks", "impact", "metrics",
			"comp", "template", "misra",
		},
		Formats: map[string][]string{
			"check":    {"text", "json", "html", "sarif", "md"},
			"report":   {"text", "json", "html", "sarif", "md"},
			"trace":    {"text", "json", "md"},
			"qualify":  {"text", "json"},
			"comp":     {"text", "json"},
			"iso26262": {"text", "json"},
			"iec61508": {"text", "json"},
			"iec62443": {"text", "json"},
			"slsa":     {"text", "json"},
			"do178":    {"text", "json"},
			"iso21434": {"text", "json"},
			"unece":    {"text", "json"},
		},
		Standards: []string{
			"iso26262", "iec61508", "do178c", "iso21434", "unece-r155",
			"iec62443", "slsa-v1.0",
		},
	}

	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(cap); err != nil {
		return fusa.ExitRuntime
	}
	return fusa.ExitOK
}
