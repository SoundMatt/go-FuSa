// Package report generates go-FuSa compliance reports.
//
// Use New to construct a Report from a slice of Findings, then Render or
// RenderToFile to produce text or JSON output.
package report

import (
	"fmt"
	"io"
	"os"
	"time"

	fusa "github.com/SoundMatt/go-FuSa"
)

// Report is the top-level go-FuSa compliance report.
// It carries the §3.1 common header plus the §3.2 report-extension fields.
//
//fusa:req REQ-RPT005
type Report struct {
	// §3.1 common header — present on every JSON document
	SchemaVersion string    `json:"schemaVersion"`
	Kind          string    `json:"kind"`
	Tool          string    `json:"tool"`
	ToolVersion   string    `json:"toolVersion"`
	Language      string    `json:"language"`
	GeneratedAt   time.Time `json:"generatedAt"`

	// §3.2 report-extension fields
	ProjectRoot string      `json:"projectRoot"`
	Project     string      `json:"project,omitempty"`
	Standard    string      `json:"standard,omitempty"`
	ASIL        string      `json:"asil,omitempty"`
	Error       *ErrorDoc   `json:"error,omitempty"`

	Findings     []fusa.Finding `json:"findings"`
	Summary      Summary        `json:"summary"`
	SummaryTable SummaryTable   `json:"summaryTable"`

	// NoSummary suppresses the SUMMARY / TOP RULES block in text output.
	// It does not affect JSON serialisation.
	NoSummary bool `json:"-"`
}

// ErrorDoc is the structured error field emitted on exit 3 (§3.2).
type ErrorDoc struct {
	Code    string `json:"code"`    // no-config | invalid-config | unsupported | internal
	Message string `json:"message"`
}

// Summary holds aggregate finding counts.
type Summary struct {
	Total    int `json:"total"`
	Errors   int `json:"errors"`
	Warnings int `json:"warnings"`
	Infos    int `json:"infos"`
}

// New builds a Report from findings, populates the §3.1 header, and
// auto-derives category and fingerprint on any finding that lacks them.
//
//fusa:req REQ-RPT003
//fusa:req REQ-NF002
func New(projectRoot string, findings []fusa.Finding) *Report {
	enriched := make([]fusa.Finding, len(findings))
	for i, f := range findings {
		if f.Category == "" {
			f.Category = fusa.DeriveCategory(f.RuleID)
		}
		if f.Fingerprint == "" && f.Location.File != "" {
			f.Fingerprint = fusa.ComputeFingerprint(f)
		}
		enriched[i] = f
	}

	r := &Report{
		SchemaVersion: fusa.SpecVersion,
		Kind:          "check-report",
		Tool:          "go-FuSa",
		ToolVersion:   fusa.Version,
		Language:      "go",
		GeneratedAt:   time.Now().UTC(),
		ProjectRoot:   projectRoot,
		Findings:      enriched,
		SummaryTable:  buildSummaryTable(enriched),
	}
	r.Summary.Total = len(enriched)
	for _, f := range enriched {
		switch f.Severity {
		case fusa.SeverityError:
			r.Summary.Errors++
		case fusa.SeverityWarning:
			r.Summary.Warnings++
		case fusa.SeverityInfo:
			r.Summary.Infos++
		}
	}
	return r
}

// Render writes r to w in the requested format ("text", "json", "html", or "sarif").
//
//fusa:req REQ-REPORT001
func Render(w io.Writer, r *Report, format string) error {
	switch format {
	case "", "text":
		return renderText(w, r)
	case "json":
		return renderJSON(w, r)
	case "html":
		return RenderHTML(w, r)
	case "sarif":
		return renderSARIF(w, r)
	default:
		return fmt.Errorf("report: unsupported format %q", format)
	}
}

// RenderToFile writes the report to path in format.
// If path is empty the report is written to stdout.
//
//fusa:req REQ-REPORT002
func RenderToFile(r *Report, format, path string) error {
	if path == "" {
		return Render(os.Stdout, r, format)
	}
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("report: create %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	return Render(f, r, format)
}
