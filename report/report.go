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
//
//fusa:req REQ-RPT005
type Report struct {
	GeneratedAt time.Time      `json:"generatedAt"`
	ProjectRoot string         `json:"projectRoot"`
	Findings    []fusa.Finding `json:"findings"`
	Summary     Summary        `json:"summary"`
}

// Summary holds aggregate finding counts.
type Summary struct {
	Total    int `json:"total"`
	Errors   int `json:"errors"`
	Warnings int `json:"warnings"`
	Infos    int `json:"infos"`
}

// New builds a Report from findings and computes the Summary.
//
//fusa:req REQ-RPT003
//fusa:req REQ-NF002
func New(projectRoot string, findings []fusa.Finding) *Report {
	r := &Report{
		GeneratedAt: time.Now().UTC(),
		ProjectRoot: projectRoot,
		Findings:    findings,
	}
	r.Summary.Total = len(findings)
	for _, f := range findings {
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
