// Package diff compares two go-FuSa check reports and categorises findings
// as introduced, resolved, or unchanged between runs.
package diff

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/report"
)

// Diff holds the categorised delta between two reports.
type Diff struct {
	Introduced []fusa.Finding `json:"introduced"`
	Resolved   []fusa.Finding `json:"resolved"`
	Unchanged  []fusa.Finding `json:"unchanged"`
}

// Compare returns the delta between a baseline and a current report.
//
//fusa:req REQ-DIFF001
func Compare(baseline, current *report.Report) *Diff {
	baseSet := index(baseline.Findings)
	curSet := index(current.Findings)

	d := &Diff{}
	for key, f := range curSet {
		if _, ok := baseSet[key]; ok {
			d.Unchanged = append(d.Unchanged, f)
		} else {
			d.Introduced = append(d.Introduced, f)
		}
	}
	for key, f := range baseSet {
		if _, ok := curSet[key]; !ok {
			d.Resolved = append(d.Resolved, f)
		}
	}
	return d
}

// index returns a map keyed by "ruleID:file:line" for deduplication.
func index(findings []fusa.Finding) map[string]fusa.Finding {
	m := make(map[string]fusa.Finding, len(findings))
	for _, f := range findings {
		key := fmt.Sprintf("%s:%s:%d", f.RuleID, f.Location.File, f.Location.Line)
		m[key] = f
	}
	return m
}

// LoadReport reads and parses a JSON report file produced by gofusa check --format json.
//
//fusa:req REQ-DIFF002
func LoadReport(path string) (*report.Report, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("diff: read %s: %w", path, err)
	}
	var r report.Report
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("diff: parse %s: %w", path, err)
	}
	return &r, nil
}

// Render writes the diff to w in the requested format ("text" or "json").
//
//fusa:req REQ-DIFF003
func Render(w io.Writer, d *Diff, format string) error {
	switch format {
	case "", "text":
		return renderText(w, d)
	case "json":
		return renderJSON(w, d)
	default:
		return fmt.Errorf("diff: unsupported format %q", format)
	}
}

func renderText(w io.Writer, d *Diff) error {
	lines := []string{
		fmt.Sprintf("Introduced: %d  Resolved: %d  Unchanged: %d",
			len(d.Introduced), len(d.Resolved), len(d.Unchanged)),
		"",
	}
	for _, f := range d.Introduced {
		lines = append(lines, fmt.Sprintf("[+] %s  %s  (%s:%d)", f.RuleID, f.Message, f.Location.File, f.Location.Line))
	}
	for _, f := range d.Resolved {
		lines = append(lines, fmt.Sprintf("[-] %s  %s  (%s:%d)", f.RuleID, f.Message, f.Location.File, f.Location.Line))
	}
	for _, line := range lines {
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}
	return nil
}

func renderJSON(w io.Writer, d *Diff) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(d)
}
