// Package gapreport provides the canonical x-FuSa standards gap-report schema (§9.3).
//
// All standards commands (iso26262, iec61508, do178, iso21434, unece, …) produce
// a Report when emitting --format json. FuSaOps rolls up these documents using
// the objectives/summary shape defined here.
package gapreport

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	fusa "github.com/SoundMatt/go-FuSa"
)

// Status values for Objective.Status (§9.3).
const (
	StatusSatisfied = "satisfied" // all required evidence present, all clauses met
	StatusPartial   = "partial"   // some evidence present but not all clauses met
	StatusGap       = "gap"       // no evidence
)

// Objective is one standards objective in the gap report.
type Objective struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Clause   string   `json:"clause,omitempty"`
	Status   string   `json:"status"`
	Evidence []string `json:"evidence,omitempty"`
	Findings []string `json:"findings,omitempty"` // blocking rule ids (not fingerprints)
}

// Summary is the invariant summary: satisfied + partial + gaps == total.
type Summary struct {
	Total     int `json:"total"`
	Satisfied int `json:"satisfied"`
	Partial   int `json:"partial"`
	Gaps      int `json:"gaps"`
}

// Report is the canonical gap-report document (§9.3 + §3.1 common header).
//
//fusa:req REQ-GAPREPORT001
type Report struct {
	SchemaVersion string      `json:"schemaVersion"`
	Kind          string      `json:"kind"`
	Tool          string      `json:"tool"`
	ToolVersion   string      `json:"toolVersion"`
	Language      string      `json:"language"`
	GeneratedAt   time.Time   `json:"generatedAt"`
	ProjectRoot   string      `json:"projectRoot"`
	Standard      string      `json:"standard"` // canonical id §2.4.1
	Objectives    []Objective `json:"objectives"`
	Summary       Summary     `json:"summary"`
}

// New builds a canonical Report with header fields pre-populated.
func New(projectRoot, standard string) *Report {
	return &Report{
		SchemaVersion: fusa.SpecVersion,
		Kind:          "gap-report",
		Tool:          "go-FuSa",
		ToolVersion:   fusa.Version,
		Language:      "go",
		GeneratedAt:   time.Now().UTC(),
		ProjectRoot:   projectRoot,
		Standard:      standard,
	}
}

// AddObjective appends an objective and updates the summary counts.
func (r *Report) AddObjective(obj Objective) {
	r.Objectives = append(r.Objectives, obj)
	r.Summary.Total++
	switch obj.Status {
	case StatusSatisfied:
		r.Summary.Satisfied++
	case StatusPartial:
		r.Summary.Partial++
	default:
		r.Summary.Gaps++
	}
}

// Render writes the report to w in the requested format ("json" or "text").
//
//fusa:req REQ-GAPREPORT002
func Render(w io.Writer, r *Report, format string) error {
	switch format {
	case "json", "":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	case "text":
		return renderText(w, r)
	default:
		return fmt.Errorf("gapreport: unsupported format %q", format)
	}
}

func renderText(w io.Writer, r *Report) error {
	fmt.Fprintf(w, "%s Gap Report\n", r.Standard)
	fmt.Fprintf(w, "Generated: %s   Project: %s\n\n",
		r.GeneratedAt.Format("2006-01-02"), r.ProjectRoot)
	fmt.Fprintf(w, "Summary: %d total  %d satisfied  %d partial  %d gaps\n\n",
		r.Summary.Total, r.Summary.Satisfied, r.Summary.Partial, r.Summary.Gaps)
	for _, obj := range r.Objectives {
		icon := statusIcon(obj.Status)
		fmt.Fprintf(w, "  %s [%s] %-12s  %s\n", icon, obj.ID, obj.Status, obj.Title)
		if len(obj.Findings) > 0 {
			fmt.Fprintf(w, "     findings: %v\n", obj.Findings)
		}
	}
	return nil
}

func statusIcon(s string) string {
	switch s {
	case StatusSatisfied:
		return "✓"
	case StatusPartial:
		return "?"
	default:
		return "✗"
	}
}
