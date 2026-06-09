// Package iso21434 produces an ISO 21434 cybersecurity compliance gap report.
//
// It maps evidence produced by the go-FuSa pipeline to key objectives from
// ISO 21434 and reports PASS, GAP, MANUAL, or N/A for each, respecting
// Cybersecurity Assurance Levels (CAL 1–4). The result can be read by a
// cybersecurity assessor as a starting point for ISO 21434 compliance.
//
// Usage:
//
//	report, err := iso21434.Assess(projectRoot, "CAL-2")
//	_ = iso21434.Render(os.Stdout, report, "text")
package iso21434

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/config"
	"github.com/SoundMatt/go-FuSa/engine"
)

// ReportFile is the default output filename.
const ReportFile = "iso21434-gap-report.json"

// CAL represents a Cybersecurity Assurance Level.
type CAL string

const (
	CAL1 CAL = "CAL-1"
	CAL2 CAL = "CAL-2"
	CAL3 CAL = "CAL-3"
	CAL4 CAL = "CAL-4"
)

// ObjectiveStatus is the assessment result for a single objective.
type ObjectiveStatus string

const (
	StatusPass   ObjectiveStatus = "PASS"
	StatusGap    ObjectiveStatus = "GAP"
	StatusManual ObjectiveStatus = "MANUAL"
	StatusNA     ObjectiveStatus = "N/A"
)

// Objective is a single ISO 21434 compliance objective.
type Objective struct {
	ID           string          `json:"id"`
	Description  string          `json:"description"`
	EvidenceFile string          `json:"evidenceFile,omitempty"`
	MinCAL       int             `json:"minCal"` // 0 = all levels; 1-4 = minimum CAL required
	Status       ObjectiveStatus `json:"status"`
	Evidence     string          `json:"evidence,omitempty"`
	Gap          string          `json:"gap,omitempty"`
	Note         string          `json:"note,omitempty"`
}

// Report is the complete ISO 21434 gap assessment.
type Report struct {
	Project    string      `json:"project"`
	CAL        CAL         `json:"cal"`
	Generated  time.Time   `json:"generated"`
	Pass       int         `json:"pass"`
	Gap        int         `json:"gap"`
	Manual     int         `json:"manual"`
	NA         int         `json:"na"`
	Objectives []Objective `json:"objectives"`
}

var allObjectives = []Objective{
	// Automatable objectives
	{ID: "6.1", Description: "Cybersecurity plan", EvidenceFile: "cyber-plan.json", MinCAL: 1},
	{ID: "8.3", Description: "Vulnerability monitoring evidence", EvidenceFile: "vuln.json", MinCAL: 1},
	{ID: "9.1", Description: "TARA — threat analysis", EvidenceFile: "tara.json", MinCAL: 1},
	{ID: "9.2", Description: "TARA — asset identification", EvidenceFile: "tara.json", MinCAL: 1},
	{ID: "9.3", Description: "TARA — threat scenarios", EvidenceFile: "tara.json", MinCAL: 1},
	{ID: "9.4", Description: "TARA — impact and risk rating", EvidenceFile: "tara.json", MinCAL: 1},
	{ID: "9.5", Description: "TARA — attack feasibility assessment", EvidenceFile: "tara.json", MinCAL: 2},
	{ID: "9.6", Description: "TARA — risk treatment decisions", EvidenceFile: "tara.json", MinCAL: 2},
	{ID: "10.1", Description: "Cybersecurity requirements", EvidenceFile: ".fusa-reqs.json", MinCAL: 1},
	{ID: "10.3", Description: "Cybersecurity design evidence", EvidenceFile: "safety-case.json", MinCAL: 2},
	{ID: "10.4", Description: "Static cybersecurity analysis", EvidenceFile: "check-report.json", MinCAL: 1},
	{ID: "11.1", Description: "Cybersecurity validation report", EvidenceFile: "cyber-validation.json", MinCAL: 2},
	{ID: "A.1", Description: "SBOM (Annex A work product)", EvidenceFile: "sbom.json", MinCAL: 1},
	{ID: "A.2", Description: "Build provenance (Annex A)", EvidenceFile: "provenance.json", MinCAL: 1},

	// MANUAL objectives
	{ID: "5.1", Description: "Cybersecurity governance", Note: "MANUAL — requires organisation-level CSMS policy"},
	{ID: "6.2", Description: "Cybersecurity responsibility", Note: "MANUAL — requires named role assignments"},
	{ID: "7.1", Description: "Supplier management", Note: "MANUAL — requires third-party cybersecurity assessment records"},
	{ID: "12.1", Description: "Production security", Note: "MANUAL — requires manufacturing process documentation"},
	{ID: "13.1", Description: "Operations monitoring", Note: "MANUAL — requires incident response plan"},
	{ID: "14.1", Description: "End-of-support plan", Note: "MANUAL — requires decommissioning procedure"},
	{ID: "15.1", Description: "Incident response (PSIRT)", Note: "MANUAL — requires PSIRT process documentation"},
}

// calRank converts a CAL to its numeric rank for comparison.
func calRank(c CAL) int {
	switch c {
	case CAL1:
		return 1
	case CAL2:
		return 2
	case CAL3:
		return 3
	case CAL4:
		return 4
	default:
		return 1
	}
}

// parseCAL converts a string to a CAL constant, defaulting to CAL1.
func parseCAL(s string) CAL {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CAL-1", "CAL1":
		return CAL1
	case "CAL-2", "CAL2":
		return CAL2
	case "CAL-3", "CAL3":
		return CAL3
	case "CAL-4", "CAL4":
		return CAL4
	default:
		return CAL1
	}
}

// Assess scans projectRoot and returns an ISO 21434 gap report for the given CAL.
//
//fusa:req REQ-ISO21434-002
func Assess(projectRoot, calStr string) (*Report, error) {
	cal := parseCAL(calStr)
	project := filepath.Base(projectRoot)

	rep := &Report{
		Project:   project,
		CAL:       cal,
		Generated: time.Now().UTC(),
	}

	rank := calRank(cal)

	for _, tmpl := range allObjectives {
		obj := tmpl

		// MANUAL objectives (EvidenceFile is empty)
		if obj.EvidenceFile == "" {
			obj.Status = StatusManual
			rep.Manual++
			rep.Objectives = append(rep.Objectives, obj)
			continue
		}

		// Check if objective applies at this CAL level
		if obj.MinCAL > 0 && rank < obj.MinCAL {
			obj.Status = StatusNA
			obj.Evidence = fmt.Sprintf("objective does not apply at %s (requires CAL-%d)", cal, obj.MinCAL)
			rep.NA++
			rep.Objectives = append(rep.Objectives, obj)
			continue
		}

		// File-based evidence check
		path := filepath.Join(projectRoot, filepath.FromSlash(obj.EvidenceFile))
		if _, err := os.Stat(path); err == nil {
			obj.Status = StatusPass
			obj.Evidence = obj.EvidenceFile + " present"
			rep.Pass++
		} else {
			obj.Status = StatusGap
			obj.Gap = obj.EvidenceFile + " not found — run 'gofusa " + commandForFile(obj.EvidenceFile) + "'"
			rep.Gap++
		}
		rep.Objectives = append(rep.Objectives, obj)
	}

	return rep, nil
}

func commandForFile(file string) string {
	m := map[string]string{
		"cyber-plan.json":       "check --output cyber-plan.json",
		"vuln.json":             "vuln",
		"tara.json":             "tara",
		".fusa-reqs.json":       "trace",
		"safety-case.json":      "safety-case",
		"check-report.json":     "check",
		"cyber-validation.json": "cyber",
		"sbom.json":             "release",
		"provenance.json":       "release",
	}
	if cmd, ok := m[file]; ok {
		return cmd
	}
	return "— check project setup"
}

// Render writes the gap report to w in the requested format ("text" or "json").
//
//fusa:req REQ-ISO21434-003
func Render(w io.Writer, rep *Report, format string) error {
	switch format {
	case "json", "":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	case "text":
		return renderText(w, rep)
	default:
		return fmt.Errorf("iso21434: unsupported format %q", format)
	}
}

func renderText(w io.Writer, rep *Report) error {
	total := rep.Pass + rep.Gap + rep.Manual + rep.NA
	fmt.Fprintf(w, "ISO 21434 Gap Report\n")
	fmt.Fprintf(w, "Project: %s   CAL: %s   Generated: %s\n\n",
		rep.Project, rep.CAL, rep.Generated.Format("2006-01-02"))
	fmt.Fprintf(w, "Summary: %d objectives  %d PASS  %d GAP  %d MANUAL  %d N/A\n\n",
		total, rep.Pass, rep.Gap, rep.Manual, rep.NA)

	for _, obj := range rep.Objectives {
		icon := statusIcon(obj.Status)
		fmt.Fprintf(w, "  %s [%s] %s  %s\n", icon, obj.ID, obj.Status, obj.Description)
		if obj.Gap != "" {
			fmt.Fprintf(w, "     GAP: %s\n", obj.Gap)
		}
		if obj.Note != "" {
			fmt.Fprintf(w, "     NOTE: %s\n", obj.Note)
		}
	}
	fmt.Fprintln(w)

	if rep.Gap > 0 {
		fmt.Fprintf(w, "Action items (%d gaps):\n", rep.Gap)
		for _, obj := range rep.Objectives {
			if obj.Status == StatusGap {
				fmt.Fprintf(w, "  gofusa %s\n", commandForFile(obj.EvidenceFile))
			}
		}
	}
	return nil
}

func statusIcon(s ObjectiveStatus) string {
	switch s {
	case StatusPass:
		return "✓"
	case StatusGap:
		return "✗"
	case StatusManual:
		return "?"
	case StatusNA:
		return "-"
	default:
		return "!"
	}
}

// ─── Engine rule ───────────────────────────────────────────────────────────────

func init() {
	engine.Default.MustRegister(&ruleISO21434TARApresent{})
}

// ISO21434001 — tara.json absent.
type ruleISO21434TARApresent struct{}

func (r *ruleISO21434TARApresent) ID() string { return "ISO21434001" }
func (r *ruleISO21434TARApresent) Description() string {
	return "tara.json absent — ISO 21434 §9 requires a documented Threat Analysis and Risk Assessment."
}

//fusa:req REQ-ISO21434-001
func (r *ruleISO21434TARApresent) Run(_ context.Context, projectRoot string, cfg *config.Config) ([]fusa.Finding, error) {
	if cfg == nil || !strings.EqualFold(string(cfg.Project.Standard), "ISO21434") {
		return nil, nil
	}
	if _, err := os.Stat(filepath.Join(projectRoot, "tara.json")); err == nil {
		return nil, nil
	}
	return []fusa.Finding{{
		RuleID:      r.ID(),
		Severity:    fusa.SeverityInfo,
		Message:     "tara.json not found",
		Location:    fusa.Location{File: "tara.json"},
		Remediation: "run 'gofusa tara'",
	}}, nil
}
