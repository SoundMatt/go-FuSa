// Package unece produces a UN Regulation No. 155 (UN R.155) cybersecurity
// compliance gap report aligned with ISO 21434.
//
// It maps evidence produced by the go-FuSa pipeline to the UN R.155 Annex 5
// threat categories and reports PASS, GAP, or MANUAL for each.
//
// Usage:
//
//	report, err := unece.Assess(projectRoot)
//	_ = unece.Render(os.Stdout, report, "text")
package unece

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
const ReportFile = "unece-gap-report.json"

// ThreatCategory maps a UN R.155 Annex 5 threat category to evidence.
type ThreatCategory struct {
	ID           string   `json:"id"`
	Description  string   `json:"description"`
	ISO21434     []string `json:"iso21434Clauses"`
	EvidenceFile string   `json:"evidenceFile,omitempty"`
	Status       string   `json:"status"` // PASS / GAP / MANUAL
	Note         string   `json:"note,omitempty"`
}

// Report is the UN R.155 compliance gap assessment.
type Report struct {
	Project    string           `json:"project"`
	Generated  time.Time        `json:"generated"`
	Pass       int              `json:"pass"`
	Gap        int              `json:"gap"`
	Manual     int              `json:"manual"`
	Categories []ThreatCategory `json:"categories"`
}

var allCategories = []ThreatCategory{
	// Automatable categories
	{
		ID:           "TC-1",
		Description:  "Vehicle communication security",
		ISO21434:     []string{"9.1", "9.3"},
		EvidenceFile: "tara.json",
	},
	{
		ID:           "TC-2",
		Description:  "Update mechanism security",
		ISO21434:     []string{"A.2"},
		EvidenceFile: "provenance.json",
	},
	{
		ID:           "TC-3",
		Description:  "Unintended physical access",
		ISO21434:     []string{"9.1"},
		EvidenceFile: "tara.json",
	},
	{
		ID:           "TC-4",
		Description:  "External connectivity threats",
		ISO21434:     []string{"10.4"},
		EvidenceFile: "check-report.json",
	},
	{
		ID:           "TC-5",
		Description:  "Supply chain integrity",
		ISO21434:     []string{"A.1"},
		EvidenceFile: "sbom.json",
	},
	{
		ID:           "TC-6",
		Description:  "Data storage security",
		ISO21434:     []string{"9.2"},
		EvidenceFile: "tara.json",
	},
	// MANUAL categories
	{
		ID:          "TC-7",
		Description: "Cryptographic key management",
		ISO21434:    []string{},
		Note:        "MANUAL — requires HSM/PKI policy documentation",
	},
	{
		ID:          "TC-8",
		Description: "Privacy protection",
		ISO21434:    []string{},
		Note:        "MANUAL — requires Data Protection Impact Assessment",
	},
	{
		ID:          "TC-9",
		Description: "Incident detection",
		ISO21434:    []string{},
		Note:        "MANUAL — requires SOC/monitoring procedure",
	},
}

// Assess scans projectRoot and returns a UN R.155 gap report.
//
//fusa:req REQ-UNECE-002
func Assess(projectRoot string) (*Report, error) {
	project := filepath.Base(projectRoot)
	rep := &Report{
		Project:   project,
		Generated: time.Now().UTC(),
	}

	for _, tmpl := range allCategories {
		cat := tmpl

		// MANUAL categories have no evidence file
		if cat.EvidenceFile == "" {
			cat.Status = "MANUAL"
			rep.Manual++
			rep.Categories = append(rep.Categories, cat)
			continue
		}

		path := filepath.Join(projectRoot, filepath.FromSlash(cat.EvidenceFile))
		if _, err := os.Stat(path); err == nil {
			cat.Status = "PASS"
			rep.Pass++
		} else {
			cat.Status = "GAP"
			rep.Gap++
		}
		rep.Categories = append(rep.Categories, cat)
	}

	return rep, nil
}

// Render writes the report to w in the requested format ("text" or "json").
//
//fusa:req REQ-UNECE-003
func Render(w io.Writer, rep *Report, format string) error {
	switch format {
	case "json", "":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	case "text":
		return renderText(w, rep)
	default:
		return fmt.Errorf("unece: unsupported format %q", format)
	}
}

func renderText(w io.Writer, rep *Report) error {
	total := rep.Pass + rep.Gap + rep.Manual
	fmt.Fprintf(w, "UN R.155 Gap Report\n")
	fmt.Fprintf(w, "Project: %s   Generated: %s\n\n",
		rep.Project, rep.Generated.Format("2006-01-02"))
	fmt.Fprintf(w, "Summary: %d categories  %d PASS  %d GAP  %d MANUAL\n\n",
		total, rep.Pass, rep.Gap, rep.Manual)

	for _, cat := range rep.Categories {
		icon := statusIcon(cat.Status)
		fmt.Fprintf(w, "  %s [%s] %s  %s\n", icon, cat.ID, cat.Status, cat.Description)
		if cat.Note != "" {
			fmt.Fprintf(w, "     NOTE: %s\n", cat.Note)
		}
	}
	fmt.Fprintln(w)

	if rep.Gap > 0 {
		fmt.Fprintf(w, "Action items (%d gaps):\n", rep.Gap)
		for _, cat := range rep.Categories {
			if cat.Status == "GAP" {
				fmt.Fprintf(w, "  %s — run 'gofusa %s' to produce %s\n",
					cat.ID, commandForFile(cat.EvidenceFile), cat.EvidenceFile)
			}
		}
	}
	return nil
}

func statusIcon(s string) string {
	switch s {
	case "PASS":
		return "✓"
	case "GAP":
		return "✗"
	case "MANUAL":
		return "?"
	default:
		return "!"
	}
}

func commandForFile(file string) string {
	m := map[string]string{
		"tara.json":         "tara",
		"provenance.json":   "release",
		"check-report.json": "check",
		"sbom.json":         "release",
	}
	if cmd, ok := m[file]; ok {
		return cmd
	}
	return "— check project setup"
}

// ─── Engine rule ───────────────────────────────────────────────────────────────

func init() {
	engine.Default.MustRegister(&ruleUNECETARApresent{})
}

// UNECE001 — tara.json absent for ISO 21434 / UN R.155 projects.
type ruleUNECETARApresent struct{}

func (r *ruleUNECETARApresent) ID() string { return "UNECE001" }
func (r *ruleUNECETARApresent) Description() string {
	return "tara.json absent — UN R.155 Annex 5 requires documented threat analysis (ISO 21434 §9)."
}

//fusa:req REQ-UNECE-001
func (r *ruleUNECETARApresent) Run(_ context.Context, projectRoot string, cfg *config.Config) ([]fusa.Finding, error) {
	if cfg == nil || !strings.EqualFold(string(cfg.Project.Standard), "ISO21434") {
		return nil, nil
	}
	if _, err := os.Stat(filepath.Join(projectRoot, "tara.json")); err == nil {
		return nil, nil
	}
	return []fusa.Finding{{
		RuleID:      r.ID(),
		Severity:    fusa.SeverityWarning,
		Message:     "tara.json not found — UN R.155 Annex 5 TC-1/TC-3/TC-6 evidence is missing",
		Location:    fusa.Location{File: "tara.json"},
		Remediation: "run 'gofusa tara' to generate TARA evidence",
	}}, nil
}
