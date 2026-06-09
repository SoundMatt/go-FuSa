// Package iec61508 produces an IEC 61508 Parts 1-3 compliance gap report.
//
// It maps evidence produced by the go-FuSa pipeline to key objectives from
// IEC 61508 and reports PASS, GAP, MANUAL, or N/A for each. The result can be
// read by a safety assessor as a starting point for IEC 61508 compliance.
//
// Usage:
//
//	report, err := iec61508.Assess(projectRoot, "myproject", iec61508.SIL2)
//	_ = iec61508.Render(os.Stdout, report, "text")
package iec61508

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/config"
	"github.com/SoundMatt/go-FuSa/engine"
)

// ReportFile is the default output filename.
const ReportFile = "iec61508-gap-report.json"

// SIL represents a Safety Integrity Level.
//
//fusa:req REQ-IEC61508-001
type SIL string

const (
	SIL1 SIL = "SIL-1"
	SIL2 SIL = "SIL-2"
	SIL3 SIL = "SIL-3"
	SIL4 SIL = "SIL-4"
)

// ObjectiveStatus is the assessment result for a single objective.
type ObjectiveStatus string

const (
	StatusPass   ObjectiveStatus = "PASS"
	StatusFail   ObjectiveStatus = "FAIL"
	StatusGap    ObjectiveStatus = "GAP"
	StatusManual ObjectiveStatus = "MANUAL"
	StatusNA     ObjectiveStatus = "N/A"
)

// Objective is a single IEC 61508 compliance objective.
//
//fusa:req REQ-IEC61508-002
type Objective struct {
	ID          string          `json:"id"`
	Part        string          `json:"part"`
	Clause      string          `json:"clause"`
	Description string          `json:"description"`
	SILsApply   []SIL           `json:"silsApply"`
	Status      ObjectiveStatus `json:"status"`
	Evidence    string          `json:"evidence,omitempty"`
	Gap         string          `json:"gap,omitempty"`
}

// Report is the complete IEC 61508 gap assessment.
//
//fusa:req REQ-IEC61508-003
type Report struct {
	Project    string      `json:"project"`
	SIL        SIL         `json:"sil"`
	Generated  time.Time   `json:"generated"`
	Pass       int         `json:"pass"`
	Fail       int         `json:"fail"`
	Gap        int         `json:"gap"`
	Manual     int         `json:"manual"`
	NA         int         `json:"na"`
	Objectives []Objective `json:"objectives"`
}

var allObjectives = []struct {
	id     string
	part   string
	clause string
	desc   string
	sils   []SIL
	file   string // evidence file; empty = manual
}{
	// Part 1 — General requirements (management)
	{
		"1.1", "Part 1", "§6.2",
		"Functional Safety Management Plan exists (SAFETY_PLAN.md)",
		[]SIL{SIL1, SIL2, SIL3, SIL4},
		"SAFETY_PLAN.md",
	},
	{
		"1.2", "Part 1", "§6.3",
		"Safety lifecycle defined and documented (.fusa.json)",
		[]SIL{SIL1, SIL2, SIL3, SIL4},
		".fusa.json",
	},
	{
		"1.3", "Part 1", "§7.4",
		"Risk assessment and SIL determination documented (.fusa-hara.json)",
		[]SIL{SIL1, SIL2, SIL3, SIL4},
		".fusa-hara.json",
	},
	// Part 2 — Requirements for electrical / electronic / programmable electronic safety-related systems
	{
		"2.1", "Part 2", "§7.2",
		"Safety Requirements Specification (.fusa-reqs.json)",
		[]SIL{SIL1, SIL2, SIL3, SIL4},
		".fusa-reqs.json",
	},
	{
		"2.2", "Part 2", "§7.3",
		"Software Safety Requirements Specification (subset of .fusa-reqs.json)",
		[]SIL{SIL1, SIL2, SIL3, SIL4},
		".fusa-reqs.json",
	},
	{
		"2.3", "Part 2", "§7.4",
		"Architecture description (boundary.mermaid)",
		[]SIL{SIL1, SIL2, SIL3, SIL4},
		"boundary.mermaid",
	},
	{
		"2.4", "Part 2", "§7.5",
		"Detailed design documentation",
		[]SIL{SIL3, SIL4},
		"", // MANUAL for SIL-3/4
	},
	// Part 3 — Software requirements
	{
		"3.1", "Part 3", "§7.3",
		"Module testing evidence (.fusa-evidence.json)",
		[]SIL{SIL1, SIL2, SIL3, SIL4},
		".fusa-evidence.json",
	},
	{
		"3.2", "Part 3", "§7.4",
		"Integration testing evidence (.fusa-evidence.json)",
		[]SIL{SIL1, SIL2, SIL3, SIL4},
		".fusa-evidence.json",
	},
	{
		"3.3", "Part 3", "§7.4.8",
		"Statement coverage (coverage-report.json)",
		[]SIL{SIL2, SIL3, SIL4},
		"coverage-report.json",
	},
	{
		"3.4", "Part 3", "§7.4.9",
		"Branch/decision coverage (coverage-report.json)",
		[]SIL{SIL3, SIL4},
		"coverage-report.json",
	},
	{
		"3.5", "Part 3", "§7.4.10",
		"MC/DC coverage",
		[]SIL{SIL4},
		"", // MANUAL
	},
	// Part 4 — Definitions and abbreviations (FMEA/HAZOP)
	{
		"4.1", "Part 4", "§B.1",
		"FMEA/FMECA analysis (fmea.json)",
		[]SIL{SIL2, SIL3, SIL4},
		"fmea.json",
	},
	{
		"4.2", "Part 4", "§B.2",
		"HAZOP or equivalent analysis (fmea.json satisfies for SIL-3; SIL-4 requires independent HAZOP)",
		[]SIL{SIL3, SIL4},
		"fmea.json",
	},
	// Part 5 — Configuration management
	{
		"5.1", "Part 5", "§6.2",
		"Configuration management (sbom.json)",
		[]SIL{SIL1, SIL2, SIL3, SIL4},
		"sbom.json",
	},
	{
		"5.2", "Part 5", "§6.3",
		"Problem reporting (.fusa-problems.json)",
		[]SIL{SIL1, SIL2, SIL3, SIL4},
		".fusa-problems.json",
	},
	{
		"5.3", "Part 5", "§6.4",
		"Software change management (provenance.json)",
		[]SIL{SIL1, SIL2, SIL3, SIL4},
		"provenance.json",
	},
	{
		"5.4", "Part 5", "§7.7",
		"Software Configuration Index (sci.json)",
		[]SIL{SIL2, SIL3, SIL4},
		"sci.json",
	},
	// Part 6 — Verification
	{
		"6.1", "Part 6", "§7.2",
		"Software verification plan (SVP.md)",
		[]SIL{SIL2, SIL3, SIL4},
		"SVP.md",
	},
	{
		"6.2", "Part 6", "§7.3",
		"Verification of requirements (.fusa-evidence.json)",
		[]SIL{SIL1, SIL2, SIL3, SIL4},
		".fusa-evidence.json",
	},
	{
		"6.3", "Part 6", "§7.4",
		"Static analysis (check-report.json)",
		[]SIL{SIL1, SIL2, SIL3, SIL4},
		"check-report.json",
	},
	{
		"6.4", "Part 6", "§7.6",
		"Tool qualification (qualify-report.json)",
		[]SIL{SIL3, SIL4},
		"qualify-report.json",
	},
	// Part 7 — Functional Safety Assessment
	{
		"7.1", "Part 7", "§8.2",
		"Functional Safety Assessment",
		[]SIL{SIL3, SIL4},
		"", // MANUAL
	},
	{
		"7.2", "Part 7", "§8.3",
		"Safety case documentation (safety-case.json)",
		[]SIL{SIL3, SIL4},
		"safety-case.json",
	},
	// Part 8 — Cybersecurity and vulnerability
	{
		"8.1", "Part 8", "§8.1",
		"Cybersecurity considerations (cyber-report.json)",
		[]SIL{SIL1, SIL2, SIL3, SIL4},
		"cyber-report.json",
	},
	{
		"8.2", "Part 8", "§8.2",
		"Vulnerability assessment (vuln.json)",
		[]SIL{SIL1, SIL2, SIL3, SIL4},
		"vuln.json",
	},
}

// Assess scans projectRoot and returns an IEC 61508 gap report for the given SIL.
//
//fusa:req REQ-IEC61508-001
func Assess(projectRoot, project string, sil SIL) (*Report, error) {
	rep := &Report{
		Project:   project,
		SIL:       sil,
		Generated: time.Now().UTC(),
	}

	for _, o := range allObjectives {
		obj := Objective{
			ID:          o.id,
			Part:        o.part,
			Clause:      o.clause,
			Description: o.desc,
			SILsApply:   o.sils,
		}

		if !silApplies(sil, o.sils) {
			obj.Status = StatusNA
			obj.Evidence = "objective does not apply at " + string(sil)
			rep.NA++
			rep.Objectives = append(rep.Objectives, obj)
			continue
		}

		// Manually assessed objectives
		if o.file == "" {
			obj.Status = StatusManual
			obj.Gap = "requires human review — go-FuSa cannot automatically assess this objective"
			rep.Manual++
			rep.Objectives = append(rep.Objectives, obj)
			continue
		}

		// File-based evidence check
		path := filepath.Join(projectRoot, filepath.FromSlash(o.file))
		if _, err := os.Stat(path); err == nil {
			obj.Status = StatusPass
			obj.Evidence = o.file + " present"
			rep.Pass++
		} else {
			obj.Status = StatusGap
			obj.Gap = o.file + " not found — run 'gofusa " + commandForFile(o.file) + "'"
			rep.Gap++
		}
		rep.Objectives = append(rep.Objectives, obj)
	}

	return rep, nil
}

func silApplies(sil SIL, sils []SIL) bool {
	for _, s := range sils {
		if s == sil {
			return true
		}
	}
	return false
}

func commandForFile(file string) string {
	m := map[string]string{
		".fusa-reqs.json":      "trace",
		".fusa-evidence.json":  "verify",
		".fusa.json":           "init",
		"sbom.json":            "release",
		"provenance.json":      "release",
		"fmea.json":            "fmea",
		"boundary.mermaid":     "boundary",
		"qualify-report.json":  "qualify",
		"safety-case.json":     "safety-case",
		"SAFETY_PLAN.md":       "template --type safety-plan",
		"SVP.md":               "template --type svp",
		"cyber-report.json":    "cyber",
		".fusa-problems.json":  "pr init",
		".fusa-hara.json":      "hara init",
		"vuln.json":            "vuln",
		"check-report.json":    "check",
		"coverage-report.json": "coverage",
		"sci.json":             "sci",
	}
	if cmd, ok := m[file]; ok {
		return cmd
	}
	return "— check project setup"
}

// Render writes the gap report to w in the requested format ("text" or "json").
//
//fusa:req REQ-IEC61508-003
func Render(w io.Writer, rep *Report, format string) error {
	switch format {
	case "json", "":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	case "text":
		return renderText(w, rep)
	default:
		return fmt.Errorf("iec61508: unsupported format %q", format)
	}
}

func renderText(w io.Writer, rep *Report) error {
	total := rep.Pass + rep.Fail + rep.Gap + rep.Manual + rep.NA
	fmt.Fprintf(w, "IEC 61508 Gap Report\n")
	fmt.Fprintf(w, "Project: %s   SIL: %s   Generated: %s\n\n",
		rep.Project, rep.SIL, rep.Generated.Format("2006-01-02"))
	fmt.Fprintf(w, "Summary: %d objectives  %d PASS  %d GAP  %d MANUAL  %d N/A  %d FAIL\n\n",
		total, rep.Pass, rep.Gap, rep.Manual, rep.NA, rep.Fail)

	for _, part := range []string{"Part 1", "Part 2", "Part 3", "Part 4", "Part 5", "Part 6", "Part 7", "Part 8"} {
		printed := false
		for _, obj := range rep.Objectives {
			if obj.Part != part {
				continue
			}
			if !printed {
				fmt.Fprintf(w, "%s\n", part)
				printed = true
			}
			icon := statusIcon(obj.Status)
			fmt.Fprintf(w, "  %s [%s] %s  %s\n", icon, obj.ID, obj.Status, obj.Description)
			if obj.Gap != "" {
				fmt.Fprintf(w, "     GAP: %s\n", obj.Gap)
			}
		}
		if printed {
			fmt.Fprintln(w)
		}
	}

	if rep.Gap > 0 {
		fmt.Fprintf(w, "Action items (%d gaps):\n", rep.Gap)
		for _, obj := range rep.Objectives {
			if obj.Status == StatusGap {
				fmt.Fprintf(w, "  gofusa %s\n", commandForFile(evidenceFile(obj)))
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

func evidenceFile(obj Objective) string {
	for _, o := range allObjectives {
		if o.id == obj.ID {
			return o.file
		}
	}
	return ""
}

// ─── Engine rule ───────────────────────────────────────────────────────────────

func init() {
	engine.Default.MustRegister(&ruleIEC61508ReportPresent{})
}

// IEC61508001 — iec61508-gap-report.json should be present.
type ruleIEC61508ReportPresent struct{}

func (r *ruleIEC61508ReportPresent) ID() string { return "IEC61508001" }
func (r *ruleIEC61508ReportPresent) Description() string {
	return "IEC 61508 gap report should be generated and committed to the repository."
}

//fusa:req REQ-IEC61508-004
func (r *ruleIEC61508ReportPresent) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	path := filepath.Join(projectRoot, ReportFile)
	if _, err := os.Stat(path); err == nil {
		return nil, nil
	}
	return []fusa.Finding{{
		RuleID:      r.ID(),
		Severity:    fusa.SeverityInfo,
		Message:     ReportFile + " not found — IEC 61508 gap assessment not yet run",
		Location:    fusa.Location{File: ReportFile},
		Remediation: "run 'gofusa iec61508' to generate the gap report",
	}}, nil
}
