// Package iso26262 produces an ISO 26262 Part 6/7/8/9/10/11 compliance gap report.
//
// It maps evidence produced by the go-FuSa pipeline to the key objectives in
// ISO 26262 Part 6 (software development) and related parts, and reports PASS,
// GAP, MANUAL, or N/A for each. The result can be read by a safety assessor as
// a starting point for ISO 26262 compliance.
//
// Usage:
//
//	report, err := iso26262.Assess(projectRoot, "myproject", iso26262.ASILB)
//	_ = iso26262.Render(os.Stdout, report, "text")
package iso26262

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
	"github.com/SoundMatt/go-FuSa/gapreport"
	"github.com/SoundMatt/go-FuSa/trace"
)

// ReportFile is the default output filename.
const ReportFile = "iso26262-gap-report.json"

// ASIL represents an Automotive Safety Integrity Level.
//
//fusa:req REQ-ISO26262-001
type ASIL string

const (
	ASILA ASIL = "ASIL-A"
	ASILB ASIL = "ASIL-B"
	ASILC ASIL = "ASIL-C"
	ASILD ASIL = "ASIL-D"
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

// Objective is a single ISO 26262 compliance objective.
//
//fusa:req REQ-ISO26262-002
type Objective struct {
	ID          string          `json:"id"`
	Part        string          `json:"part"`
	Clause      string          `json:"clause"`
	Description string          `json:"description"`
	ASILsApply  []ASIL          `json:"asilsApply"`
	Status      ObjectiveStatus `json:"status"`
	Evidence    string          `json:"evidence,omitempty"`
	Gap         string          `json:"gap,omitempty"`
}

// Report is the complete ISO 26262 gap assessment.
//
//fusa:req REQ-ISO26262-003
type Report struct {
	Project    string      `json:"project"`
	ASIL       ASIL        `json:"asil"`
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
	asils  []ASIL
	file   string // evidence file; empty = manual
}{
	// Part 6 — Software development
	{
		"6.1", "Part 6", "§6.4.3",
		"Software safety requirements specification exists (.fusa-reqs.json)",
		[]ASIL{ASILA, ASILB, ASILC, ASILD},
		".fusa-reqs.json",
	},
	{
		"6.2", "Part 6", "§6.4.5",
		"Software architectural design documented (boundary.mermaid)",
		[]ASIL{ASILA, ASILB, ASILC, ASILD},
		"boundary.mermaid",
	},
	{
		"6.3", "Part 6", "§6.4.7",
		"Software unit design and implementation (source code with annotations)",
		[]ASIL{ASILA, ASILB, ASILC, ASILD},
		".fusa.json",
	},
	{
		"6.4", "Part 6", "§6.4.9",
		"Software unit verification (test evidence + coverage) (.fusa-evidence.json)",
		[]ASIL{ASILA, ASILB, ASILC, ASILD},
		".fusa-evidence.json",
	},
	{
		"6.5", "Part 6", "§6.4.11",
		"Software integration and integration testing (provenance.json)",
		[]ASIL{ASILA, ASILB, ASILC, ASILD},
		"provenance.json",
	},
	{
		"6.6", "Part 6", "§6.4.12",
		"Verification of software safety requirements (.fusa-evidence.json + .fusa-reqs.json)",
		[]ASIL{ASILA, ASILB, ASILC, ASILD},
		".fusa-evidence.json",
	},
	{
		"6.7", "Part 6", "§6.5",
		"Software safety case (safety-case.json)",
		[]ASIL{ASILC, ASILD},
		"safety-case.json",
	},
	// Part 7 — Production and operation (system-level safety)
	{
		"7.1", "Part 7", "§7.3",
		"ASIL decomposition documented in .fusa.json",
		[]ASIL{ASILA, ASILB, ASILC, ASILD},
		".fusa.json",
	},
	{
		"7.2", "Part 7", "§7.4",
		"Safety goal documentation (.fusa-reqs.json with ASIL annotations)",
		[]ASIL{ASILA, ASILB, ASILC, ASILD},
		".fusa-reqs.json",
	},
	{
		"7.3", "Part 7", "§7.4.2",
		"Hazard and Risk Analysis (HARA) structured data (.fusa-hara.json)",
		[]ASIL{ASILA, ASILB, ASILC, ASILD},
		".fusa-hara.json",
	},
	{
		"7.4", "Part 7", "§7.5",
		"Functional safety concept (SAFETY_PLAN.md)",
		[]ASIL{ASILA, ASILB, ASILC, ASILD},
		"SAFETY_PLAN.md",
	},
	// Part 8 — Supporting processes
	{
		"8.1", "Part 8", "§8.4.4",
		"Hardware-software interface specification (boundary.mermaid)",
		[]ASIL{ASILC, ASILD},
		"boundary.mermaid",
	},
	// Part 9 — ASIL-oriented and safety-oriented analyses
	{
		"9.1", "Part 9", "§9.4",
		"FMEA analysis performed (fmea.json)",
		[]ASIL{ASILB, ASILC, ASILD},
		"fmea.json",
	},
	{
		"9.2", "Part 9", "§9.5",
		"Hazard-to-FMEA linkage (fmea.json + .fusa-reqs.json)",
		[]ASIL{ASILC, ASILD},
		"fmea.json",
	},
	// Part 10 — Guideline on ISO 26262 / Configuration management
	{
		"10.1", "Part 10", "§10.4.2",
		"Software configuration management (sbom.json)",
		[]ASIL{ASILA, ASILB, ASILC, ASILD},
		"sbom.json",
	},
	{
		"10.2", "Part 10", "§10.4.3",
		"Problem reports tracked (.fusa-problems.json)",
		[]ASIL{ASILA, ASILB, ASILC, ASILD},
		".fusa-problems.json",
	},
	{
		"10.3", "Part 10", "§10.4.5",
		"Software qualification evidence (qualify-report.json)",
		[]ASIL{ASILC, ASILD},
		"qualify-report.json",
	},
	// Part 10 continued — Software Configuration Index
	{
		"10.4", "Part 10", "§10.4.4",
		"Software Configuration Index (sci.json)",
		[]ASIL{ASILB, ASILC, ASILD},
		"sci.json",
	},
	// Part 11 — Guidelines on application of ISO 26262
	{
		"11.1", "Part 11", "§11.3",
		"Confirmation review evidence",
		[]ASIL{ASILC, ASILD},
		"", // MANUAL
	},
	{
		"11.2", "Part 11", "§11.4",
		"Cybersecurity integration (cyber-report.json)",
		[]ASIL{ASILA, ASILB, ASILC, ASILD},
		"cyber-report.json",
	},
	{
		"11.3", "Part 11", "§11.5",
		"Coupling characterisation evidence (coupling-report.json)",
		[]ASIL{ASILC, ASILD},
		"coupling-report.json",
	},
}

// Assess scans projectRoot and returns an ISO 26262 gap report for the given ASIL.
//
//fusa:req REQ-ISO26262-001
func Assess(projectRoot, project string, asil ASIL) (*Report, error) {
	rep := &Report{
		Project:   project,
		ASIL:      asil,
		Generated: time.Now().UTC(),
	}

	for _, o := range allObjectives {
		obj := Objective{
			ID:          o.id,
			Part:        o.part,
			Clause:      o.clause,
			Description: o.desc,
			ASILsApply:  o.asils,
		}

		if !asilApplies(asil, o.asils) {
			obj.Status = StatusNA
			obj.Evidence = "objective does not apply at " + string(asil)
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

func asilApplies(asil ASIL, asils []ASIL) bool {
	for _, a := range asils {
		if a == asil {
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
		"HARA.md":              "template --type hara",
		".fusa-hara.json":      "hara init",
		"cyber-report.json":    "cyber",
		".fusa-problems.json":  "pr init",
		"sci.json":             "sci",
		"coupling-report.json": "coupling",
	}
	if cmd, ok := m[file]; ok {
		return cmd
	}
	return "— check project setup"
}

// Render writes the gap report to w in the requested format ("text" or "json").
//
//fusa:req REQ-ISO26262-003
func Render(w io.Writer, rep *Report, format string) error {
	switch format {
	case "json", "":
		return gapreport.Render(w, toGapReport(rep), "json")
	case "text":
		return renderText(w, rep)
	default:
		return fmt.Errorf("iso26262: unsupported format %q", format)
	}
}

// toGapReport converts the internal Report to the canonical §9.3 gap-report shape.
func toGapReport(rep *Report) *gapreport.Report {
	gr := gapreport.New(rep.Project, "ISO 26262 "+string(rep.ASIL))
	for _, obj := range rep.Objectives {
		if obj.Status == StatusNA {
			continue
		}
		gobj := gapreport.Objective{
			ID:     obj.ID,
			Title:  obj.Description,
			Clause: obj.Clause,
			Status: mapToCanonical(obj.Status),
		}
		if obj.Evidence != "" {
			gobj.Evidence = []string{obj.Evidence}
		}
		if obj.Gap != "" {
			gobj.Findings = []string{obj.Gap}
		}
		gr.AddObjective(gobj)
	}
	return gr
}

func mapToCanonical(s ObjectiveStatus) string {
	switch s {
	case StatusPass:
		return gapreport.StatusSatisfied
	case StatusManual:
		return gapreport.StatusPartial
	default:
		return gapreport.StatusGap
	}
}

func renderText(w io.Writer, rep *Report) error {
	total := rep.Pass + rep.Fail + rep.Gap + rep.Manual + rep.NA
	fmt.Fprintf(w, "ISO 26262 Gap Report\n")
	fmt.Fprintf(w, "Project: %s   ASIL: %s   Generated: %s\n\n",
		rep.Project, rep.ASIL, rep.Generated.Format("2006-01-02"))
	fmt.Fprintf(w, "Summary: %d objectives  %d PASS  %d GAP  %d MANUAL  %d N/A  %d FAIL\n\n",
		total, rep.Pass, rep.Gap, rep.Manual, rep.NA, rep.Fail)

	for _, part := range []string{"Part 6", "Part 7", "Part 8", "Part 9", "Part 10", "Part 11"} {
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
	engine.Default.MustRegister(&ruleISO26262ReportPresent{})
	engine.Default.MustRegister(&ruleISO26262ASILReqs{})
	engine.Default.MustRegister(&ruleISO26262QualDepth{})
}

// ISO26262001 — iso26262-gap-report.json should be present.
type ruleISO26262ReportPresent struct{}

func (r *ruleISO26262ReportPresent) ID() string { return "ISO26262001" }
func (r *ruleISO26262ReportPresent) Description() string {
	return "ISO 26262 gap report should be generated and committed to the repository."
}

//fusa:req REQ-ISO26262-004
func (r *ruleISO26262ReportPresent) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	path := filepath.Join(projectRoot, ReportFile)
	if _, err := os.Stat(path); err == nil {
		return nil, nil
	}
	return []fusa.Finding{{
		RuleID:      r.ID(),
		Severity:    fusa.SeverityInfo,
		Message:     ReportFile + " not found — ISO 26262 gap assessment not yet run",
		Location:    fusa.Location{File: ReportFile},
		Remediation: "run 'gofusa iso26262' to generate the gap report",
	}}, nil
}

// ISO26262002 — requirements in .fusa-reqs.json lack ASIL annotations.
// ISO 26262-6 §6.4.2 requires that software safety requirements carry ASIL
// designations derived from the safety goal ASIL.
type ruleISO26262ASILReqs struct{}

func (r *ruleISO26262ASILReqs) ID() string { return "ISO26262002" }
func (r *ruleISO26262ASILReqs) Description() string {
	return "Requirements in .fusa-reqs.json lack ASIL annotations — ISO 26262-6 §6.4.2 requires ASIL on safety requirements."
}

//fusa:req REQ-ISO26262-005
func (r *ruleISO26262ASILReqs) Run(_ context.Context, projectRoot string, cfg *config.Config) ([]fusa.Finding, error) {
	if cfg == nil || !strings.EqualFold(string(cfg.Project.Standard), "ISO26262") {
		return nil, nil
	}
	reqs, err := trace.LoadRequirements(projectRoot)
	if err != nil {
		return nil, nil // TRACE001 covers missing file
	}
	if len(reqs) == 0 {
		return nil, nil
	}
	var untagged int
	for _, r := range reqs {
		if r.ASIL == "" {
			untagged++
		}
	}
	if untagged == 0 {
		return nil, nil
	}
	return []fusa.Finding{{
		RuleID:   r.ID(),
		Severity: fusa.SeverityInfo,
		Message: fmt.Sprintf(
			"%d of %d requirements in .fusa-reqs.json have no ASIL annotation",
			untagged, len(reqs),
		),
		Location:    fusa.Location{File: trace.ReqsFile},
		Remediation: `add "asil": "ASIL-B" (or appropriate level) to each requirement in .fusa-reqs.json`,
	}}, nil
}

// ISO26262003 — tool qualification report has failures.
// ISO 26262-8 §11 requires that tool qualification evidence demonstrates the
// tool is fit for purpose. A non-zero fail count undermines this evidence.
type ruleISO26262QualDepth struct{}

func (r *ruleISO26262QualDepth) ID() string { return "ISO26262003" }
func (r *ruleISO26262QualDepth) Description() string {
	return "Tool qualification report (qualify-report.json) has failed test cases — evidence is incomplete."
}

//fusa:req REQ-ISO26262-006
func (r *ruleISO26262QualDepth) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	path := filepath.Join(projectRoot, "qualify-report.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil // ISO26262001 / objective 10.3 cover absence
	}
	var rep struct {
		Fail int `json:"fail"`
		Pass int `json:"pass"`
	}
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, nil
	}
	if rep.Fail == 0 {
		return nil, nil // no failures — qualification evidence is clean
	}
	return []fusa.Finding{{
		RuleID:      r.ID(),
		Severity:    fusa.SeverityWarning,
		Message:     fmt.Sprintf("qualify-report.json has %d failed test case(s) — tool qualification evidence is incomplete", rep.Fail),
		Location:    fusa.Location{File: "qualify-report.json"},
		Remediation: "run 'gofusa qualify' to regenerate tool qualification evidence",
	}}, nil
}
