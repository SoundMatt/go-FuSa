// Package do178 produces a DO-178C compliance gap report.
//
// It maps evidence produced by the go-FuSa pipeline to the key objectives in
// DO-178C Annex A (Tables A-1 through A-10) and reports PASS, FAIL, GAP, NA,
// or MANUAL for each. The result can be read by a DER as a starting point for
// compliance assessment.
//
// Usage:
//
//	report, err := do178.Assess(projectRoot, dal)
//	_ = do178.Render(os.Stdout, report, "text")
package do178

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/SoundMatt/go-FuSa/trace"
)

// ReportFile is the default output filename.
const ReportFile = "do178-gap-report.json"

// DAL represents a Design Assurance Level.
type DAL string

const (
	DALA DAL = "DAL-A"
	DALB DAL = "DAL-B"
	DALC DAL = "DAL-C"
	DALD DAL = "DAL-D"
	DALE DAL = "DAL-E"
)

// ObjectiveStatus is the assessment result for a single objective.
type ObjectiveStatus string

const (
	StatusPass   ObjectiveStatus = "PASS"
	StatusFail   ObjectiveStatus = "FAIL"
	StatusGap    ObjectiveStatus = "GAP"
	StatusNA     ObjectiveStatus = "N/A"
	StatusManual ObjectiveStatus = "MANUAL"
)

// Objective is a single DO-178C compliance objective.
//
//fusa:req REQ-DO178-001
type Objective struct {
	ID          string          `json:"id"`
	Table       string          `json:"table"`
	Section     string          `json:"section"`
	Description string          `json:"description"`
	DALsApply   []DAL           `json:"dalsApply"`
	Status      ObjectiveStatus `json:"status"`
	Evidence    string          `json:"evidence,omitempty"`
	Gap         string          `json:"gap,omitempty"`
}

// Report is the complete DO-178C gap assessment.
//
//fusa:req REQ-DO178-002
type Report struct {
	Project    string      `json:"project"`
	DAL        DAL         `json:"dal"`
	Generated  time.Time   `json:"generated"`
	Pass       int         `json:"pass"`
	Fail       int         `json:"fail"`
	Gap        int         `json:"gap"`
	Manual     int         `json:"manual"`
	NA         int         `json:"na"`
	Objectives []Objective `json:"objectives"`
}

// allObjectives defines the key DO-178C Annex A objectives that go-FuSa can assess.
var allObjectives = []struct {
	id      string
	table   string
	section string
	desc    string
	dals    []DAL
	file    string // evidence file (empty = manual)
	check   func(projectRoot string) (ObjectiveStatus, string, string)
}{
	// Table A-1: Software Planning Process
	{
		"A-1.1", "A-1", "§4 / §11.1",
		"Software Development Plan (SDP) exists and describes software lifecycle",
		[]DAL{DALA, DALB, DALC, DALD},
		"SAFETY_PLAN.md", nil,
	},
	{
		"A-1.2", "A-1", "§4 / §11.3",
		"Software Verification Plan (SVP) describes verification activities",
		[]DAL{DALA, DALB, DALC, DALD},
		"SVP.md", nil,
	},
	{
		"A-1.3", "A-1", "§4 / §11.4",
		"Software Configuration Management Plan (SCMP) exists",
		[]DAL{DALA, DALB, DALC, DALD},
		"SCMP.md", nil,
	},
	{
		"A-1.4", "A-1", "§4 / §11.5",
		"Software Quality Assurance Plan (SQAP) exists",
		[]DAL{DALA, DALB, DALC, DALD},
		"SQAP.md", nil,
	},
	{
		"A-1.5", "A-1", "§4.4",
		"Tool qualification plan addresses tools that could introduce errors",
		[]DAL{DALA, DALB, DALC},
		"qualify-report.json", nil,
	},
	// Table A-2: Software Development Process
	{
		"A-2.1", "A-2", "§5.1",
		"High-level requirements are developed and documented",
		[]DAL{DALA, DALB, DALC, DALD},
		".fusa-reqs.json", nil,
	},
	{
		"A-2.2", "A-2", "§5.2",
		"Low-level requirements derived from HLR (Level=LLR in .fusa-reqs.json)",
		[]DAL{DALA, DALB},
		".fusa-reqs.json", checkLLRItems,
	},
	{
		"A-2.3", "A-2", "§5.3",
		"Software architecture is documented (component boundary diagram)",
		[]DAL{DALA, DALB, DALC, DALD},
		"boundary.mermaid", nil,
	},
	{
		"A-2.4", "A-2", "§5.4",
		"Source code implements requirements and conforms to standards",
		[]DAL{DALA, DALB, DALC, DALD},
		"", nil, // assessed via check results
	},
	{
		"A-2.5", "A-2", "§5.5",
		"Integration output (executable) produced from reviewed source",
		[]DAL{DALA, DALB, DALC, DALD},
		"provenance.json", nil,
	},
	// Table A-3: Verification of Software Planning Outputs
	{
		"A-3.1", "A-3", "§6.1",
		"Software plans reviewed for completeness and consistency",
		[]DAL{DALA, DALB, DALC, DALD},
		"", nil,
	},
	// Table A-4: Verification of Software HLR
	{
		"A-4.1", "A-4", "§6.3.1",
		"HLR conform to system requirements",
		[]DAL{DALA, DALB, DALC, DALD},
		"", nil,
	},
	{
		"A-4.2", "A-4", "§6.3.2",
		"HLR are accurate, consistent, verifiable, and unambiguous",
		[]DAL{DALA, DALB, DALC, DALD},
		".fusa-reqs.json", nil,
	},
	{
		"A-4.3", "A-4", "§6.3.3",
		"HLR are compatible with target computer (timing, memory)",
		[]DAL{DALA, DALB, DALC},
		"", nil,
	},
	// Table A-5: Verification of Software LLR (DAL-A/B only)
	{
		"A-5.1", "A-5", "§6.4.1",
		"LLR conform to HLR, are accurate, consistent, verifiable",
		[]DAL{DALA, DALB},
		"", nil,
	},
	{
		"A-5.2", "A-5", "§6.4.2",
		"Verification of LLR is independent (different person than developer at DAL-A/B)",
		[]DAL{DALA, DALB},
		"", nil,
	},
	// Table A-6: Verification of SW Architecture
	{
		"A-6.1", "A-6", "§6.4.3",
		"Software architecture is consistent with HLR",
		[]DAL{DALA, DALB, DALC, DALD},
		"boundary.mermaid", nil,
	},
	{
		"A-6.2", "A-6", "§6.4.4.2",
		"No dead code exists in the software (check-report.json from gofusa check)",
		[]DAL{DALA, DALB},
		"check-report.json", nil,
	},
	{
		"A-6.3", "A-6", "§6.4.4.3",
		"Data coupling and control coupling are characterised (coupling-report.json)",
		[]DAL{DALA, DALB, DALC},
		"coupling-report.json", nil,
	},
	// Table A-7: Verification of Source Code
	{
		"A-7.1", "A-7", "§6.4.4.1",
		"Source code conforms to software standards (lint, analysis)",
		[]DAL{DALA, DALB, DALC, DALD},
		"", nil, // assessed via gofusa check
	},
	{
		"A-7.2", "A-7", "§6.4.4.2",
		"Source code is traceable to LLR",
		[]DAL{DALA, DALB, DALC, DALD},
		".fusa-reqs.json", nil,
	},
	{
		"A-7.3", "A-7", "§6.4.4.3",
		"Statement coverage achieved by tests",
		[]DAL{DALA, DALB, DALC},
		"coverage-report.json", nil,
	},
	{
		"A-7.4", "A-7", "§6.4.4.3",
		"Decision coverage achieved by tests (DAL-A/B)",
		[]DAL{DALA, DALB},
		"coverage-report.json", nil,
	},
	{
		"A-7.5", "A-7", "§6.4.4.3",
		"MC/DC coverage achieved by tests (DAL-A only; use decision coverage from coverage-report.json as partial evidence)",
		[]DAL{DALA},
		"", nil, // manual — Go toolchain does not report MC/DC; decision coverage (A-7.4) is the strongest automated substitute
	},
	// Table A-8: Testing of Integration Process
	{
		"A-8.1", "A-8", "§6.6",
		"Test cases exist for all HLR",
		[]DAL{DALA, DALB, DALC, DALD},
		".fusa-evidence.json", nil,
	},
	{
		"A-8.2", "A-8", "§6.6",
		"Test procedures exist and are derived from test cases",
		[]DAL{DALA, DALB, DALC, DALD},
		".fusa-evidence.json", nil,
	},
	{
		"A-8.3", "A-8", "§6.6",
		"Test results reviewed and pass/fail criteria established",
		[]DAL{DALA, DALB, DALC, DALD},
		".fusa-evidence.json", nil,
	},
	// Table A-9: Verification of Tests
	{
		"A-9.1", "A-9", "§6.7",
		"Test environment is verified and controlled",
		[]DAL{DALA, DALB, DALC},
		"provenance.json", nil,
	},
	{
		"A-9.2", "A-9", "§6.7",
		"Regression testing is performed after changes",
		[]DAL{DALA, DALB, DALC, DALD},
		".github/workflows/ci.yml", nil,
	},
	// Table A-10: Software Configuration Management
	{
		"A-10.1", "A-10", "§7 / §11.15",
		"SBOM produced and configuration items identified",
		[]DAL{DALA, DALB, DALC, DALD},
		"sbom.json", nil,
	},
	{
		"A-10.2", "A-10", "§7 / §11.16",
		"Software Configuration Index (SCI) produced",
		[]DAL{DALA, DALB, DALC, DALD},
		"sci.json", nil,
	},
	{
		"A-10.3", "A-10", "§7 / §11.17",
		"Problem reports exist and are tracked to closure",
		[]DAL{DALA, DALB, DALC, DALD},
		".fusa-problems.json", nil,
	},
	{
		"A-10.4", "A-10", "§7.2",
		"Build reproducibility and provenance documented",
		[]DAL{DALA, DALB, DALC},
		"provenance.json", nil,
	},
	// DO-178C §11 Lifecycle Data
	{
		"A-11.1", "A-11", "§11.20",
		"Software Accomplishment Summary (SAS) produced",
		[]DAL{DALA, DALB, DALC, DALD},
		"sas.md", nil,
	},
	{
		"A-11.2", "A-11", "§11.14",
		"Test evidence bundle present",
		[]DAL{DALA, DALB, DALC, DALD},
		".fusa-evidence.json", nil,
	},
	{
		"A-11.3", "A-11", "§11.9",
		"Safety analysis (FMEA) performed",
		[]DAL{DALA, DALB, DALC},
		"fmea.json", nil,
	},
	{
		"A-11.4", "A-11", "§12 / DO-330",
		"Tool qualification report present",
		[]DAL{DALA, DALB, DALC},
		"qualify-report.json", nil,
	},
	{
		"A-11.5", "A-11", "§11.10",
		"Vulnerability assessment performed",
		[]DAL{DALA, DALB, DALC},
		"vuln.json", nil,
	},
}

// Assess scans projectRoot and returns a DO-178C gap report for the given DAL.
//
//fusa:req REQ-DO178-001
func Assess(projectRoot, project string, dal DAL) (*Report, error) {
	rep := &Report{
		Project:   project,
		DAL:       dal,
		Generated: time.Now().UTC(),
	}

	for _, o := range allObjectives {
		obj := Objective{
			ID:          o.id,
			Table:       o.table,
			Section:     o.section,
			Description: o.desc,
			DALsApply:   o.dals,
		}

		if !dalApplies(dal, o.dals) {
			obj.Status = StatusNA
			obj.Evidence = "objective does not apply at " + string(dal)
			rep.NA++
			rep.Objectives = append(rep.Objectives, obj)
			continue
		}

		// Custom check function takes precedence over file check.
		if o.check != nil {
			status, evidence, gap := o.check(projectRoot)
			obj.Status = status
			obj.Evidence = evidence
			obj.Gap = gap
			switch status {
			case StatusPass:
				rep.Pass++
			case StatusGap:
				rep.Gap++
			default:
				rep.Manual++
			}
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

	// Additional dynamic checks
	checkSourceCode(projectRoot, rep)

	return rep, nil
}

func dalApplies(dal DAL, dals []DAL) bool {
	for _, d := range dals {
		if d == dal {
			return true
		}
	}
	return false
}

// checkSourceCode adds dynamic assessments based on what go-FuSa can inspect.
func checkSourceCode(projectRoot string, rep *Report) {
	// Check if .fusa.json config exists (indicates project is configured)
	configPath := filepath.Join(projectRoot, ".fusa.json")
	for i, obj := range rep.Objectives {
		if obj.ID == "A-2.4" {
			if _, err := os.Stat(configPath); err == nil {
				rep.Objectives[i].Status = StatusManual
				rep.Objectives[i].Evidence = ".fusa.json found — run 'gofusa check' to assess coding standards conformance"
				rep.Objectives[i].Gap = "review 'gofusa check' output for zero ERROR findings"
				// Fix the counter
				rep.Gap--
				rep.Manual++
			}
			break
		}
	}
	// Check A-3.1 (plans reviewed) — all 4 plan files present?
	for i, obj := range rep.Objectives {
		if obj.ID == "A-3.1" {
			plans := []string{"SAFETY_PLAN.md", "SVP.md", "SCMP.md", "SQAP.md"}
			present := 0
			for _, p := range plans {
				if _, err := os.Stat(filepath.Join(projectRoot, p)); err == nil {
					present++
				}
			}
			if present == 4 {
				rep.Objectives[i].Status = StatusManual
				rep.Objectives[i].Evidence = "all 4 plan documents present — manual review required"
				if obj.Status == StatusGap {
					rep.Gap--
				}
				rep.Manual++
			}
			break
		}
	}
}

// checkLLRItems returns PASS if .fusa-reqs.json contains at least one
// requirement with Level == "LLR", GAP otherwise (DO-178C §5.2).
func checkLLRItems(projectRoot string) (ObjectiveStatus, string, string) {
	reqs, err := trace.LoadRequirements(projectRoot)
	if err != nil {
		return StatusGap, "", ".fusa-reqs.json not found — run 'gofusa trace' to create requirements file"
	}
	for _, r := range reqs {
		if strings.EqualFold(r.Level, "LLR") {
			return StatusPass, ".fusa-reqs.json contains LLR-tagged requirements", ""
		}
	}
	if len(reqs) == 0 {
		return StatusGap, "", "no requirements in .fusa-reqs.json — run 'gofusa trace' to populate"
	}
	return StatusGap, "", `no requirements tagged with level "LLR" in .fusa-reqs.json — add "level":"LLR" to low-level requirements`
}

func commandForFile(file string) string {
	m := map[string]string{
		".fusa-reqs.json":          "trace",
		".fusa-evidence.json":      "verify",
		"sbom.json":                "release",
		"provenance.json":          "release",
		"fmea.json":                "fmea",
		"boundary.mermaid":         "boundary",
		"qualify-report.json":      "qualify",
		"vuln.json":                "vuln",
		"sas.md":                   "sas",
		"sci.json":                 "sci",
		".fusa-problems.json":      "pr init",
		"coverage-report.json":     "coverage",
		"coupling-report.json":     "coupling",
		"check-report.json":        "check --format json",
		"SAFETY_PLAN.md":           "template --type sdp",
		"SVP.md":                   "template --type svp",
		"SCMP.md":                  "template --type scmp",
		"SQAP.md":                  "template --type sqap",
		".github/workflows/ci.yml": "— add CI workflow",
		".github/CODEOWNERS":       "hooks install",
	}
	if cmd, ok := m[file]; ok {
		return cmd
	}
	return "— check project setup"
}

// Render writes the gap report to w in the requested format ("text" or "json").
//
//fusa:req REQ-DO178-003
func Render(w io.Writer, rep *Report, format string) error {
	switch format {
	case "json", "":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	case "text":
		return renderText(w, rep)
	default:
		return fmt.Errorf("do178: unsupported format %q", format)
	}
}

func renderText(w io.Writer, rep *Report) error {
	total := rep.Pass + rep.Fail + rep.Gap + rep.Manual + rep.NA
	fmt.Fprintf(w, "DO-178C Gap Report\n")
	fmt.Fprintf(w, "Project: %s   DAL: %s   Generated: %s\n\n",
		rep.Project, rep.DAL, rep.Generated.Format("2006-01-02"))
	fmt.Fprintf(w, "Summary: %d objectives  %d PASS  %d GAP  %d MANUAL  %d N/A  %d FAIL\n\n",
		total, rep.Pass, rep.Gap, rep.Manual, rep.NA, rep.Fail)

	for _, table := range []string{"A-1", "A-2", "A-3", "A-4", "A-5", "A-6", "A-7", "A-8", "A-9", "A-10", "A-11"} {
		printed := false
		for _, obj := range rep.Objectives {
			if obj.Table != table {
				continue
			}
			if !printed {
				fmt.Fprintf(w, "Table %s\n", table)
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
				cmd := commandForFile(evidenceFile(obj))
				if cmd != "" && !strings.HasPrefix(cmd, "—") {
					fmt.Fprintf(w, "  gofusa %s\n", cmd)
				}
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
