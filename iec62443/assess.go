// Package iec62443 — gap report extension.
//
// This file adds Assess/Render/SL so that 'gofusa iec62443' can emit a
// §9.3-canonical IEC 62443-4-2 gap report alongside the engine rules that
// already run via 'gofusa check'.
package iec62443

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/SoundMatt/go-FuSa/gapreport"
)

// SL is an IEC 62443 Security Level (IEC 62443-2-1 §4.3).
//
//fusa:req REQ-IEC62443-ASSESS001
type SL string

const (
	SL1 SL = "SL-1"
	SL2 SL = "SL-2"
	SL3 SL = "SL-3"
	SL4 SL = "SL-4"
)

// ReportFile is the default output filename for gofusa iec62443.
const ReportFile = "iec62443-gap-report.json"

// ProvenanceFile matches the filename produced by gofusa release.
const ProvenanceFile = "provenance.json"

type objectiveSpec struct {
	id      string
	cr      string // Component Requirement clause
	title   string
	minSL   SL
	files   []string // evidence files (any present = PASS); empty = manual
	command string   // remediation command hint
}

var slObjectives = []objectiveSpec{
	// ── SL-1: foundational ───────────────────────────────────────────────────
	{
		"IEC62443-CR-1.1", "CR 1.1",
		"Security Level declared (.fusa-iec62443.json with target_sl)",
		SL1,
		[]string{ConfigFile},
		"init (create .fusa-iec62443.json with target_sl, component_type)",
	},
	{
		"IEC62443-CR-2.1", "CR 2.1",
		"Check report present (authorization enforcement evidence)",
		SL1,
		[]string{"check-report.json"},
		"check --output check-report.json",
	},
	{
		"IEC62443-CR-3.4", "CR 3.4",
		"Software integrity tracked (sbom.json present)",
		SL1,
		[]string{"sbom.json"},
		"release",
	},
	{
		"IEC62443-CR-4.3", "CR 4.3",
		"Cryptographic integrity recorded (provenance.json present)",
		SL1,
		[]string{"provenance.json"},
		"release",
	},
	{
		"IEC62443-CR-6.1", "CR 6.1",
		"Audit log accessible (check-report.json present)",
		SL1,
		[]string{"check-report.json"},
		"check --output check-report.json",
	},
	{
		"IEC62443-CR-6.2", "CR 6.2",
		"Vulnerability management policy (SECURITY.md present)",
		SL1,
		[]string{"SECURITY.md", "SECURITY_POLICY.md", "security-policy.md", "docs/SECURITY.md"},
		"— create SECURITY.md documenting the vulnerability disclosure policy",
	},
	// ── SL-2: structured ─────────────────────────────────────────────────────
	{
		"IEC62443-CR-1.4", "CR 1.4",
		"Software update documentation (provenance.json with builder field)",
		SL2,
		nil, // assessed separately via JSON parse
		"release (run from CI so the builder field is populated)",
	},
	{
		"IEC62443-CR-3.1", "CR 3.1",
		"Security hardening evidence (cyber-report.json present)",
		SL2,
		[]string{"cyber-report.json"},
		"cyber --output cyber-report.json",
	},
	{
		"IEC62443-CR-6.2.1", "CR 6.2.1",
		"Cyber incident response plan present",
		SL2,
		[]string{
			"INCIDENT-RESPONSE.md", "incident-response.md",
			"docs/incident-response.md", "docs/INCIDENT-RESPONSE.md",
		},
		"— create INCIDENT-RESPONSE.md or set incident_resp_doc in .fusa-iec62443.json",
	},
	{
		"IEC62443-CR-7.3", "CR 7.3",
		"Safety case documented (safety-case.json present)",
		SL2,
		[]string{"safety-case.json"},
		"safety-case",
	},
	// ── SL-3: sophisticated ───────────────────────────────────────────────────
	{
		"IEC62443-CR-7.6", "CR 7.6",
		"Network segmentation documented (boundary.mermaid present)",
		SL3,
		[]string{"boundary.mermaid"},
		"boundary",
	},
	{
		"IEC62443-CR-2.6", "CR 2.6",
		"Full evidence bundle produced (audit-pack.zip present)",
		SL3,
		[]string{"audit-pack.zip"},
		"audit-pack",
	},
}

// Objective is one assessed IEC 62443 objective.
type Objective struct {
	ID     string `json:"id"`
	CR     string `json:"cr"`
	Title  string `json:"title"`
	MinSL  SL     `json:"minSL"`
	Status string `json:"status"` // PASS / GAP / N/A
	Note   string `json:"note,omitempty"`
}

// Report is the IEC 62443 gap assessment result.
//
//fusa:req REQ-IEC62443-ASSESS002
type Report struct {
	Project    string      `json:"project"`
	SL         SL          `json:"sl"`
	Generated  time.Time   `json:"generated"`
	Pass       int         `json:"pass"`
	Gap        int         `json:"gap"`
	NA         int         `json:"na"`
	Objectives []Objective `json:"objectives"`
}

func slNum(sl SL) int {
	switch sl {
	case SL1:
		return 1
	case SL2:
		return 2
	case SL3:
		return 3
	case SL4:
		return 4
	}
	return 0
}

// Assess scans projectRoot and returns an IEC 62443 gap report for the given SL.
//
//fusa:req REQ-IEC62443-ASSESS003
func Assess(projectRoot, project string, level SL) (*Report, error) {
	rep := &Report{
		Project:   project,
		SL:        level,
		Generated: time.Now().UTC(),
	}

	iecCfg, _ := LoadConfig(projectRoot)
	targetNum := slNum(level)

	for _, spec := range slObjectives {
		obj := Objective{
			ID:    spec.id,
			CR:    spec.cr,
			Title: spec.title,
			MinSL: spec.minSL,
		}

		if slNum(spec.minSL) > targetNum {
			obj.Status = "N/A"
			rep.NA++
			rep.Objectives = append(rep.Objectives, obj)
			continue
		}

		status, note := assessSpec(projectRoot, spec, iecCfg)
		obj.Status = status
		obj.Note = note
		if status == "PASS" {
			rep.Pass++
		} else {
			rep.Gap++
		}
		rep.Objectives = append(rep.Objectives, obj)
	}

	return rep, nil
}

func assessSpec(root string, spec objectiveSpec, cfg *ProjectConfig) (status, note string) {
	// CR-6.2.1: also accept the configured incident_resp_doc path.
	if spec.id == "IEC62443-CR-6.2.1" && cfg != nil && cfg.IncidentRespDoc != "" {
		if _, err := os.Stat(filepath.Join(root, cfg.IncidentRespDoc)); err == nil {
			return "PASS", ""
		}
	}

	// CR-1.4: provenance must exist AND have a builder field.
	if spec.id == "IEC62443-CR-1.4" {
		ok, msg := provenanceHasBuilder(root)
		if ok {
			return "PASS", ""
		}
		return "GAP", msg
	}

	for _, name := range spec.files {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(name))); err == nil {
			return "PASS", ""
		}
	}
	primary := ""
	if len(spec.files) > 0 {
		primary = spec.files[0]
	}
	return "GAP", fmt.Sprintf("%s not found — run 'gofusa %s'", primary, spec.command)
}

func provenanceHasBuilder(root string) (bool, string) {
	data, err := os.ReadFile(filepath.Join(root, ProvenanceFile))
	if err != nil {
		return false, "provenance.json not found — run 'gofusa release'"
	}
	var prov map[string]interface{}
	if err := json.Unmarshal(data, &prov); err != nil {
		return false, "provenance.json is not valid JSON"
	}
	if v, _ := prov["builder"].(string); v != "" {
		return true, ""
	}
	return false, "provenance.json missing builder field — run 'gofusa release' from CI"
}

// Render writes the IEC 62443 gap report to w.
//
//fusa:req REQ-IEC62443-ASSESS004
func Render(w io.Writer, rep *Report, format string) error {
	switch format {
	case "json", "":
		return gapreport.Render(w, toGapReport(rep), "json")
	case "text":
		return renderText(w, rep)
	default:
		return fmt.Errorf("iec62443: unsupported format %q", format)
	}
}

func toGapReport(rep *Report) *gapreport.Report {
	gr := gapreport.New(rep.Project, "iec62443")
	for _, obj := range rep.Objectives {
		gobj := gapreport.Objective{
			ID:     obj.ID,
			Clause: obj.CR,
			Title:  obj.Title,
			Status: toCanonical(obj.Status),
		}
		if obj.Note != "" {
			gobj.Findings = []string{obj.Note}
		}
		gr.AddObjective(gobj)
	}
	return gr
}

func toCanonical(s string) string {
	switch s {
	case "PASS":
		return gapreport.StatusSatisfied
	case "N/A":
		return gapreport.StatusPartial
	default:
		return gapreport.StatusGap
	}
}

func renderText(w io.Writer, rep *Report) error {
	total := rep.Pass + rep.Gap + rep.NA
	fmt.Fprintf(w, "IEC 62443 Gap Report\n")
	fmt.Fprintf(w, "Project: %s   SL: %s   Generated: %s\n\n",
		rep.Project, rep.SL, rep.Generated.Format("2006-01-02"))
	fmt.Fprintf(w, "Summary: %d objectives  %d PASS  %d GAP  %d N/A\n\n",
		total, rep.Pass, rep.Gap, rep.NA)

	for _, obj := range rep.Objectives {
		icon := statusIcon(obj.Status)
		suffix := ""
		if obj.Status == "N/A" {
			suffix = " (above target SL)"
		}
		fmt.Fprintf(w, "  %s [%s] %s  %s%s\n", icon, obj.ID, obj.Status, obj.Title, suffix)
		if obj.Note != "" {
			fmt.Fprintf(w, "     NOTE: %s\n", obj.Note)
		}
	}
	fmt.Fprintln(w)

	if rep.Gap > 0 {
		fmt.Fprintf(w, "Action items (%d gaps):\n", rep.Gap)
		for _, obj := range rep.Objectives {
			if obj.Status == "GAP" {
				fmt.Fprintf(w, "  %s (%s) — %s\n", obj.ID, obj.CR, obj.Note)
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
	case "N/A":
		return "–"
	default:
		return "!"
	}
}
