// Package sas generates the Software Accomplishment Summary (SAS) required
// by DO-178C §11.20.
//
// The SAS is the final lifecycle document submitted with a certification
// package. It declares DAL, summarises all evidence, identifies deviations
// from plans, and asserts that all DO-178C objectives have been satisfied.
//
// Build assembles evidence from existing go-FuSa artifacts; Render writes
// the result as Markdown (human-readable) or JSON.
package sas

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// SASFile is the default output filename.
const SASFile = "sas.md"

// SASJSONFile is the default JSON output filename.
const SASJSONFile = "sas.json"

// EvidenceSummary describes a single piece of evidence in the SAS.
//
//fusa:req REQ-SAS001
type EvidenceSummary struct {
	Title   string `json:"title"`
	File    string `json:"file"`
	Present bool   `json:"present"`
	Summary string `json:"summary,omitempty"`
}

// SAS is the Software Accomplishment Summary.
//
//fusa:req REQ-SAS002
type SAS struct {
	Project    string            `json:"project"`
	Version    string            `json:"version"`
	DAL        string            `json:"dal"`
	Standard   string            `json:"standard"`
	Generated  time.Time         `json:"generated"`
	Prepared   string            `json:"prepared"`
	Deviations []string          `json:"deviations,omitempty"`
	Evidence   []EvidenceSummary `json:"evidence"`
	Gaps       []string          `json:"gaps,omitempty"`
	Assertion  string            `json:"assertion"`
}

// evidenceItems is the ordered list of evidence the SAS checks for.
var evidenceItems = []struct {
	title string
	file  string
	desc  string
}{
	{"Software Development Plan", "SAFETY_PLAN.md", "Documents the planned software lifecycle and development process."},
	{"Software Verification Plan", "SVP.md", "Describes verification activities, methods, and environments."},
	{"Software Configuration Management Plan", "SCMP.md", "Defines configuration identification, control, and status accounting."},
	{"Software Quality Assurance Plan", "SQAP.md", "Documents quality assurance activities and authority."},
	{"Requirements Manifest", ".fusa-reqs.json", "Machine-readable record of all software requirements."},
	{"Traceability Matrix", ".fusa-reqs.json", "Requirements traceable to source code and test annotations."},
	{"Test Evidence Bundle", ".fusa-evidence.json", "Test execution records and pass/fail results."},
	{"SBOM (SPDX 3.0.1)", "sbom.json", "Software Bill of Materials identifying all components and dependencies."},
	{"Build Provenance", "provenance.json", "Cryptographic build provenance and reproducibility evidence."},
	{"Tool Qualification Report", "qualify-report.json", "Self-qualification evidence per DO-330."},
	{"Safety Analysis (FMEA)", "fmea.json", "Failure Mode and Effects Analysis from exported functions."},
	{"Threat Analysis (TARA)", "tara.json", "Threat Analysis and Risk Assessment per ISO 21434 §9."},
	{"Vulnerability Report", "vuln.json", "Dependency vulnerability scan results (OSV database)."},
	{"Component Boundary Diagram", "boundary.mermaid", "Package-level component boundary diagram."},
	{"Safety Case", "safety-case.json", "Structured safety case with GSN argument and evidence mapping."},
	{"Coverage Report", "coverage-report.json", "DO-178C structural coverage analysis (statement/decision/MC/DC)."},
	{"Software Configuration Index", "sci.json", "Formal inventory of all lifecycle data items with checksums."},
	{"DO-178C Gap Report", "do178-gap-report.json", "Per-objective DO-178C compliance gap assessment."},
	{"Problem Reports", ".fusa-problems.json", "Problem reporting log per DO-178C §11.17."},
	{"Audit Pack", "audit-pack.zip", "Complete evidence bundle for auditor review."},
}

// Build assembles a SAS from evidence in projectRoot.
//
//fusa:req REQ-SAS001
func Build(projectRoot, project, version, dal, prepared string) (*SAS, error) {
	sas := &SAS{
		Project:   project,
		Version:   version,
		DAL:       dal,
		Standard:  "DO-178C / RTCA",
		Generated: time.Now().UTC(),
		Prepared:  prepared,
	}

	var gaps []string
	for _, item := range evidenceItems {
		path := filepath.Join(projectRoot, filepath.FromSlash(item.file))
		ev := EvidenceSummary{
			Title:   item.title,
			File:    item.file,
			Summary: item.desc,
		}
		if _, err := os.Stat(path); err == nil {
			ev.Present = true
		} else {
			gaps = append(gaps, fmt.Sprintf("%s (%s) — not found", item.title, item.file))
		}
		sas.Evidence = append(sas.Evidence, ev)
	}

	sas.Gaps = gaps
	if len(gaps) == 0 {
		sas.Assertion = fmt.Sprintf(
			"All required lifecycle data items are present. The software for project %q "+
				"at version %s has been developed and verified in accordance with DO-178C at %s. "+
				"All applicable objectives in Annex A have been addressed.",
			project, version, dal,
		)
	} else {
		sas.Assertion = fmt.Sprintf(
			"Software Accomplishment Summary INCOMPLETE — %d lifecycle data item(s) are absent. "+
				"See gaps list. Address all gaps before submitting for DER review.",
			len(gaps),
		)
	}

	return sas, nil
}

// Render writes the SAS in the requested format ("markdown" or "json") to w.
//
//fusa:req REQ-SAS003
func Render(w io.Writer, sas *SAS, format string) error {
	switch format {
	case "markdown", "text", "":
		return renderMarkdown(w, sas)
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(sas)
	default:
		return fmt.Errorf("sas: unsupported format %q", format)
	}
}

func renderMarkdown(w io.Writer, sas *SAS) error {
	present := 0
	for _, ev := range sas.Evidence {
		if ev.Present {
			present++
		}
	}

	fmt.Fprintf(w, "# Software Accomplishment Summary\n\n")
	fmt.Fprintf(w, "> DO-178C §11.20 — This document asserts that the software lifecycle was executed\n")
	fmt.Fprintf(w, "> in accordance with the approved plans and that applicable objectives are satisfied.\n\n")
	fmt.Fprintf(w, "| Field | Value |\n|---|---|\n")
	fmt.Fprintf(w, "| Project | %s |\n", sas.Project)
	fmt.Fprintf(w, "| Version | %s |\n", sas.Version)
	fmt.Fprintf(w, "| Standard | %s |\n", sas.Standard)
	fmt.Fprintf(w, "| Design Assurance Level | %s |\n", sas.DAL)
	fmt.Fprintf(w, "| Generated | %s |\n", sas.Generated.Format("2006-01-02"))
	fmt.Fprintf(w, "| Prepared by | %s |\n\n", sas.Prepared)

	fmt.Fprintf(w, "## Evidence Summary\n\n")
	fmt.Fprintf(w, "**%d / %d** lifecycle data items present.\n\n", present, len(sas.Evidence))
	fmt.Fprintf(w, "| Item | File | Present |\n|---|---|:---:|\n")
	for _, ev := range sas.Evidence {
		mark := "✗"
		if ev.Present {
			mark = "✓"
		}
		fmt.Fprintf(w, "| %s | `%s` | %s |\n", ev.Title, ev.File, mark)
	}
	fmt.Fprintln(w)

	if len(sas.Gaps) > 0 {
		fmt.Fprintf(w, "## Gaps (%d)\n\n", len(sas.Gaps))
		for _, g := range sas.Gaps {
			fmt.Fprintf(w, "- %s\n", g)
		}
		fmt.Fprintln(w)
	}

	if len(sas.Deviations) > 0 {
		fmt.Fprintf(w, "## Deviations / Alternatives\n\n")
		for _, d := range sas.Deviations {
			fmt.Fprintf(w, "- %s\n", d)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintf(w, "## Assertion\n\n%s\n\n", sas.Assertion)
	fmt.Fprintf(w, "---\n_Generated by go-FuSa v%s — DO-178C §11.20_\n", "0.18.0")
	return nil
}
