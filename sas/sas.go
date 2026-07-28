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
	"time"

	fusa "github.com/SoundMatt/go-FuSa"
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

// ChecklistItem is the x-FuSa spec §9.3 `sas.json` canonical checklist row.
//
//fusa:req REQ-SAS004
type ChecklistItem struct {
	Item     string `json:"item"`
	Clause   string `json:"clause,omitempty"`
	Present  bool   `json:"present"`
	Evidence string `json:"evidence,omitempty"`
}

// ChecklistSummary is the x-FuSa spec §9.3 `sas.json` summary block.
//
//fusa:req REQ-SAS005
type ChecklistSummary struct {
	Total   int `json:"total"`
	Present int `json:"present"`
}

// SAS is the Software Accomplishment Summary.
//
//fusa:req REQ-SAS002
type SAS struct {
	// §3.1 common header.
	SchemaVersion string    `json:"schemaVersion"`
	Kind          string    `json:"kind"`
	Tool          string    `json:"tool"`
	ToolVersion   string    `json:"toolVersion"`
	Language      string    `json:"language"`
	GeneratedAt   time.Time `json:"generatedAt"`

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

	// Checklist/Summary are the x-FuSa spec §9.3 canonical fields, derived
	// from the same Evidence scan above.
	Checklist []ChecklistItem  `json:"checklist"`
	Summary   ChecklistSummary `json:"summary"`

	// Attestation is the optional §1.6.2 independent-review assertion.
	// SAS's only free-text field subject to §1.6.1 rule A is Deviations
	// (user-authored); the fixed evidenceItems catalog below is not
	// per-project-derived content, so rule B does not apply to it.
	Attestation *fusa.Attestation `json:"attestation,omitempty"`
}

// evidenceItems is the ordered list of evidence the SAS checks for. clause
// is the DO-178C §11 data-item number this row corresponds to, where one
// exists (best-effort mapping — several go-FuSa evidence files, e.g. the
// SBOM, have no single canonical §11 item number and are left unmapped).
var evidenceItems = []struct {
	title  string
	file   string
	desc   string
	clause string
}{
	{"Software Development Plan", "SAFETY_PLAN.md", "Documents the planned software lifecycle and development process.", "11.2"},
	{"Software Verification Plan", "SVP.md", "Describes verification activities, methods, and environments.", "11.3"},
	{"Software Configuration Management Plan", "SCMP.md", "Defines configuration identification, control, and status accounting.", "11.4"},
	{"Software Quality Assurance Plan", "SQAP.md", "Documents quality assurance activities and authority.", "11.5"},
	{"Requirements Manifest", ".fusa-reqs.json", "Machine-readable record of all software requirements.", "11.9"},
	{"Traceability Matrix", ".fusa-reqs.json", "Requirements traceable to source code and test annotations.", "11.9"},
	{"Test Evidence Bundle", ".fusa-evidence.json", "Test execution records and pass/fail results.", "11.14"},
	{"SBOM (SPDX 3.0.1)", "sbom.json", "Software Bill of Materials identifying all components and dependencies.", ""},
	{"Build Provenance", "provenance.json", "Cryptographic build provenance and reproducibility evidence.", ""},
	{"Tool Qualification Report", "qualify-report.json", "Self-qualification evidence per DO-330.", "12"},
	{"Safety Analysis (FMEA)", "fmea.json", "Failure Mode and Effects Analysis from exported functions.", ""},
	{"Threat Analysis (TARA)", "tara.json", "Threat Analysis and Risk Assessment per ISO 21434 §9.", ""},
	{"Vulnerability Report", "vuln.json", "Dependency vulnerability scan results (OSV database).", ""},
	{"Component Boundary Diagram", "boundary.mermaid", "Package-level component boundary diagram.", "11.10"},
	{"Safety Case", "safety-case.json", "Structured safety case with GSN argument and evidence mapping.", ""},
	{"Coverage Report", "coverage-report.json", "DO-178C structural coverage analysis (statement/decision/MC/DC).", "11.14"},
	{"Software Configuration Index", "sci.json", "Formal inventory of all lifecycle data items with checksums.", "11.16"},
	{"DO-178C Gap Report", "do178-gap-report.json", "Per-objective DO-178C compliance gap assessment.", ""},
	{"Problem Reports", ".fusa-problems.json", "Problem reporting log per DO-178C §11.17.", "11.17"},
	{"Audit Pack", "audit-pack.zip", "Complete evidence bundle for auditor review.", ""},
}

// Build assembles a SAS from evidence in projectRoot.
//
//fusa:req REQ-SAS001
func Build(projectRoot, project, version, dal, prepared string) (*SAS, error) {
	now := time.Now().UTC()
	sas := &SAS{
		SchemaVersion: fusa.SchemaVersion(),
		Kind:          "sas",
		Tool:          "go-FuSa",
		ToolVersion:   fusa.Version,
		Language:      "go",
		GeneratedAt:   now,
		Project:       project,
		Version:       version,
		DAL:           dal,
		Standard:      "DO-178C / RTCA",
		Generated:     now,
		Prepared:      prepared,
	}

	var gaps []string
	for _, item := range evidenceItems {
		ev := EvidenceSummary{
			Title:   item.title,
			File:    item.file,
			Summary: item.desc,
		}
		ci := ChecklistItem{Item: item.title, Clause: item.clause, Evidence: item.file}
		if fusa.ResolveDoc(projectRoot, item.file) != "" {
			ev.Present = true
			ci.Present = true
		} else {
			gaps = append(gaps, fmt.Sprintf("%s (%s) — not found", item.title, item.file))
		}
		sas.Evidence = append(sas.Evidence, ev)
		sas.Checklist = append(sas.Checklist, ci)
	}

	sas.Summary.Total = len(sas.Checklist)
	for _, ci := range sas.Checklist {
		if ci.Present {
			sas.Summary.Present++
		}
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
	fmt.Fprintf(w, "---\n_Generated by go-FuSa v%s — DO-178C §11.20_\n", fusa.Version)
	return nil
}

// LoadReport reads a persisted SAS from path (typically sas.json).
//
//fusa:req REQ-SAS006
func LoadReport(path string) (*SAS, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s SAS
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("%w: %s: %s", fusa.ErrInvalidConfig, path, err)
	}
	return &s, nil
}
