// Package safetycase assembles a structured safety case from evidence produced
// by the go-FuSa pipeline (v0.11).
//
// Build reads the standard evidence files (check-report.json,
// .fusa-reqs.json, .fusa-evidence.json, sbom.json, provenance.json,
// qualify-report.json) from a project root and returns a [SafetyCase] that
// describes the argument structure, evidence status, compliance mapping, and
// any gaps.
//
// Render writes the safety case in "text" (Markdown), "json", or "mermaid"
// (GSN diagram) format to any [io.Writer].
//
// Activate the engine rule by importing this package for its side effects:
//
//	import _ "github.com/SoundMatt/go-FuSa/safetycase"
package safetycase

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

// SafeCaseFile is the default filename for the machine-readable safety case.
const SafeCaseFile = "safety-case.json"

// EvidenceStatus indicates whether an evidence item was found.
type EvidenceStatus string

const (
	StatusPresent EvidenceStatus = "present"
	StatusAbsent  EvidenceStatus = "absent"
)

// EvidenceItem is a single piece of safety evidence collected from the project.
//
//fusa:req REQ-SC001
type EvidenceItem struct {
	ID          string         `json:"id"`
	Description string         `json:"description"`
	File        string         `json:"file"`
	Status      EvidenceStatus `json:"status"`
	Detail      string         `json:"detail,omitempty"`
}

// ClauseMapping maps a standard clause to one or more evidence item IDs.
//
//fusa:req REQ-SC005
type ClauseMapping struct {
	Standard    string   `json:"standard"`
	Clause      string   `json:"clause"`
	Title       string   `json:"title"`
	EvidenceIDs []string `json:"evidenceIds"`
}

// SafetyCase is the assembled safety case for a project.
type SafetyCase struct {
	Format      string          `json:"format"`
	GeneratedAt time.Time       `json:"generatedAt"`
	Module      string          `json:"module"`
	Standard    string          `json:"standard"`
	Evidence    []EvidenceItem  `json:"evidence"`
	Mappings    []ClauseMapping `json:"clauses,omitempty"`
	//fusa:req REQ-SC002
	Gaps []string `json:"gaps"`
}

// ─── Build ────────────────────────────────────────────────────────────────────

// minimal unmarshalling structs — no external imports needed.

type minQualify struct {
	Total  int `json:"total"`
	Passed int `json:"passed"`
	Failed int `json:"failed"`
}

type minVerify struct {
	Summary struct {
		Total   int `json:"total"`
		Passed  int `json:"passed"`
		Failed  int `json:"failed"`
		Skipped int `json:"skipped"`
	} `json:"summary"`
}

type minReqs struct {
	Requirements []json.RawMessage `json:"requirements"`
}

type minCheck struct {
	Summary struct {
		Total    int `json:"total"`
		Errors   int `json:"errors"`
		Warnings int `json:"warnings"`
	} `json:"summary"`
}

// Build reads evidence files from projectRoot and assembles a SafetyCase.
// standard must be one of "iec61508", "iso26262", "iso21434", or "generic";
// if empty, "generic" is used.
//
//fusa:req REQ-SC001
func Build(projectRoot, standard string) (*SafetyCase, error) {
	if standard == "" {
		standard = "generic"
	}
	module := filepath.Base(projectRoot)
	if mod, err := readModuleName(filepath.Join(projectRoot, "go.mod")); err == nil {
		module = mod
	}

	items := []EvidenceItem{
		collectCheck(projectRoot),
		collectTrace(projectRoot),
		collectVerify(projectRoot),
		collectQualify(projectRoot),
		collectFile(projectRoot, "sbom", "SBOM (SPDX 3.0.1)", "sbom.json"),
		collectFile(projectRoot, "provenance", "Build provenance", "provenance.json"),
	}

	//fusa:req REQ-SC002
	var gaps []string
	for _, it := range items {
		if it.Status == StatusAbsent {
			gaps = append(gaps, it.ID)
		}
	}

	sc := &SafetyCase{
		Format:      "go-FuSa Safety Case v1",
		GeneratedAt: time.Now().UTC(),
		Module:      module,
		Standard:    standard,
		Evidence:    items,
		Mappings:    mappingsFor(standard),
		Gaps:        gaps,
	}
	return sc, nil
}

func collectCheck(root string) EvidenceItem {
	item := EvidenceItem{
		ID:          "check",
		Description: "Coding standard and static analysis checks",
		File:        "check-report.json",
	}
	path := filepath.Join(root, "check-report.json")
	data, err := os.ReadFile(path)
	if err != nil {
		item.Status = StatusAbsent
		item.Detail = "run 'gofusa check --output check-report.json' to generate"
		return item
	}
	var r minCheck
	if json.Unmarshal(data, &r) == nil && r.Summary.Total > 0 {
		item.Detail = fmt.Sprintf("%d findings (%d errors, %d warnings)", r.Summary.Total, r.Summary.Errors, r.Summary.Warnings)
	}
	item.Status = StatusPresent
	return item
}

func collectTrace(root string) EvidenceItem {
	item := EvidenceItem{
		ID:          "trace",
		Description: "Requirements traceability matrix",
		File:        ".fusa-reqs.json",
	}
	path := filepath.Join(root, ".fusa-reqs.json")
	data, err := os.ReadFile(path)
	if err != nil {
		item.Status = StatusAbsent
		item.Detail = "run 'gofusa trace' and add requirements to .fusa-reqs.json"
		return item
	}
	var r minReqs
	if json.Unmarshal(data, &r) == nil {
		item.Detail = fmt.Sprintf("%d requirements", len(r.Requirements))
	}
	item.Status = StatusPresent
	return item
}

func collectVerify(root string) EvidenceItem {
	item := EvidenceItem{
		ID:          "verify",
		Description: "Test evidence bundle",
		File:        ".fusa-evidence.json",
	}
	path := filepath.Join(root, ".fusa-evidence.json")
	data, err := os.ReadFile(path)
	if err != nil {
		item.Status = StatusAbsent
		item.Detail = "run 'gofusa verify' to generate"
		return item
	}
	var r minVerify
	if json.Unmarshal(data, &r) == nil && r.Summary.Total > 0 {
		item.Detail = fmt.Sprintf("%d/%d tests passed", r.Summary.Passed, r.Summary.Total)
	}
	item.Status = StatusPresent
	return item
}

func collectQualify(root string) EvidenceItem {
	item := EvidenceItem{
		ID:          "qualify",
		Description: "Tool qualification report",
		File:        "qualify-report.json",
	}
	path := filepath.Join(root, "qualify-report.json")
	data, err := os.ReadFile(path)
	if err != nil {
		item.Status = StatusAbsent
		item.Detail = "run 'gofusa qualify' to generate"
		return item
	}
	var r minQualify
	if json.Unmarshal(data, &r) == nil && r.Total > 0 {
		item.Detail = fmt.Sprintf("%d/%d cases passed", r.Passed, r.Total)
	}
	item.Status = StatusPresent
	return item
}

func collectFile(root, id, description, filename string) EvidenceItem {
	item := EvidenceItem{ID: id, Description: description, File: filename}
	_, err := os.Stat(filepath.Join(root, filename))
	if err == nil {
		item.Status = StatusPresent
		return item
	}
	item.Status = StatusAbsent
	item.Detail = fmt.Sprintf("run 'gofusa release' to generate %s", filename)
	return item
}

// ─── Compliance mappings ──────────────────────────────────────────────────────

//fusa:req REQ-SC005
func mappingsFor(standard string) []ClauseMapping {
	switch strings.ToLower(standard) {
	case "iso26262":
		return []ClauseMapping{
			// Part 4 — Product development at the system level
			{Standard: "ISO 26262-4", Clause: "§7", Title: "Technical safety requirements", EvidenceIDs: []string{"trace"}},
			{Standard: "ISO 26262-4", Clause: "§8", Title: "System design (safety mechanisms)", EvidenceIDs: []string{"check", "trace"}},
			{Standard: "ISO 26262-4", Clause: "§9", Title: "Integration and testing — system level", EvidenceIDs: []string{"verify"}},
			// Part 5 — HW (informative for SW-only projects; mark N/A if no HW component)
			{Standard: "ISO 26262-5", Clause: "§7", Title: "Hardware design (N/A for SW-only projects)", EvidenceIDs: []string{}},
			// Part 6 — Product development at the software level
			{Standard: "ISO 26262-6", Clause: "§6", Title: "Software safety requirements specification", EvidenceIDs: []string{"trace"}},
			{Standard: "ISO 26262-6", Clause: "§7", Title: "Software architectural design", EvidenceIDs: []string{"check"}},
			{Standard: "ISO 26262-6", Clause: "§8", Title: "Software unit design and implementation", EvidenceIDs: []string{"check"}},
			{Standard: "ISO 26262-6", Clause: "§9", Title: "Software unit verification", EvidenceIDs: []string{"verify"}},
			{Standard: "ISO 26262-6", Clause: "§10", Title: "Software integration and integration testing", EvidenceIDs: []string{"verify"}},
			{Standard: "ISO 26262-6", Clause: "§11", Title: "Software testing (functional safety)", EvidenceIDs: []string{"verify"}},
			{Standard: "ISO 26262-6", Clause: "§12", Title: "Dependent failure analysis / coding guidelines", EvidenceIDs: []string{"check"}},
			// Part 8 — Supporting processes
			{Standard: "ISO 26262-8", Clause: "§7", Title: "Configuration management", EvidenceIDs: []string{"sbom", "provenance"}},
			{Standard: "ISO 26262-8", Clause: "§8", Title: "Change management", EvidenceIDs: []string{"provenance"}},
			{Standard: "ISO 26262-8", Clause: "§11", Title: "Tool qualification", EvidenceIDs: []string{"qualify"}},
		}
	case "iec61508":
		return []ClauseMapping{
			{Standard: "IEC 61508", Clause: "Part 3 §7.2", Title: "Software requirements specification", EvidenceIDs: []string{"trace"}},
			{Standard: "IEC 61508", Clause: "Part 3 §7.4.3", Title: "Software architecture and design", EvidenceIDs: []string{"check"}},
			{Standard: "IEC 61508", Clause: "Part 3 §7.9–7.10", Title: "Software module and integration testing", EvidenceIDs: []string{"verify"}},
			{Standard: "IEC 61508", Clause: "Part 1 §6.2(d)", Title: "Tool qualification", EvidenceIDs: []string{"qualify"}},
			{Standard: "IEC 61508", Clause: "Part 3 §7.8", Title: "Software integration", EvidenceIDs: []string{"sbom", "provenance"}},
		}
	case "iso21434":
		return []ClauseMapping{
			{Standard: "ISO 21434", Clause: "§9.1", Title: "TARA — threat analysis", EvidenceIDs: []string{"tara"}},
			{Standard: "ISO 21434", Clause: "§9.3", Title: "TARA — threat scenarios", EvidenceIDs: []string{"tara"}},
			{Standard: "ISO 21434", Clause: "§10.1", Title: "Cybersecurity requirements", EvidenceIDs: []string{"trace"}},
			{Standard: "ISO 21434", Clause: "§10.4", Title: "Static cybersecurity analysis", EvidenceIDs: []string{"check"}},
			{Standard: "ISO 21434", Clause: "§10", Title: "Verification and validation", EvidenceIDs: []string{"verify"}},
			{Standard: "ISO 21434", Clause: "§A.1", Title: "SBOM (Annex A work product)", EvidenceIDs: []string{"sbom"}},
			{Standard: "ISO 21434", Clause: "§A.2", Title: "Build provenance (Annex A)", EvidenceIDs: []string{"provenance"}},
		}
	case "unece155":
		return []ClauseMapping{
			{Standard: "UN R.155", Clause: "TC-1", Title: "Vehicle communication security", EvidenceIDs: []string{"tara"}},
			{Standard: "UN R.155", Clause: "TC-2", Title: "Update mechanism security", EvidenceIDs: []string{"provenance"}},
			{Standard: "UN R.155", Clause: "TC-3", Title: "Unintended physical access", EvidenceIDs: []string{"tara"}},
			{Standard: "UN R.155", Clause: "TC-4", Title: "External connectivity threats", EvidenceIDs: []string{"check"}},
			{Standard: "UN R.155", Clause: "TC-5", Title: "Supply chain integrity", EvidenceIDs: []string{"sbom"}},
			{Standard: "UN R.155", Clause: "TC-6", Title: "Data storage security", EvidenceIDs: []string{"tara"}},
		}
	default: // "generic"
		return []ClauseMapping{
			{Standard: "Generic", Clause: "CS-1", Title: "Coding standard compliance", EvidenceIDs: []string{"check"}},
			{Standard: "Generic", Clause: "CS-2", Title: "Requirements traceability", EvidenceIDs: []string{"trace"}},
			{Standard: "Generic", Clause: "CS-3", Title: "Test evidence", EvidenceIDs: []string{"verify"}},
			{Standard: "Generic", Clause: "CS-4", Title: "Tool qualification", EvidenceIDs: []string{"qualify"}},
			{Standard: "Generic", Clause: "CS-5", Title: "Release inventory", EvidenceIDs: []string{"sbom", "provenance"}},
		}
	}
}

// ─── Render ───────────────────────────────────────────────────────────────────

// Render writes sc to w in the given format: "text", "json", or "mermaid".
//
//fusa:req REQ-SC003
func Render(w io.Writer, sc *SafetyCase, format string) error {
	switch format {
	case "json", "":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(sc)
	case "text":
		return renderText(w, sc)
	case "mermaid":
		return renderMermaid(w, sc)
	default:
		return fmt.Errorf("safetycase: unknown format %q", format)
	}
}

func renderText(w io.Writer, sc *SafetyCase) error {
	fmt.Fprintf(w, "# Safety Case: %s\n\n", sc.Module)
	fmt.Fprintf(w, "Generated: %s  \nStandard: %s\n\n", sc.GeneratedAt.Format(time.RFC3339), sc.Standard)

	fmt.Fprintf(w, "## Top Claim\n\n")
	fmt.Fprintf(w, "**G1:** The software `%s` is acceptably safe for use in `%s` context,\n", sc.Module, sc.Standard)
	fmt.Fprintf(w, "argued by demonstrating compliance with the safety development lifecycle.\n\n")

	fmt.Fprintf(w, "## Evidence Summary\n\n")
	fmt.Fprintf(w, "| ID | Description | Status | Detail |\n")
	fmt.Fprintf(w, "|---|---|---|---|\n")
	for i, it := range sc.Evidence {
		status := "✅ present"
		if it.Status == StatusAbsent {
			status = "⚠ absent"
		}
		snID := fmt.Sprintf("Sn%d", i+1)
		fmt.Fprintf(w, "| %s | %s | %s | %s |\n", snID, it.Description, status, it.Detail)
	}
	fmt.Fprintf(w, "\n")

	if len(sc.Mappings) > 0 {
		fmt.Fprintf(w, "## Compliance Mapping\n\n")
		fmt.Fprintf(w, "| Standard | Clause | Title | Evidence |\n")
		fmt.Fprintf(w, "|---|---|---|---|\n")
		for _, m := range sc.Mappings {
			fmt.Fprintf(w, "| %s | %s | %s | %s |\n", m.Standard, m.Clause, m.Title, strings.Join(m.EvidenceIDs, ", "))
		}
		fmt.Fprintf(w, "\n")
	}

	if len(sc.Gaps) == 0 {
		fmt.Fprintf(w, "## Gaps\n\nNone — all evidence present.\n")
	} else {
		fmt.Fprintf(w, "## Gaps\n\nThe following evidence items are absent:\n\n")
		for _, g := range sc.Gaps {
			fmt.Fprintf(w, "- `%s`\n", g)
		}
	}
	return nil
}

// renderMermaid writes a GSN flowchart in Mermaid syntax.
//
//fusa:req REQ-SC004
func renderMermaid(w io.Writer, sc *SafetyCase) error {
	fmt.Fprintf(w, "flowchart TD\n")
	fmt.Fprintf(w, "    G1[\"**G1** %s is acceptably safe\\nfor use in %s context\"]\n", escape(sc.Module), sc.Standard)
	fmt.Fprintf(w, "    S1{{\"**S1** Argued over safety lifecycle\\nprocess compliance\"}}\n")

	evIDs := make([]string, 0, len(sc.Evidence))
	for i, it := range sc.Evidence {
		snID := fmt.Sprintf("Sn%d", i+1)
		gID := fmt.Sprintf("G%d", i+2)
		tick := "✅"
		if it.Status == StatusAbsent {
			tick = "⚠"
		}
		detail := it.Detail
		if detail == "" {
			detail = it.File
		}
		fmt.Fprintf(w, "    %s[\"**%s** %s\\n%s %s\"]\n", gID, gID, it.Description, tick, escape(detail))
		fmt.Fprintf(w, "    %s([\"**%s** %s\"])\n", snID, snID, escape(it.File))
		evIDs = append(evIDs, gID)
	}

	fmt.Fprintf(w, "    G1 --> S1\n")
	for _, g := range evIDs {
		fmt.Fprintf(w, "    S1 --> %s\n", g)
	}
	for i := range sc.Evidence {
		fmt.Fprintf(w, "    G%d --> Sn%d\n", i+2, i+1)
	}

	// colour absent nodes red
	for i, it := range sc.Evidence {
		if it.Status == StatusAbsent {
			fmt.Fprintf(w, "    style G%d fill:#fee2e2,stroke:#ef4444\n", i+2)
			fmt.Fprintf(w, "    style Sn%d fill:#fee2e2,stroke:#ef4444\n", i+1)
		}
	}
	return nil
}

func escape(s string) string {
	s = strings.ReplaceAll(s, `"`, `'`)
	s = strings.ReplaceAll(s, "\n", "\\n")
	return s
}

// ─── helpers ──────────────────────────────────────────────────────────────────

func readModuleName(gomod string) (string, error) {
	data, err := os.ReadFile(gomod)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "module ")), nil
		}
	}
	return "", fmt.Errorf("no module directive in %s", gomod)
}

// ─── Engine rule ──────────────────────────────────────────────────────────────

func init() {
	engine.Default.MustRegister(&ruleSafetyCasePresent{})
}

type ruleSafetyCasePresent struct{}

func (r *ruleSafetyCasePresent) ID() string { return "SAFETYCASE001" }
func (r *ruleSafetyCasePresent) Description() string {
	return "Project should have a safety-case.json safety case document."
}

//fusa:req REQ-SAFETYCASE001
func (r *ruleSafetyCasePresent) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	_, err := os.Stat(filepath.Join(projectRoot, SafeCaseFile))
	if err == nil {
		return nil, nil
	}
	if os.IsNotExist(err) {
		return []fusa.Finding{{
			RuleID:      r.ID(),
			Severity:    fusa.SeverityInfo,
			Message:     "no safety-case.json found — safety case not yet assembled",
			Location:    fusa.Location{File: SafeCaseFile},
			Remediation: "run 'gofusa safety-case' to generate the safety case",
		}}, nil
	}
	return nil, err
}
