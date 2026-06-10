// Package gapreport_test exercises the canonical gap-report package (§9.3).
package gapreport_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/SoundMatt/go-FuSa/gapreport"
)

// ─── New ──────────────────────────────────────────────────────────────────────

//fusa:test REQ-GAPREPORT001
func TestNew_HeaderFields(t *testing.T) {
	r := gapreport.New("/some/project", "iso26262")
	if r.SchemaVersion == "" {
		t.Error("SchemaVersion must be populated")
	}
	if r.Kind != "gap-report" {
		t.Errorf("Kind = %q, want gap-report", r.Kind)
	}
	if r.Tool != "go-FuSa" {
		t.Errorf("Tool = %q, want go-FuSa", r.Tool)
	}
	if r.ToolVersion == "" {
		t.Error("ToolVersion must be populated")
	}
	if r.Language != "go" {
		t.Errorf("Language = %q, want go", r.Language)
	}
	if r.ProjectRoot != "/some/project" {
		t.Errorf("ProjectRoot = %q, want /some/project", r.ProjectRoot)
	}
	if r.Standard != "iso26262" {
		t.Errorf("Standard = %q, want iso26262", r.Standard)
	}
	if r.GeneratedAt.IsZero() {
		t.Error("GeneratedAt must be set")
	}
}

//fusa:test REQ-GAPREPORT001
func TestNew_EmptyObjectives(t *testing.T) {
	r := gapreport.New(".", "iec61508")
	if len(r.Objectives) != 0 {
		t.Errorf("expected 0 objectives, got %d", len(r.Objectives))
	}
	if r.Summary.Total != 0 {
		t.Errorf("Summary.Total = %d, want 0", r.Summary.Total)
	}
}

// ─── AddObjective / Summary ───────────────────────────────────────────────────

//fusa:test REQ-GAPREPORT001
func TestAddObjective_Satisfied(t *testing.T) {
	r := gapreport.New(".", "iso26262")
	r.AddObjective(gapreport.Objective{
		ID:     "OBJ-001",
		Title:  "Software planning",
		Status: gapreport.StatusSatisfied,
	})
	if r.Summary.Total != 1 {
		t.Errorf("Total = %d, want 1", r.Summary.Total)
	}
	if r.Summary.Satisfied != 1 {
		t.Errorf("Satisfied = %d, want 1", r.Summary.Satisfied)
	}
	if r.Summary.Partial != 0 {
		t.Errorf("Partial = %d, want 0", r.Summary.Partial)
	}
	if r.Summary.Gaps != 0 {
		t.Errorf("Gaps = %d, want 0", r.Summary.Gaps)
	}
}

//fusa:test REQ-GAPREPORT001
func TestAddObjective_Partial(t *testing.T) {
	r := gapreport.New(".", "iso26262")
	r.AddObjective(gapreport.Objective{
		ID:     "OBJ-002",
		Title:  "Partial objective",
		Status: gapreport.StatusPartial,
	})
	if r.Summary.Partial != 1 {
		t.Errorf("Partial = %d, want 1", r.Summary.Partial)
	}
	if r.Summary.Satisfied != 0 {
		t.Errorf("Satisfied = %d, want 0", r.Summary.Satisfied)
	}
	if r.Summary.Gaps != 0 {
		t.Errorf("Gaps = %d, want 0", r.Summary.Gaps)
	}
}

//fusa:test REQ-GAPREPORT001
func TestAddObjective_Gap(t *testing.T) {
	r := gapreport.New(".", "iso26262")
	r.AddObjective(gapreport.Objective{
		ID:     "OBJ-003",
		Title:  "Missing evidence",
		Status: gapreport.StatusGap,
	})
	if r.Summary.Gaps != 1 {
		t.Errorf("Gaps = %d, want 1", r.Summary.Gaps)
	}
	if r.Summary.Satisfied != 0 {
		t.Errorf("Satisfied = %d, want 0", r.Summary.Satisfied)
	}
}

//fusa:test REQ-GAPREPORT001
func TestAddObjective_UnknownStatus_CountsAsGap(t *testing.T) {
	r := gapreport.New(".", "iso26262")
	r.AddObjective(gapreport.Objective{
		ID:     "OBJ-004",
		Title:  "Unknown status",
		Status: "unknown-status",
	})
	if r.Summary.Gaps != 1 {
		t.Errorf("unknown status should count as gap; Gaps = %d", r.Summary.Gaps)
	}
}

//fusa:test REQ-GAPREPORT001
func TestAddObjective_SummaryCounts_Mixed(t *testing.T) {
	r := gapreport.New(".", "iec61508")
	r.AddObjective(gapreport.Objective{ID: "O1", Status: gapreport.StatusSatisfied})
	r.AddObjective(gapreport.Objective{ID: "O2", Status: gapreport.StatusSatisfied})
	r.AddObjective(gapreport.Objective{ID: "O3", Status: gapreport.StatusPartial})
	r.AddObjective(gapreport.Objective{ID: "O4", Status: gapreport.StatusGap})
	r.AddObjective(gapreport.Objective{ID: "O5", Status: gapreport.StatusGap})

	if r.Summary.Total != 5 {
		t.Errorf("Total = %d, want 5", r.Summary.Total)
	}
	if r.Summary.Satisfied != 2 {
		t.Errorf("Satisfied = %d, want 2", r.Summary.Satisfied)
	}
	if r.Summary.Partial != 1 {
		t.Errorf("Partial = %d, want 1", r.Summary.Partial)
	}
	if r.Summary.Gaps != 2 {
		t.Errorf("Gaps = %d, want 2", r.Summary.Gaps)
	}
}

//fusa:test REQ-GAPREPORT001
func TestAddObjective_WithEvidenceAndFindings(t *testing.T) {
	r := gapreport.New(".", "do178c")
	r.AddObjective(gapreport.Objective{
		ID:       "OBJ-005",
		Title:    "MC/DC coverage",
		Clause:   "§6.4.4.3",
		Status:   gapreport.StatusPartial,
		Evidence: []string{"coverage-report.json"},
		Findings: []string{"COV001", "COV002"},
	})
	if len(r.Objectives) != 1 {
		t.Fatalf("expected 1 objective, got %d", len(r.Objectives))
	}
	obj := r.Objectives[0]
	if obj.Clause != "§6.4.4.3" {
		t.Errorf("Clause = %q", obj.Clause)
	}
	if len(obj.Evidence) != 1 {
		t.Errorf("Evidence len = %d, want 1", len(obj.Evidence))
	}
	if len(obj.Findings) != 2 {
		t.Errorf("Findings len = %d, want 2", len(obj.Findings))
	}
}

// ─── Render JSON ──────────────────────────────────────────────────────────────

//fusa:test REQ-GAPREPORT002
func TestRender_JSON_RoundTrip(t *testing.T) {
	r := gapreport.New("/proj", "iso26262")
	r.AddObjective(gapreport.Objective{
		ID:     "OBJ-001",
		Title:  "Software planning",
		Status: gapreport.StatusSatisfied,
	})
	r.AddObjective(gapreport.Objective{
		ID:     "OBJ-002",
		Title:  "Gap item",
		Status: gapreport.StatusGap,
	})

	var buf bytes.Buffer
	if err := gapreport.Render(&buf, r, "json"); err != nil {
		t.Fatalf("Render json: %v", err)
	}

	// Must be valid JSON
	var decoded gapreport.Report
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("JSON unmarshal: %v; raw: %s", err, buf.String())
	}

	if decoded.Kind != "gap-report" {
		t.Errorf("Kind = %q", decoded.Kind)
	}
	if decoded.Standard != "iso26262" {
		t.Errorf("Standard = %q", decoded.Standard)
	}
	if len(decoded.Objectives) != 2 {
		t.Errorf("Objectives len = %d, want 2", len(decoded.Objectives))
	}
	if decoded.Summary.Total != 2 {
		t.Errorf("Summary.Total = %d, want 2", decoded.Summary.Total)
	}
	if decoded.Summary.Satisfied != 1 {
		t.Errorf("Summary.Satisfied = %d, want 1", decoded.Summary.Satisfied)
	}
	if decoded.Summary.Gaps != 1 {
		t.Errorf("Summary.Gaps = %d, want 1", decoded.Summary.Gaps)
	}
}

//fusa:test REQ-GAPREPORT002
func TestRender_EmptyFormat_DefaultsToJSON(t *testing.T) {
	r := gapreport.New(".", "iso26262")
	var buf bytes.Buffer
	if err := gapreport.Render(&buf, r, ""); err != nil {
		t.Fatalf("Render empty format: %v", err)
	}
	if !strings.Contains(buf.String(), `"kind"`) {
		t.Errorf("expected JSON output for empty format; got: %s", buf.String())
	}
}

//fusa:test REQ-GAPREPORT002
func TestRender_UnsupportedFormat(t *testing.T) {
	r := gapreport.New(".", "iso26262")
	var buf bytes.Buffer
	err := gapreport.Render(&buf, r, "xml")
	if err == nil {
		t.Fatal("expected error for unsupported format")
	}
	if !strings.Contains(err.Error(), "unsupported format") {
		t.Errorf("error message = %q, should mention unsupported format", err.Error())
	}
}

// ─── Render text ──────────────────────────────────────────────────────────────

//fusa:test REQ-GAPREPORT002
func TestRender_Text_HeaderAndSummary(t *testing.T) {
	r := gapreport.New("/my/project", "iso26262")
	r.AddObjective(gapreport.Objective{
		ID:     "OBJ-001",
		Title:  "Planning",
		Status: gapreport.StatusSatisfied,
	})
	r.AddObjective(gapreport.Objective{
		ID:     "OBJ-002",
		Title:  "Verification",
		Status: gapreport.StatusGap,
	})

	var buf bytes.Buffer
	if err := gapreport.Render(&buf, r, "text"); err != nil {
		t.Fatalf("Render text: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "iso26262") {
		t.Errorf("missing standard name in text output; got: %s", out)
	}
	if !strings.Contains(out, "/my/project") {
		t.Errorf("missing project root in text output; got: %s", out)
	}
	if !strings.Contains(out, "Summary:") {
		t.Errorf("missing Summary line; got: %s", out)
	}
	if !strings.Contains(out, "OBJ-001") {
		t.Errorf("missing OBJ-001 in text output; got: %s", out)
	}
	if !strings.Contains(out, "OBJ-002") {
		t.Errorf("missing OBJ-002 in text output; got: %s", out)
	}
}

//fusa:test REQ-GAPREPORT002
func TestRender_Text_StatusIcons(t *testing.T) {
	r := gapreport.New(".", "iec61508")
	r.AddObjective(gapreport.Objective{ID: "A", Status: gapreport.StatusSatisfied, Title: "Sat"})
	r.AddObjective(gapreport.Objective{ID: "B", Status: gapreport.StatusPartial, Title: "Part"})
	r.AddObjective(gapreport.Objective{ID: "C", Status: gapreport.StatusGap, Title: "Gap"})

	var buf bytes.Buffer
	if err := gapreport.Render(&buf, r, "text"); err != nil {
		t.Fatalf("Render text: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "✓") {
		t.Errorf("missing satisfied icon ✓; got: %s", out)
	}
	if !strings.Contains(out, "?") {
		t.Errorf("missing partial icon ?; got: %s", out)
	}
	if !strings.Contains(out, "✗") {
		t.Errorf("missing gap icon ✗; got: %s", out)
	}
}

//fusa:test REQ-GAPREPORT002
func TestRender_Text_FindingsDisplayed(t *testing.T) {
	r := gapreport.New(".", "do178c")
	r.AddObjective(gapreport.Objective{
		ID:       "OBJ-X",
		Title:    "With findings",
		Status:   gapreport.StatusPartial,
		Findings: []string{"FUSA001", "COV003"},
	})

	var buf bytes.Buffer
	if err := gapreport.Render(&buf, r, "text"); err != nil {
		t.Fatalf("Render text: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "findings") {
		t.Errorf("expected 'findings' label in output; got: %s", out)
	}
	if !strings.Contains(out, "FUSA001") {
		t.Errorf("expected FUSA001 in output; got: %s", out)
	}
}

//fusa:test REQ-GAPREPORT002
func TestRender_Text_NoFindings_NoFindingsLine(t *testing.T) {
	r := gapreport.New(".", "do178c")
	r.AddObjective(gapreport.Objective{
		ID:     "OBJ-Y",
		Title:  "No findings",
		Status: gapreport.StatusSatisfied,
		// no Findings slice
	})

	var buf bytes.Buffer
	if err := gapreport.Render(&buf, r, "text"); err != nil {
		t.Fatalf("Render text: %v", err)
	}
	out := buf.String()

	// Should NOT print a findings: line when there are no findings
	if strings.Contains(out, "findings:") {
		t.Errorf("unexpected 'findings:' line when Findings is nil; got: %s", out)
	}
}

// ─── Status constants ─────────────────────────────────────────────────────────

func TestStatusConstants(t *testing.T) {
	if gapreport.StatusSatisfied != "satisfied" {
		t.Errorf("StatusSatisfied = %q", gapreport.StatusSatisfied)
	}
	if gapreport.StatusPartial != "partial" {
		t.Errorf("StatusPartial = %q", gapreport.StatusPartial)
	}
	if gapreport.StatusGap != "gap" {
		t.Errorf("StatusGap = %q", gapreport.StatusGap)
	}
}
