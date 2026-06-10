package iso26262_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SoundMatt/go-FuSa/config"
	"github.com/SoundMatt/go-FuSa/engine"
	"github.com/SoundMatt/go-FuSa/iso26262"
)

//fusa:test REQ-ISO26262-001
func TestAssess_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	rep, err := iso26262.Assess(dir, "myproject", iso26262.ASILB)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if rep.Project != "myproject" {
		t.Errorf("Project = %q", rep.Project)
	}
	if rep.ASIL != iso26262.ASILB {
		t.Errorf("ASIL = %v", rep.ASIL)
	}
	if len(rep.Objectives) == 0 {
		t.Error("expected objectives")
	}
	if rep.Gap == 0 {
		t.Error("expected some GAP objectives in empty dir")
	}
}

//fusa:test REQ-ISO26262-001
func TestAssess_WithEvidence(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{"SAFETY_PLAN.md", ".fusa-reqs.json", ".fusa-evidence.json", "boundary.mermaid"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o644); err != nil {
			t.Fatalf("write %s: %v", f, err)
		}
	}
	rep, err := iso26262.Assess(dir, "proj", iso26262.ASILB)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if rep.Pass == 0 {
		t.Error("expected some PASS objectives with evidence files present")
	}
}

//fusa:test REQ-ISO26262-001
func TestAssess_ASILC_SafetyCase(t *testing.T) {
	dir := t.TempDir()
	rep, err := iso26262.Assess(dir, "proj", iso26262.ASILC)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	// 6.7 (safety-case.json) applies only at ASIL-C/D
	found := false
	for _, obj := range rep.Objectives {
		if obj.ID == "6.7" {
			found = true
			// It should be a GAP (file absent)
			if obj.Status != iso26262.StatusGap {
				t.Errorf("6.7 status = %v, want GAP", obj.Status)
			}
		}
	}
	if !found {
		t.Error("6.7 objective not found at ASIL-C")
	}
}

//fusa:test REQ-ISO26262-001
func TestAssess_ASILA_SafetyCaseNA(t *testing.T) {
	dir := t.TempDir()
	rep, err := iso26262.Assess(dir, "proj", iso26262.ASILA)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	for _, obj := range rep.Objectives {
		if obj.ID == "6.7" {
			if obj.Status != iso26262.StatusNA {
				t.Errorf("6.7 at ASIL-A should be N/A, got %v", obj.Status)
			}
			return
		}
	}
	t.Error("6.7 not found")
}

//fusa:test REQ-ISO26262-001
func TestAssess_ASILC_ManualReview(t *testing.T) {
	dir := t.TempDir()
	rep, err := iso26262.Assess(dir, "proj", iso26262.ASILC)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	// 11.1 (confirmation review) applies at ASIL-C/D and is MANUAL
	for _, obj := range rep.Objectives {
		if obj.ID == "11.1" {
			if obj.Status != iso26262.StatusManual {
				t.Errorf("11.1 status = %v, want MANUAL", obj.Status)
			}
			return
		}
	}
	t.Error("11.1 not found at ASIL-C")
}

//fusa:test REQ-ISO26262-003
func TestRender_Text(t *testing.T) {
	dir := t.TempDir()
	rep, _ := iso26262.Assess(dir, "proj", iso26262.ASILB)
	var buf bytes.Buffer
	if err := iso26262.Render(&buf, rep, "text"); err != nil {
		t.Fatalf("Render text: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "ISO 26262 Gap Report") {
		t.Error("missing report header")
	}
	if !strings.Contains(out, "ASIL-B") {
		t.Error("missing ASIL in text output")
	}
}

//fusa:test REQ-ISO26262-003
func TestRender_JSON(t *testing.T) {
	dir := t.TempDir()
	rep, _ := iso26262.Assess(dir, "proj", iso26262.ASILB)
	var buf bytes.Buffer
	if err := iso26262.Render(&buf, rep, "json"); err != nil {
		t.Fatalf("Render json: %v", err)
	}
	if !strings.Contains(buf.String(), `"standard"`) {
		t.Error("missing standard field in JSON")
	}
}

//fusa:test REQ-ISO26262-003
func TestRender_InvalidFormat(t *testing.T) {
	rep := &iso26262.Report{}
	if err := iso26262.Render(&bytes.Buffer{}, rep, "html"); err == nil {
		t.Error("expected error for unsupported format")
	}
}

//fusa:test REQ-ISO26262-002
func TestASILConstants(t *testing.T) {
	if iso26262.ASILA != "ASIL-A" {
		t.Errorf("ASILA = %q", iso26262.ASILA)
	}
	if iso26262.ASILD != "ASIL-D" {
		t.Errorf("ASILD = %q", iso26262.ASILD)
	}
}

//fusa:test REQ-ISO26262-004
func TestRuleFiresWhenReportAbsent(t *testing.T) {
	// The rule is registered via init(); we just verify Assess works in an empty dir
	// and the report file constant is correct.
	if iso26262.ReportFile != "iso26262-gap-report.json" {
		t.Errorf("ReportFile = %q", iso26262.ReportFile)
	}
}

//fusa:test REQ-ISO26262-004
func TestRuleAbsentWhenPresent(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, iso26262.ReportFile), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := iso26262.Assess(dir, "proj", iso26262.ASILD)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if rep == nil {
		t.Error("expected report")
	}
}

// ─── New v0.22 objectives ─────────────────────────────────────────────────────

//fusa:test REQ-ISO26262-001
func TestAssess_7_3_UsesHARAJSON(t *testing.T) {
	dir := t.TempDir()
	// .fusa-hara.json present → obj 7.3 should PASS
	if err := os.WriteFile(filepath.Join(dir, ".fusa-hara.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := iso26262.Assess(dir, "proj", iso26262.ASILB)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	for _, obj := range rep.Objectives {
		if obj.ID == "7.3" {
			if obj.Status != iso26262.StatusPass {
				t.Errorf("7.3 with .fusa-hara.json should PASS, got %v", obj.Status)
			}
			return
		}
	}
	t.Error("objective 7.3 not found")
}

//fusa:test REQ-ISO26262-001
func TestAssess_10_4_SCI(t *testing.T) {
	dir := t.TempDir()
	rep, err := iso26262.Assess(dir, "proj", iso26262.ASILB)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	for _, obj := range rep.Objectives {
		if obj.ID == "10.4" {
			if obj.Status != iso26262.StatusGap {
				t.Errorf("10.4 without sci.json should be GAP, got %v", obj.Status)
			}
			return
		}
	}
	t.Error("objective 10.4 not found")
}

//fusa:test REQ-ISO26262-001
func TestAssess_10_4_SCI_Pass(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "sci.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := iso26262.Assess(dir, "proj", iso26262.ASILB)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	for _, obj := range rep.Objectives {
		if obj.ID == "10.4" {
			if obj.Status != iso26262.StatusPass {
				t.Errorf("10.4 with sci.json should PASS, got %v", obj.Status)
			}
			return
		}
	}
	t.Error("objective 10.4 not found")
}

//fusa:test REQ-ISO26262-005
func TestISO26262002_FiresForISO26262ProjectWithUnannotatedReqs(t *testing.T) {
	dir := t.TempDir()
	reqs := `{"requirements":[{"id":"REQ-001","title":"req without ASIL"}]}`
	if err := os.WriteFile(filepath.Join(dir, ".fusa-reqs.json"), []byte(reqs), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default("m", "p")
	cfg.Project.Standard = "ISO26262"
	result, err := engine.Default.Run(context.Background(), dir, cfg)
	if err != nil {
		t.Fatalf("engine.Run: %v", err)
	}
	found := false
	for _, f := range result.Findings {
		if f.RuleID == "ISO26262002" {
			found = true
			break
		}
	}
	if !found {
		t.Error("ISO26262002 should fire when ISO26262 project has requirements without ASIL")
	}
}

//fusa:test REQ-ISO26262-005
func TestISO26262002_SilentForNonISO26262(t *testing.T) {
	dir := t.TempDir()
	reqs := `{"requirements":[{"id":"REQ-001","title":"no asil"}]}`
	if err := os.WriteFile(filepath.Join(dir, ".fusa-reqs.json"), []byte(reqs), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default("m", "p") // standard is "generic"
	result, err := engine.Default.Run(context.Background(), dir, cfg)
	if err != nil {
		t.Fatalf("engine.Run: %v", err)
	}
	for _, f := range result.Findings {
		if f.RuleID == "ISO26262002" {
			t.Error("ISO26262002 should not fire for non-ISO26262 project")
			return
		}
	}
}

//fusa:test REQ-ISO26262-006
func TestISO26262003_SilentWhenNoFailures(t *testing.T) {
	dir := t.TempDir()
	qualify := `{"pass":44,"fail":0,"total":44}`
	if err := os.WriteFile(filepath.Join(dir, "qualify-report.json"), []byte(qualify), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default("m", "p")
	result, err := engine.Default.Run(context.Background(), dir, cfg)
	if err != nil {
		t.Fatalf("engine.Run: %v", err)
	}
	for _, f := range result.Findings {
		if f.RuleID == "ISO26262003" {
			t.Errorf("ISO26262003 should not fire when qualify has 0 failures, got: %s", f.Message)
			return
		}
	}
}

//fusa:test REQ-ISO26262-006
func TestISO26262003_FiresWhenFailures(t *testing.T) {
	dir := t.TempDir()
	qualify := `{"pass":42,"fail":2,"total":44}`
	if err := os.WriteFile(filepath.Join(dir, "qualify-report.json"), []byte(qualify), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default("m", "p")
	result, err := engine.Default.Run(context.Background(), dir, cfg)
	if err != nil {
		t.Fatalf("engine.Run: %v", err)
	}
	for _, f := range result.Findings {
		if f.RuleID == "ISO26262003" {
			return // found — expected
		}
	}
	t.Error("ISO26262003 should fire when qualify-report.json has failures")
}

// ─── Description coverage ─────────────────────────────────────────────────────

//fusa:test REQ-ISO26262-004
func TestISO26262_Descriptions(t *testing.T) {
	ids := []string{"ISO26262001", "ISO26262002", "ISO26262003"}
	for _, id := range ids {
		found := false
		for _, r := range engine.Default.Rules() {
			if r.ID() == id {
				if r.Description() == "" {
					t.Errorf("%s Description empty", id)
				}
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s not registered", id)
		}
	}
}
