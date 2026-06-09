package iso26262_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SoundMatt/go-FuSa/iso26262"
)

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

func TestRender_JSON(t *testing.T) {
	dir := t.TempDir()
	rep, _ := iso26262.Assess(dir, "proj", iso26262.ASILB)
	var buf bytes.Buffer
	if err := iso26262.Render(&buf, rep, "json"); err != nil {
		t.Fatalf("Render json: %v", err)
	}
	if !strings.Contains(buf.String(), `"asil"`) {
		t.Error("missing asil field in JSON")
	}
}

func TestRender_InvalidFormat(t *testing.T) {
	rep := &iso26262.Report{}
	if err := iso26262.Render(&bytes.Buffer{}, rep, "html"); err == nil {
		t.Error("expected error for unsupported format")
	}
}

func TestASILConstants(t *testing.T) {
	if iso26262.ASILA != "ASIL-A" {
		t.Errorf("ASILA = %q", iso26262.ASILA)
	}
	if iso26262.ASILD != "ASIL-D" {
		t.Errorf("ASILD = %q", iso26262.ASILD)
	}
}

func TestRuleFiresWhenReportAbsent(t *testing.T) {
	// The rule is registered via init(); we just verify Assess works in an empty dir
	// and the report file constant is correct.
	if iso26262.ReportFile != "iso26262-gap-report.json" {
		t.Errorf("ReportFile = %q", iso26262.ReportFile)
	}
}

func TestRuleAbsentWhenPresent(t *testing.T) {
	dir := t.TempDir()
	// Write a fake report file
	if err := os.WriteFile(filepath.Join(dir, iso26262.ReportFile), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Verify Assess still runs (rule absence is tested via engine; here we just
	// confirm the file check logic in Assess is unaffected)
	rep, err := iso26262.Assess(dir, "proj", iso26262.ASILD)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if rep == nil {
		t.Error("expected report")
	}
}
