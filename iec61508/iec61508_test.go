package iec61508_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SoundMatt/go-FuSa/iec61508"
)

func TestAssess_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	rep, err := iec61508.Assess(dir, "myproject", iec61508.SIL2)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if rep.Project != "myproject" {
		t.Errorf("Project = %q", rep.Project)
	}
	if rep.SIL != iec61508.SIL2 {
		t.Errorf("SIL = %v", rep.SIL)
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
	for _, f := range []string{"SAFETY_PLAN.md", ".fusa-reqs.json", ".fusa-evidence.json", "sbom.json"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o644); err != nil {
			t.Fatalf("write %s: %v", f, err)
		}
	}
	rep, err := iec61508.Assess(dir, "proj", iec61508.SIL2)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if rep.Pass == 0 {
		t.Error("expected some PASS objectives with evidence files present")
	}
}

func TestAssess_SIL4_MCDC_Manual(t *testing.T) {
	dir := t.TempDir()
	rep, err := iec61508.Assess(dir, "proj", iec61508.SIL4)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	// 3.5 (MC/DC) should be MANUAL at SIL-4
	found := false
	for _, obj := range rep.Objectives {
		if obj.ID == "3.5" {
			found = true
			if obj.Status != iec61508.StatusManual {
				t.Errorf("3.5 status = %v, want MANUAL", obj.Status)
			}
		}
	}
	if !found {
		t.Error("3.5 objective not found at SIL-4")
	}
}

func TestAssess_SIL1_MCDC_NA(t *testing.T) {
	dir := t.TempDir()
	rep, err := iec61508.Assess(dir, "proj", iec61508.SIL1)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	for _, obj := range rep.Objectives {
		if obj.ID == "3.5" {
			if obj.Status != iec61508.StatusNA {
				t.Errorf("3.5 at SIL-1 should be N/A, got %v", obj.Status)
			}
			return
		}
	}
	t.Error("3.5 not found")
}

func TestAssess_SIL3_SafetyCase(t *testing.T) {
	dir := t.TempDir()
	rep, err := iec61508.Assess(dir, "proj", iec61508.SIL3)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	// 7.2 (safety-case.json) applies at SIL-3/4
	found := false
	for _, obj := range rep.Objectives {
		if obj.ID == "7.2" {
			found = true
			if obj.Status != iec61508.StatusGap {
				t.Errorf("7.2 status = %v, want GAP (file absent)", obj.Status)
			}
		}
	}
	if !found {
		t.Error("7.2 not found at SIL-3")
	}
}

func TestRender_Text(t *testing.T) {
	dir := t.TempDir()
	rep, _ := iec61508.Assess(dir, "proj", iec61508.SIL2)
	var buf bytes.Buffer
	if err := iec61508.Render(&buf, rep, "text"); err != nil {
		t.Fatalf("Render text: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "IEC 61508 Gap Report") {
		t.Error("missing report header")
	}
	if !strings.Contains(out, "SIL-2") {
		t.Error("missing SIL in text output")
	}
}

func TestRender_JSON(t *testing.T) {
	dir := t.TempDir()
	rep, _ := iec61508.Assess(dir, "proj", iec61508.SIL2)
	var buf bytes.Buffer
	if err := iec61508.Render(&buf, rep, "json"); err != nil {
		t.Fatalf("Render json: %v", err)
	}
	if !strings.Contains(buf.String(), `"sil"`) {
		t.Error("missing sil field in JSON")
	}
}

func TestRender_InvalidFormat(t *testing.T) {
	rep := &iec61508.Report{}
	if err := iec61508.Render(&bytes.Buffer{}, rep, "html"); err == nil {
		t.Error("expected error for unsupported format")
	}
}

func TestSILConstants(t *testing.T) {
	if iec61508.SIL1 != "SIL-1" {
		t.Errorf("SIL1 = %q", iec61508.SIL1)
	}
	if iec61508.SIL4 != "SIL-4" {
		t.Errorf("SIL4 = %q", iec61508.SIL4)
	}
}

func TestReportFile(t *testing.T) {
	if iec61508.ReportFile != "iec61508-gap-report.json" {
		t.Errorf("ReportFile = %q", iec61508.ReportFile)
	}
}

func TestRuleAbsentWhenPresent(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, iec61508.ReportFile), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := iec61508.Assess(dir, "proj", iec61508.SIL2)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if rep == nil {
		t.Error("expected report")
	}
}
