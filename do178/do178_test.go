package do178_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SoundMatt/go-FuSa/do178"
)

func TestAssess_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	rep, err := do178.Assess(dir, "myproject", do178.DALB)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if rep.Project != "myproject" {
		t.Errorf("Project = %q", rep.Project)
	}
	if rep.DAL != do178.DALB {
		t.Errorf("DAL = %v", rep.DAL)
	}
	if len(rep.Objectives) == 0 {
		t.Error("expected objectives")
	}
	// All DAL-B objectives with evidence files should be GAP in empty dir
	if rep.Gap == 0 {
		t.Error("expected some GAP objectives in empty dir")
	}
}

func TestAssess_WithEvidence(t *testing.T) {
	dir := t.TempDir()
	// Create evidence files to convert some GAPs to PASSes
	for _, f := range []string{"SAFETY_PLAN.md", "SVP.md", "SCMP.md", "SQAP.md", ".fusa-reqs.json"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o644); err != nil {
			t.Fatalf("write %s: %v", f, err)
		}
	}
	rep, err := do178.Assess(dir, "proj", do178.DALB)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if rep.Pass == 0 {
		t.Error("expected some PASS objectives with evidence files present")
	}
}

func TestAssess_DALE_AllNA(t *testing.T) {
	dir := t.TempDir()
	rep, err := do178.Assess(dir, "proj", do178.DALE)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	// DAL-E means none of the standard objectives apply
	if rep.Gap > 0 {
		t.Errorf("DAL-E should have no GAPs, got %d", rep.Gap)
	}
}

func TestAssess_DALA_MCDCOBJ(t *testing.T) {
	dir := t.TempDir()
	rep, err := do178.Assess(dir, "proj", do178.DALA)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	// A-7.5 (MC/DC) should be MANUAL at DAL-A
	found := false
	for _, obj := range rep.Objectives {
		if obj.ID == "A-7.5" {
			if obj.Status != do178.StatusManual {
				t.Errorf("A-7.5 status = %v, want MANUAL", obj.Status)
			}
			found = true
		}
	}
	if !found {
		t.Error("A-7.5 objective not found at DAL-A")
	}
}

func TestObjectiveNotApply_DALE(t *testing.T) {
	dir := t.TempDir()
	rep, err := do178.Assess(dir, "proj", do178.DALE)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	for _, obj := range rep.Objectives {
		if obj.Status != do178.StatusNA {
			t.Errorf("DAL-E: objective %s has status %v, want N/A", obj.ID, obj.Status)
		}
	}
}

func TestRender_Text(t *testing.T) {
	dir := t.TempDir()
	rep, _ := do178.Assess(dir, "proj", do178.DALB)
	var buf bytes.Buffer
	if err := do178.Render(&buf, rep, "text"); err != nil {
		t.Fatalf("Render text: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "DO-178C Gap Report") {
		t.Error("missing report header")
	}
	if !strings.Contains(out, "DAL-B") {
		t.Error("missing DAL in text output")
	}
}

func TestRender_JSON(t *testing.T) {
	dir := t.TempDir()
	rep, _ := do178.Assess(dir, "proj", do178.DALB)
	var buf bytes.Buffer
	if err := do178.Render(&buf, rep, "json"); err != nil {
		t.Fatalf("Render json: %v", err)
	}
	if !strings.Contains(buf.String(), `"dal"`) {
		t.Error("missing dal field in JSON")
	}
}

func TestRender_InvalidFormat(t *testing.T) {
	rep := &do178.Report{}
	if err := do178.Render(&bytes.Buffer{}, rep, "html"); err == nil {
		t.Error("expected error for unsupported format")
	}
}

func TestDALConstants(t *testing.T) {
	if do178.DALA != "DAL-A" {
		t.Errorf("DALA = %q", do178.DALA)
	}
	if do178.DALE != "DAL-E" {
		t.Errorf("DALE = %q", do178.DALE)
	}
}

func TestStatusConstants(t *testing.T) {
	if do178.StatusPass != "PASS" {
		t.Errorf("StatusPass = %q", do178.StatusPass)
	}
	if do178.StatusGap != "GAP" {
		t.Errorf("StatusGap = %q", do178.StatusGap)
	}
	if do178.StatusManual != "MANUAL" {
		t.Errorf("StatusManual = %q", do178.StatusManual)
	}
	if do178.StatusNA != "N/A" {
		t.Errorf("StatusNA = %q", do178.StatusNA)
	}
}

func TestGapIncludes_SBOMFile(t *testing.T) {
	dir := t.TempDir()
	rep, _ := do178.Assess(dir, "proj", do178.DALB)
	// A-10.1 requires sbom.json, which won't exist in temp dir
	for _, obj := range rep.Objectives {
		if obj.ID == "A-10.1" {
			if obj.Status != do178.StatusGap {
				t.Errorf("A-10.1 should be GAP without sbom.json, got %v", obj.Status)
			}
			if !strings.Contains(obj.Gap, "sbom.json") {
				t.Errorf("A-10.1 gap message missing sbom.json: %q", obj.Gap)
			}
			return
		}
	}
	t.Error("A-10.1 not found in objectives")
}

func TestNestedFile_CI(t *testing.T) {
	dir := t.TempDir()
	// Create nested .github/workflows/ci.yml
	wfDir := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wfDir, "ci.yml"), []byte("ci"), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, _ := do178.Assess(dir, "proj", do178.DALB)
	for _, obj := range rep.Objectives {
		if obj.ID == "A-9.2" {
			if obj.Status != do178.StatusPass {
				t.Errorf("A-9.2 should be PASS with ci.yml present, got %v", obj.Status)
			}
			return
		}
	}
	t.Error("A-9.2 not found")
}
