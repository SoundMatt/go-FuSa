package sci_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SoundMatt/go-FuSa/sci"
)

//fusa:test REQ-SCI001
func TestBuild_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	index, err := sci.Build(dir, "test-project", "1.0.0")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if index.Project != "test-project" {
		t.Errorf("Project = %q", index.Project)
	}
	if index.Version != "1.0.0" {
		t.Errorf("Version = %q", index.Version)
	}
	if len(index.Items) == 0 {
		t.Error("Items should be non-empty (catalog always populated)")
	}
	// Nothing should be present in an empty dir
	for _, it := range index.Items {
		if it.Present {
			t.Errorf("item %q should not be present in empty dir", it.Name)
		}
	}
}

//fusa:test REQ-SCI001
func TestBuild_WithSomeFiles(t *testing.T) {
	dir := t.TempDir()
	// Create a few catalog files
	for _, f := range []string{"SAFETY_PLAN.md", "sbom.json", ".fusa-evidence.json"} {
		path := filepath.Join(dir, f)
		if err := os.WriteFile(path, []byte("content"), 0o644); err != nil {
			t.Fatalf("write %s: %v", f, err)
		}
	}
	index, err := sci.Build(dir, "proj", "2.0.0")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	present := 0
	for _, it := range index.Items {
		if it.Present {
			present++
			if it.SHA256 == "" {
				t.Errorf("present item %q has no SHA256", it.Name)
			}
		}
	}
	if present != 3 {
		t.Errorf("expected 3 present items, got %d", present)
	}
}

//fusa:test REQ-SCI001
func TestBuild_SHA256Stable(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "sbom.json"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	a, _ := sci.Build(dir, "p", "v1")
	b, _ := sci.Build(dir, "p", "v1")
	var hashA, hashB string
	for _, it := range a.Items {
		if it.File == "sbom.json" {
			hashA = it.SHA256
		}
	}
	for _, it := range b.Items {
		if it.File == "sbom.json" {
			hashB = it.SHA256
		}
	}
	if hashA != hashB {
		t.Error("SHA256 is not stable across two builds")
	}
}

//fusa:test REQ-SCI002
func TestRender_JSON(t *testing.T) {
	dir := t.TempDir()
	index, _ := sci.Build(dir, "proj", "1.0")
	var buf bytes.Buffer
	if err := sci.Render(&buf, index, "json"); err != nil {
		t.Fatalf("Render json: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `"project"`) {
		t.Error("missing project field in JSON")
	}
}

//fusa:test REQ-SCI002
func TestRender_Markdown(t *testing.T) {
	dir := t.TempDir()
	index, _ := sci.Build(dir, "proj", "1.0")
	var buf bytes.Buffer
	if err := sci.Render(&buf, index, "markdown"); err != nil {
		t.Fatalf("Render markdown: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "# Software Configuration Index") {
		t.Error("missing markdown header")
	}
	if !strings.Contains(out, "proj") {
		t.Error("missing project name in markdown")
	}
}

//fusa:test REQ-SCI002
func TestRender_InvalidFormat(t *testing.T) {
	index := &sci.SCI{}
	if err := sci.Render(&bytes.Buffer{}, index, "csv"); err == nil {
		t.Error("expected error for unsupported format")
	}
}

//fusa:test REQ-SCI003
func TestSaveJSON(t *testing.T) {
	dir := t.TempDir()
	index, _ := sci.Build(dir, "proj", "1.0")
	outPath := filepath.Join(dir, "sci.json")
	if err := sci.SaveJSON(outPath, index); err != nil {
		t.Fatalf("SaveJSON: %v", err)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !strings.Contains(string(data), "proj") {
		t.Error("saved JSON missing project name")
	}
}

//fusa:test REQ-SCI001
func TestDataClassConstants(t *testing.T) {
	if sci.ClassPlan != "Plan" {
		t.Errorf("ClassPlan = %q", sci.ClassPlan)
	}
	if sci.ClassAccomplishment != "Accomplishment Summary" {
		t.Errorf("ClassAccomplishment = %q", sci.ClassAccomplishment)
	}
}
