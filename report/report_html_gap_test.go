package report_test

// Gap tests for moduleFromRoot() and countRequirements() in report/html.go (v0.33.1).
// Both functions are exercised indirectly via RenderHTML / Render("html").

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/report"
)

// renderHTML is a helper that calls Render("html") on a Report whose
// ProjectRoot is set to dir.
func renderHTML(t *testing.T, dir string) string {
	t.Helper()
	r := report.New(dir, nil)
	var buf bytes.Buffer
	if err := report.Render(&buf, r, "html"); err != nil {
		t.Fatalf("Render html: %v", err)
	}
	return buf.String()
}

// ─── moduleFromRoot ───────────────────────────────────────────────────────────

// TestModuleFromRoot_WithGoMod covers the success branch of moduleFromRoot
// (go.mod present and has "module <path>").
//
//fusa:test REQ-HTML001
func TestModuleFromRoot_WithGoMod(t *testing.T) {
	dir := t.TempDir()
	gomod := "module github.com/example/myproject\n\ngo 1.22\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0o640); err != nil {
		t.Fatal(err)
	}

	out := renderHTML(t, dir)
	if !bytes.Contains([]byte(out), []byte("myproject")) {
		t.Error("HTML should contain module name 'myproject' when go.mod is present")
	}
}

// TestModuleFromRoot_GoModNoModuleDirective covers the loop-fallthrough branch
// (go.mod exists but has no "module" line) → returns "".
//
//fusa:test REQ-HTML001
func TestModuleFromRoot_GoModNoModuleDirective(t *testing.T) {
	dir := t.TempDir()
	// go.mod with only a go directive, no module line
	gomod := "go 1.22\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0o640); err != nil {
		t.Fatal(err)
	}

	out := renderHTML(t, dir)
	// Should still produce valid HTML even when module is empty.
	if !bytes.Contains([]byte(out), []byte("<!DOCTYPE html>")) {
		t.Error("expected valid HTML output when go.mod has no module directive")
	}
}

// ─── countRequirements ────────────────────────────────────────────────────────

// TestCountRequirements_ValidReqsFile covers the success branch of
// countRequirements (valid JSON with requirements array).
//
//fusa:test REQ-HTML001
func TestCountRequirements_ValidReqsFile(t *testing.T) {
	dir := t.TempDir()
	reqs := `{"requirements":[{"id":"REQ-001"},{"id":"REQ-002"},{"id":"REQ-003"}]}`
	if err := os.WriteFile(filepath.Join(dir, ".fusa-reqs.json"), []byte(reqs), 0o640); err != nil {
		t.Fatal(err)
	}

	out := renderHTML(t, dir)
	// The HTML contains the req count; just verify it rendered without error.
	if !bytes.Contains([]byte(out), []byte("<!DOCTYPE html>")) {
		t.Error("expected valid HTML output with req count")
	}
}

// TestCountRequirements_InvalidJSON covers the json.Unmarshal error branch of
// countRequirements → returns 0, 0.
//
//fusa:test REQ-HTML001
func TestCountRequirements_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".fusa-reqs.json"), []byte("not json"), 0o640); err != nil {
		t.Fatal(err)
	}

	out := renderHTML(t, dir)
	if !bytes.Contains([]byte(out), []byte("<!DOCTYPE html>")) {
		t.Error("expected valid HTML output even with invalid .fusa-reqs.json")
	}
}

// TestRenderHTML_WithFindingsAndModule exercises RenderHTML end-to-end with
// a go.mod and findings, hitting both moduleFromRoot and countRequirements.
//
//fusa:test REQ-HTML001
//fusa:test REQ-HTML003
func TestRenderHTML_WithFindingsAndModule(t *testing.T) {
	dir := t.TempDir()
	gomod := "module github.com/example/htmltest\n\ngo 1.22\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0o640); err != nil {
		t.Fatal(err)
	}
	reqs := `{"requirements":[{"id":"REQ-X001"}]}`
	if err := os.WriteFile(filepath.Join(dir, ".fusa-reqs.json"), []byte(reqs), 0o640); err != nil {
		t.Fatal(err)
	}

	r := report.New(dir, []fusa.Finding{
		{RuleID: "TEST001", Severity: fusa.SeverityError, Message: "test error",
			Location: fusa.Location{File: "foo.go", Line: 1}},
	})
	var buf bytes.Buffer
	if err := report.RenderHTML(&buf, r); err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}
	out := buf.String()
	if !bytes.Contains([]byte(out), []byte("htmltest")) {
		t.Errorf("expected module name 'htmltest' in HTML output")
	}
	if !bytes.Contains([]byte(out), []byte("TEST001")) {
		t.Errorf("expected finding 'TEST001' in HTML output")
	}
}
