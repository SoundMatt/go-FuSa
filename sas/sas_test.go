package sas_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SoundMatt/go-FuSa/sas"
)

//fusa:test REQ-SAS001
func TestBuild_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	doc, err := sas.Build(dir, "myproject", "1.0.0", "DAL-B", "Test Team")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if doc.Project != "myproject" {
		t.Errorf("Project = %q", doc.Project)
	}
	if doc.Version != "1.0.0" {
		t.Errorf("Version = %q", doc.Version)
	}
	if doc.DAL != "DAL-B" {
		t.Errorf("DAL = %q", doc.DAL)
	}
	if doc.Prepared != "Test Team" {
		t.Errorf("Prepared = %q", doc.Prepared)
	}
	if len(doc.Evidence) == 0 {
		t.Error("Evidence should not be empty")
	}
	if len(doc.Gaps) == 0 {
		t.Error("expected gaps in empty dir")
	}
	if !strings.Contains(doc.Assertion, "INCOMPLETE") {
		t.Errorf("Assertion should say INCOMPLETE, got: %q", doc.Assertion)
	}
}

//fusa:test REQ-SAS001
func TestBuild_AllPresent(t *testing.T) {
	dir := t.TempDir()
	// Write all evidence files the catalog expects
	files := []string{
		"SAFETY_PLAN.md", "SVP.md", "SCMP.md", "SQAP.md",
		".fusa-reqs.json", ".fusa-evidence.json", "sbom.json",
		"provenance.json", "qualify-report.json", "fmea.json",
		"tara.json", "vuln.json", "boundary.mermaid", "safety-case.json",
		"coverage-report.json", "sci.json", "do178-gap-report.json",
		".fusa-problems.json", "audit-pack.zip",
	}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o644); err != nil {
			t.Fatalf("write %s: %v", f, err)
		}
	}
	doc, err := sas.Build(dir, "proj", "2.0", "DAL-A", "Alice")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	// All evidence present — assertion should be complete
	if strings.Contains(doc.Assertion, "INCOMPLETE") {
		t.Errorf("expected complete assertion with all evidence, got: %q", doc.Assertion)
	}
	if len(doc.Gaps) != 0 {
		t.Errorf("expected no gaps, got: %v", doc.Gaps)
	}
}

//fusa:test REQ-SAS003
func TestRender_Markdown(t *testing.T) {
	dir := t.TempDir()
	doc, _ := sas.Build(dir, "proj", "1.0", "DAL-C", "Bob")
	var buf bytes.Buffer
	if err := sas.Render(&buf, doc, "markdown"); err != nil {
		t.Fatalf("Render markdown: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "# Software Accomplishment Summary") {
		t.Error("missing markdown header")
	}
	if !strings.Contains(out, "proj") {
		t.Error("missing project name in markdown")
	}
	if !strings.Contains(out, "DAL-C") {
		t.Error("missing DAL in markdown")
	}
}

//fusa:test REQ-SAS003
func TestRender_Text(t *testing.T) {
	dir := t.TempDir()
	doc, _ := sas.Build(dir, "proj", "1.0", "DAL-B", "")
	var buf bytes.Buffer
	if err := sas.Render(&buf, doc, "text"); err != nil {
		t.Fatalf("Render text: %v", err)
	}
	if !strings.Contains(buf.String(), "Software Accomplishment Summary") {
		t.Error("missing header in text output")
	}
}

//fusa:test REQ-SAS003
func TestRender_JSON(t *testing.T) {
	dir := t.TempDir()
	doc, _ := sas.Build(dir, "proj", "1.0", "DAL-B", "")
	var buf bytes.Buffer
	if err := sas.Render(&buf, doc, "json"); err != nil {
		t.Fatalf("Render json: %v", err)
	}
	if !strings.Contains(buf.String(), `"project"`) {
		t.Error("missing project field in JSON")
	}
	if !strings.Contains(buf.String(), `"dal"`) {
		t.Error("missing dal field in JSON")
	}
}

//fusa:test REQ-SAS003
func TestRender_InvalidFormat(t *testing.T) {
	doc := &sas.SAS{}
	if err := sas.Render(&bytes.Buffer{}, doc, "html"); err == nil {
		t.Error("expected error for unsupported format")
	}
}

//fusa:test REQ-SAS001
func TestSASFileConstant(t *testing.T) {
	if sas.SASFile != "sas.md" {
		t.Errorf("SASFile = %q", sas.SASFile)
	}
}

//fusa:test REQ-SAS002
func TestEvidenceCount(t *testing.T) {
	dir := t.TempDir()
	doc, _ := sas.Build(dir, "proj", "1.0", "DAL-B", "")
	// All evidence items checked — expect at least 15 items
	if len(doc.Evidence) < 15 {
		t.Errorf("expected ≥15 evidence items, got %d", len(doc.Evidence))
	}
}
