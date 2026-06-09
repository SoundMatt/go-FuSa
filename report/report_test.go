package report_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/report"
)

var testFindings = []fusa.Finding{
	{
		RuleID:      "FUSA001",
		Severity:    fusa.SeverityError,
		Message:     "missing config",
		Location:    fusa.Location{File: ".fusa.json"},
		Remediation: "run gofusa init",
	},
	{
		RuleID:   "FUSA003",
		Severity: fusa.SeverityWarning,
		Message:  "missing license",
		Location: fusa.Location{File: "LICENSE", Line: 0},
	},
	{
		RuleID:   "FUSA004",
		Severity: fusa.SeverityInfo,
		Message:  "informational note",
		Location: fusa.Location{File: "README.md", Line: 1, Column: 1},
	},
}

//fusa:test REQ-RPT003
func TestNew_Summary(t *testing.T) {
	r := report.New("/tmp/proj", testFindings)
	if r.Summary.Total != 3 {
		t.Errorf("Total = %d, want 3", r.Summary.Total)
	}
	if r.Summary.Errors != 1 {
		t.Errorf("Errors = %d, want 1", r.Summary.Errors)
	}
	if r.Summary.Warnings != 1 {
		t.Errorf("Warnings = %d, want 1", r.Summary.Warnings)
	}
	if r.Summary.Infos != 1 {
		t.Errorf("Infos = %d, want 1", r.Summary.Infos)
	}
}

func TestNew_EmptyFindings(t *testing.T) {
	r := report.New("/tmp/proj", nil)
	if r.Summary.Total != 0 {
		t.Errorf("Total = %d, want 0", r.Summary.Total)
	}
	if r.GeneratedAt.IsZero() {
		t.Error("GeneratedAt is zero")
	}
}

//fusa:test REQ-RPT001
func TestRender_Text_ContainsFindings(t *testing.T) {
	r := report.New("/proj", testFindings)
	var buf bytes.Buffer
	if err := report.Render(&buf, r, "text"); err != nil {
		t.Fatalf("Render text: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"FUSA001", "ERROR", "FUSA003", "WARNING", "FAIL", "Summary"} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q", want)
		}
	}
}

//fusa:test REQ-RPT002
func TestRender_Text_Pass(t *testing.T) {
	r := report.New("/proj", nil)
	var buf bytes.Buffer
	if err := report.Render(&buf, r, "text"); err != nil {
		t.Fatalf("Render text: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "PASS") {
		t.Error("expected PASS in output with no findings")
	}
	if !strings.Contains(out, "No findings") {
		t.Error("expected 'No findings' in empty output")
	}
}

func TestRender_Text_LocationFormatting(t *testing.T) {
	findings := []fusa.Finding{
		{RuleID: "X001", Severity: fusa.SeverityInfo, Message: "msg",
			Location: fusa.Location{File: "foo.go", Line: 10, Column: 5}},
	}
	r := report.New("/proj", findings)
	var buf bytes.Buffer
	if err := report.Render(&buf, r, "text"); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "foo.go:10:5") {
		t.Errorf("expected 'foo.go:10:5' in output, got:\n%s", out)
	}
}

//fusa:test REQ-RPT004
//fusa:test REQ-RPT005
func TestRender_JSON_Valid(t *testing.T) {
	r := report.New("/proj", testFindings)
	r.GeneratedAt = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	var buf bytes.Buffer
	if err := report.Render(&buf, r, "json"); err != nil {
		t.Fatalf("Render json: %v", err)
	}
	var decoded report.Report
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("JSON decode: %v", err)
	}
	if decoded.Summary.Errors != 1 {
		t.Errorf("JSON summary errors = %d, want 1", decoded.Summary.Errors)
	}
	if len(decoded.Findings) != 3 {
		t.Errorf("JSON findings len = %d, want 3", len(decoded.Findings))
	}
}

//fusa:test REQ-HTML001
//fusa:test REQ-HTML003
func TestRender_HTML_ContainsKeyElements(t *testing.T) {
	r := report.New(t.TempDir(), testFindings)
	var buf bytes.Buffer
	if err := report.Render(&buf, r, "html"); err != nil {
		t.Fatalf("Render html: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"<!DOCTYPE html>", "Safety Compliance Report", "FUSA001", "FAIL"} {
		if !strings.Contains(out, want) {
			t.Errorf("html output missing %q", want)
		}
	}
}

//fusa:test REQ-HTML002
func TestRender_HTML_EvidenceCards(t *testing.T) {
	r := report.New(t.TempDir(), nil)
	var buf bytes.Buffer
	if err := report.Render(&buf, r, "html"); err != nil {
		t.Fatalf("Render html: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Evidence Status") {
		t.Error("html output missing Evidence Status section")
	}
}

func TestRender_HTML_PassBadge(t *testing.T) {
	r := report.New(t.TempDir(), nil)
	var buf bytes.Buffer
	if err := report.Render(&buf, r, "html"); err != nil {
		t.Fatalf("Render html: %v", err)
	}
	if !strings.Contains(buf.String(), "PASS") {
		t.Error("html output missing PASS badge for empty findings")
	}
}

func TestRender_UnknownFormat(t *testing.T) {
	r := report.New("/proj", nil)
	if err := report.Render(&bytes.Buffer{}, r, "xml"); err == nil {
		t.Error("Render unknown format: expected error, got nil")
	}
}

func TestRenderToFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.txt")
	r := report.New("/proj", testFindings)
	if err := report.RenderToFile(r, "text", path); err != nil {
		t.Fatalf("RenderToFile: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if !strings.Contains(string(data), "FUSA001") {
		t.Error("output file missing FUSA001")
	}
}

//fusa:test REQ-NF002
func TestReport_GeneratedAtIsUTC(t *testing.T) {
	r := report.New("/proj", nil)
	if r.GeneratedAt.Location() != time.UTC {
		t.Errorf("GeneratedAt location = %v, want UTC", r.GeneratedAt.Location())
	}
}

func TestRenderToFile_DefaultFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.txt")
	r := report.New("/proj", nil)
	if err := report.RenderToFile(r, "", path); err != nil {
		t.Fatalf("RenderToFile empty format: %v", err)
	}
}

func TestRender_SARIF_Valid(t *testing.T) {
	r := report.New("/proj", testFindings)
	var buf bytes.Buffer
	if err := report.Render(&buf, r, "sarif"); err != nil {
		t.Fatalf("Render sarif: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "sarif") {
		t.Error("sarif output missing 'sarif' keyword")
	}
}

// ─── html_bundle ──────────────────────────────────────────────────────────────

func TestRenderEvidenceHTML_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	if err := report.RenderEvidenceHTML(&buf, dir); err != nil {
		t.Fatalf("RenderEvidenceHTML empty dir: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "<html") {
		t.Error("output missing <html tag")
	}
	if !strings.Contains(out, "Evidence") {
		t.Error("output missing 'Evidence'")
	}
}

func TestRenderEvidenceHTML_WithFindings(t *testing.T) {
	dir := t.TempDir()
	// Write a check-report.json with findings
	findings := []map[string]interface{}{
		{"ruleID": "LINT001", "severity": "WARNING", "message": "test finding"},
	}
	data, _ := json.Marshal(findings)
	if err := os.WriteFile(filepath.Join(dir, "check-report.json"), data, 0o640); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := report.RenderEvidenceHTML(&buf, dir); err != nil {
		t.Fatalf("RenderEvidenceHTML with findings: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "<html") {
		t.Error("output missing <html tag")
	}
}

func TestRenderEvidenceHTML_WithReqs(t *testing.T) {
	dir := t.TempDir()
	reqs := `[{"id":"REQ-001","title":"First"},{"id":"REQ-002","title":"Second"}]`
	if err := os.WriteFile(filepath.Join(dir, ".fusa-reqs.json"), []byte(reqs), 0o640); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := report.RenderEvidenceHTML(&buf, dir); err != nil {
		t.Fatalf("RenderEvidenceHTML with reqs: %v", err)
	}
	if !strings.Contains(buf.String(), "<html") {
		t.Error("output missing <html tag")
	}
}
