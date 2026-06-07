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

func TestRender_UnknownFormat(t *testing.T) {
	r := report.New("/proj", nil)
	if err := report.Render(&bytes.Buffer{}, r, "html"); err == nil {
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

func TestRenderToFile_DefaultFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.txt")
	r := report.New("/proj", nil)
	if err := report.RenderToFile(r, "", path); err != nil {
		t.Fatalf("RenderToFile empty format: %v", err)
	}
}
