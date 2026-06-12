package report_test

import (
	"bytes"
	"strings"
	"testing"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/report"
)

//fusa:test REQ-REPORT-MD001
func TestRenderMarkdown_NoFindings(t *testing.T) {
	rep := report.New("/project", nil)
	var buf bytes.Buffer
	if err := report.Render(&buf, rep, "md"); err != nil {
		t.Fatalf("Render(md): %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "# go-FuSa Compliance Report") {
		t.Errorf("missing heading: %s", out)
	}
	if !strings.Contains(out, "No findings") {
		t.Errorf("expected 'No findings' message: %s", out)
	}
}

//fusa:test REQ-REPORT-MD001
func TestRenderMarkdown_MarkdownAlias(t *testing.T) {
	rep := report.New("/project", nil)
	var buf bytes.Buffer
	if err := report.Render(&buf, rep, "markdown"); err != nil {
		t.Fatalf("Render(markdown): %v", err)
	}
	if !strings.Contains(buf.String(), "go-FuSa") {
		t.Errorf("expected go-FuSa in output")
	}
}

//fusa:test REQ-REPORT-MD001
func TestRenderMarkdown_WithFindings(t *testing.T) {
	findings := []fusa.Finding{
		{
			RuleID:   "LINT001",
			Severity: fusa.SeverityError,
			Message:  "test error",
			Location: fusa.Location{File: "main.go", Line: 10},
		},
		{
			RuleID:   "ANA001",
			Severity: fusa.SeverityWarning,
			Message:  "test warning",
			Location: fusa.Location{File: "foo.go", Line: 5},
		},
	}
	rep := report.New("/project", findings)
	var buf bytes.Buffer
	if err := report.Render(&buf, rep, "md"); err != nil {
		t.Fatalf("Render(md): %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "LINT001") {
		t.Errorf("expected LINT001 in output: %s", out)
	}
	if !strings.Contains(out, "## Findings") {
		t.Errorf("expected Findings section: %s", out)
	}
	if !strings.Contains(out, "| 1 |") {
		t.Errorf("expected error count 1 in summary: %s", out)
	}
}

//fusa:test REQ-REPORT-MD001
func TestRenderMarkdown_SILField(t *testing.T) {
	rep := report.New("/project", nil)
	rep.SIL = "SIL-2"
	rep.Standard = "IEC61508"
	var buf bytes.Buffer
	if err := report.Render(&buf, rep, "md"); err != nil {
		t.Fatalf("Render(md): %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "SIL-2") {
		t.Errorf("expected SIL-2 in output: %s", out)
	}
}

//fusa:test REQ-REPORT-MD001
func TestRenderMarkdown_DALField(t *testing.T) {
	rep := report.New("/project", nil)
	rep.DAL = "DAL-B"
	rep.Standard = "DO178C"
	var buf bytes.Buffer
	if err := report.Render(&buf, rep, "md"); err != nil {
		t.Fatalf("Render(md): %v", err)
	}
	if !strings.Contains(buf.String(), "DAL-B") {
		t.Errorf("expected DAL-B in output")
	}
}
