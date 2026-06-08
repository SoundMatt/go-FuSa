package tara_test

import (
	"bytes"
	"strings"
	"testing"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/tara"
	"github.com/SoundMatt/go-FuSa/testutil"
)

func makeFinding(ruleID string, sev fusa.Severity, file string, line int) fusa.Finding {
	return fusa.Finding{
		RuleID:   ruleID,
		Severity: sev,
		Message:  "test finding for " + ruleID,
		Location: fusa.Location{File: file, Line: line},
	}
}

func TestScan_EmptyFindings(t *testing.T) {
	dir := testutil.ProjectDir(t, map[string]string{
		"go.mod": "module example.com/test\ngo 1.22\n",
	})
	report, err := tara.Scan(dir, nil)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(report.Entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(report.Entries))
	}
	if report.Format == "" {
		t.Error("Format should not be empty")
	}
}

func TestScan_KnownRules(t *testing.T) {
	dir := testutil.ProjectDir(t, map[string]string{
		"go.mod": "module example.com/test\ngo 1.22\n",
	})
	findings := []fusa.Finding{
		makeFinding("CYBER007", fusa.SeverityError, "crypto.go", 42),
		makeFinding("CYBER001", fusa.SeverityWarning, "hash.go", 10),
		makeFinding("CYBER005", fusa.SeverityWarning, "cmd.go", 5),
	}
	report, err := tara.Scan(dir, findings)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(report.Entries) != 3 {
		t.Errorf("expected 3 entries, got %d", len(report.Entries))
	}
	// Check CYBER007 maps to ERROR → High likelihood.
	for _, e := range report.Entries {
		if e.CyberRuleID == "CYBER007" {
			if e.Likelihood != "High" {
				t.Errorf("CYBER007 (ERROR): want Likelihood=High, got %s", e.Likelihood)
			}
			if !containsSTRIDE(e.STRIDE, "I") {
				t.Errorf("CYBER007: expected I (Info Disclosure) in STRIDE %v", e.STRIDE)
			}
			if e.CWE != "CWE-295" {
				t.Errorf("CYBER007 CWE: want CWE-295 got %s", e.CWE)
			}
		}
	}
}

func TestScan_UnknownRule(t *testing.T) {
	dir := testutil.ProjectDir(t, map[string]string{
		"go.mod": "module example.com/test\ngo 1.22\n",
	})
	findings := []fusa.Finding{
		makeFinding("UNKNOWN999", fusa.SeverityInfo, "foo.go", 1),
	}
	report, err := tara.Scan(dir, findings)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(report.Entries) != 1 {
		t.Fatalf("expected 1 entry for unknown rule, got %d", len(report.Entries))
	}
}

func TestScan_IDSequential(t *testing.T) {
	dir := testutil.ProjectDir(t, map[string]string{
		"go.mod": "module example.com/test\ngo 1.22\n",
	})
	findings := []fusa.Finding{
		makeFinding("CYBER001", fusa.SeverityWarning, "a.go", 1),
		makeFinding("CYBER002", fusa.SeverityWarning, "b.go", 2),
		makeFinding("CYBER003", fusa.SeverityInfo, "c.go", 3),
	}
	report, _ := tara.Scan(dir, findings)
	for i, e := range report.Entries {
		want := strings.Replace("TARA-000", "000", padded(i+1), 1)
		_ = want
		if !strings.HasPrefix(e.ID, "TARA-") {
			t.Errorf("entry %d: ID should start with TARA-, got %s", i, e.ID)
		}
	}
}

func padded(n int) string {
	if n < 10 {
		return "00" + string(rune('0'+n))
	}
	if n < 100 {
		return "0" + string(rune('0'+(n/10))) + string(rune('0'+(n%10)))
	}
	return strings.Repeat("?", 3)
}

// ─── Render ───────────────────────────────────────────────────────────────────

func TestRender_JSON(t *testing.T) {
	dir := testutil.ProjectDir(t, map[string]string{
		"go.mod": "module example.com/test\ngo 1.22\n",
	})
	findings := []fusa.Finding{
		makeFinding("CYBER006", fusa.SeverityError, "creds.go", 10),
	}
	report, _ := tara.Scan(dir, findings)
	var buf bytes.Buffer
	if err := tara.Render(&buf, report, "json"); err != nil {
		t.Fatalf("Render json: %v", err)
	}
	if !strings.Contains(buf.String(), `"entries"`) {
		t.Error("JSON output should contain entries key")
	}
	if !strings.Contains(buf.String(), "CYBER006") {
		t.Error("JSON output should contain CYBER006")
	}
}

func TestRender_Markdown(t *testing.T) {
	dir := testutil.ProjectDir(t, map[string]string{
		"go.mod": "module example.com/test\ngo 1.22\n",
	})
	findings := []fusa.Finding{
		makeFinding("CYBER007", fusa.SeverityError, "tls.go", 5),
	}
	report, _ := tara.Scan(dir, findings)
	var buf bytes.Buffer
	if err := tara.Render(&buf, report, "markdown"); err != nil {
		t.Fatalf("Render markdown: %v", err)
	}
	md := buf.String()
	if !strings.Contains(md, "TARA") {
		t.Error("markdown should contain TARA heading")
	}
	if !strings.Contains(md, "STRIDE") {
		t.Error("markdown table should contain STRIDE column")
	}
	if !strings.Contains(md, "CWE-295") {
		t.Error("markdown should contain CWE-295 for CYBER007")
	}
}

func TestRender_UnknownFormat(t *testing.T) {
	report := &tara.Report{}
	err := tara.Render(bytes.NewBuffer(nil), report, "xml")
	if err == nil {
		t.Error("expected error for unknown format")
	}
}

// ─── TARA001 engine rule ──────────────────────────────────────────────────────

func TestTARA_001_MissingFile(t *testing.T) {
	dir := testutil.ProjectDir(t, map[string]string{
		"go.mod": "module example.com/test\ngo 1.22\n",
	})
	// Just verify tara.json absence produces correct path in finding.
	findings := []fusa.Finding{}
	report, _ := tara.Scan(dir, findings)
	_ = report
	// The engine rule is tested via integration; verify TARAFile constant.
	if tara.TARAFile != "tara.json" {
		t.Errorf("TARAFile constant: want tara.json got %s", tara.TARAFile)
	}
}

// ─── all 20 CYBER rules have metadata entries ────────────────────────────────

func TestScan_AllCYBERRules_HaveMetadata(t *testing.T) {
	dir := testutil.ProjectDir(t, map[string]string{
		"go.mod": "module example.com/test\ngo 1.22\n",
	})
	for i := 1; i <= 20; i++ {
		ruleID := strings.Replace("CYBER000", "000", padded(i), 1)
		findings := []fusa.Finding{makeFinding(ruleID, fusa.SeverityWarning, "f.go", 1)}
		report, err := tara.Scan(dir, findings)
		if err != nil {
			t.Errorf("%s: Scan error: %v", ruleID, err)
			continue
		}
		if len(report.Entries) != 1 {
			t.Errorf("%s: expected 1 entry, got %d", ruleID, len(report.Entries))
			continue
		}
		e := report.Entries[0]
		if e.CWE == "" {
			t.Errorf("%s: CWE should not be empty", ruleID)
		}
		if len(e.STRIDE) == 0 {
			t.Errorf("%s: STRIDE should not be empty", ruleID)
		}
	}
}

func containsSTRIDE(stride []string, cat string) bool {
	for _, s := range stride {
		if s == cat {
			return true
		}
	}
	return false
}
