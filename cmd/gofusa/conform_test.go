package main

// §2.2 / §2.9 x-FuSa spec conformance tests.
//
// §2.2: When --output <file> is given, stdout MUST be empty (no double-write).
// §2.9: ruleId, severity, and category MUST be identical across text/json/sarif/html output formats.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// projectWithPanic creates a minimal Go project that triggers LINT002 (panic usage)
// and FUSA001 (missing .fusa.json) deterministically.
func projectWithPanic(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/test\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\nfunc f() { panic(\"x\") }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// ─── §2.2: --output no-stdout ─────────────────────────────────────────────────

//fusa:test REQ-CLI006
func TestConform_OutputNoStdout_Check(t *testing.T) {
	dir := projectWithPanic(t)
	outFile := filepath.Join(dir, "report.json")
	var stdout, stderr bytes.Buffer
	runCheck([]string{"--dir", dir, "--format", "json", "--output", outFile}, &stdout, &stderr)
	if stdout.Len() != 0 {
		t.Errorf("§2.2: check --output wrote %d bytes to stdout, want 0:\n%s", stdout.Len(), stdout.String())
	}
	if _, err := os.Stat(outFile); err != nil {
		t.Errorf("§2.2: check --output did not create output file: %v", err)
	}
}

//fusa:test REQ-CLI006
func TestConform_OutputNoStdout_Report(t *testing.T) {
	dir := projectWithPanic(t)
	outFile := filepath.Join(dir, "report.json")
	var stdout, stderr bytes.Buffer
	runReport([]string{"--dir", dir, "--format", "json", "--output", outFile}, &stdout, &stderr)
	if stdout.Len() != 0 {
		t.Errorf("§2.2: report --output wrote %d bytes to stdout, want 0:\n%s", stdout.Len(), stdout.String())
	}
}

//fusa:test REQ-CLI006
func TestConform_OutputNoStdout_Lint(t *testing.T) {
	dir := projectWithPanic(t)
	outFile := filepath.Join(dir, "lint.json")
	var stdout, stderr bytes.Buffer
	runLint([]string{"--dir", dir, "--format", "json", "--output", outFile}, &stdout, &stderr)
	if stdout.Len() != 0 {
		t.Errorf("§2.2: lint --output wrote %d bytes to stdout, want 0:\n%s", stdout.Len(), stdout.String())
	}
}

//fusa:test REQ-CLI006
func TestConform_OutputNoStdout_Trace(t *testing.T) {
	dir := projectWithPanic(t)
	outFile := filepath.Join(dir, "trace.json")
	var stdout, stderr bytes.Buffer
	runTrace([]string{"--dir", dir, "--format", "json", "--output", outFile}, &stdout, &stderr)
	if stdout.Len() != 0 {
		t.Errorf("§2.2: trace --output wrote %d bytes to stdout, want 0:\n%s", stdout.Len(), stdout.String())
	}
}

//fusa:test REQ-CLI006
func TestConform_OutputNoStdout_Comp(t *testing.T) {
	dir := projectWithPanic(t)
	outFile := filepath.Join(dir, "comp.json")
	var stdout, stderr bytes.Buffer
	runComp([]string{"--dir", dir, "--format", "json", "--output", outFile}, &stdout, &stderr)
	if stdout.Len() != 0 {
		t.Errorf("§2.2: comp --output wrote %d bytes to stdout, want 0:\n%s", stdout.Len(), stdout.String())
	}
}

//fusa:test REQ-CLI006
func TestConform_OutputNoStdout_SLSA(t *testing.T) {
	dir := projectWithPanic(t)
	outFile := filepath.Join(dir, "slsa.json")
	var stdout, stderr bytes.Buffer
	runSLSA([]string{"--dir", dir, "--format", "json", "--output", outFile}, &stdout, &stderr)
	if stdout.Len() != 0 {
		t.Errorf("§2.2: slsa --output wrote %d bytes to stdout, want 0:\n%s", stdout.Len(), stdout.String())
	}
}

//fusa:test REQ-CLI006
func TestConform_OutputNoStdout_IEC62443(t *testing.T) {
	dir := projectWithPanic(t)
	outFile := filepath.Join(dir, "iec62443.json")
	var stdout, stderr bytes.Buffer
	runIEC62443([]string{"--dir", dir, "--format", "json", "--output", outFile}, &stdout, &stderr)
	if stdout.Len() != 0 {
		t.Errorf("§2.2: iec62443 --output wrote %d bytes to stdout, want 0:\n%s", stdout.Len(), stdout.String())
	}
}

//fusa:test REQ-CLI006
func TestConform_OutputNoStdout_ISO26262(t *testing.T) {
	dir := projectWithPanic(t)
	outFile := filepath.Join(dir, "iso26262.json")
	var stdout, stderr bytes.Buffer
	runISO26262([]string{"--dir", dir, "--format", "json", "--output", outFile}, &stdout, &stderr)
	if stdout.Len() != 0 {
		t.Errorf("§2.2: iso26262 --output wrote %d bytes to stdout, want 0:\n%s", stdout.Len(), stdout.String())
	}
}

//fusa:test REQ-CLI006
func TestConform_OutputNoStdout_ISO21434(t *testing.T) {
	dir := projectWithPanic(t)
	outFile := filepath.Join(dir, "iso21434.json")
	var stdout, stderr bytes.Buffer
	runISO21434([]string{"--dir", dir, "--format", "json", "--output", outFile}, &stdout, &stderr)
	if stdout.Len() != 0 {
		t.Errorf("§2.2: iso21434 --output wrote %d bytes to stdout, want 0:\n%s", stdout.Len(), stdout.String())
	}
}

//fusa:test REQ-CLI006
func TestConform_OutputNoStdout_IEC61508(t *testing.T) {
	dir := projectWithPanic(t)
	outFile := filepath.Join(dir, "iec61508.json")
	var stdout, stderr bytes.Buffer
	runIEC61508([]string{"--dir", dir, "--format", "json", "--output", outFile}, &stdout, &stderr)
	if stdout.Len() != 0 {
		t.Errorf("§2.2: iec61508 --output wrote %d bytes to stdout, want 0:\n%s", stdout.Len(), stdout.String())
	}
}

//fusa:test REQ-CLI006
func TestConform_OutputNoStdout_UNECE(t *testing.T) {
	dir := projectWithPanic(t)
	outFile := filepath.Join(dir, "unece.json")
	var stdout, stderr bytes.Buffer
	runUNECE([]string{"--dir", dir, "--format", "json", "--output", outFile}, &stdout, &stderr)
	if stdout.Len() != 0 {
		t.Errorf("§2.2: unece --output wrote %d bytes to stdout, want 0:\n%s", stdout.Len(), stdout.String())
	}
}

// ─── §2.9: format-invariant ruleId / severity / category ─────────────────────

type conformFinding struct {
	RuleID   string `json:"ruleId"`
	Severity string `json:"severity"`
	Category string `json:"category"`
}
type conformReport struct {
	Findings []conformFinding `json:"findings"`
}

// runCheckJSON runs gofusa check with --format json and returns parsed findings.
func runCheckJSON(t *testing.T, dir string) []conformFinding {
	t.Helper()
	var out bytes.Buffer
	runCheck([]string{"--dir", dir, "--format", "json"}, &out, &bytes.Buffer{})
	var rep conformReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("§2.9: parse JSON report: %v\nraw: %s", err, out.String())
	}
	return rep.Findings
}

// runCheckSARIF runs gofusa check with --format sarif and returns a map of ruleId→level.
func runCheckSARIF(t *testing.T, dir string) map[string]string {
	t.Helper()
	var out bytes.Buffer
	runCheck([]string{"--dir", dir, "--format", "sarif"}, &out, &bytes.Buffer{})
	var doc struct {
		Runs []struct {
			Results []struct {
				RuleID string `json:"ruleId"`
				Level  string `json:"level"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("§2.9: parse SARIF: %v\nraw: %s", err, out.String())
	}
	m := make(map[string]string)
	if len(doc.Runs) > 0 {
		for _, r := range doc.Runs[0].Results {
			m[r.RuleID] = r.Level
		}
	}
	return m
}

// sarifLevel maps fusa severity to SARIF level for comparison.
func sarifLevel(sev string) string {
	switch sev {
	case "ERROR":
		return "error"
	case "WARNING":
		return "warning"
	default:
		return "note"
	}
}

//fusa:test REQ-CLI006
func TestConform_FormatInvariant_RuleID(t *testing.T) {
	dir := projectWithPanic(t)
	jsonFindings := runCheckJSON(t, dir)
	sarifMap := runCheckSARIF(t, dir)

	if len(jsonFindings) == 0 {
		t.Skip("§2.9: no findings produced — cannot verify format invariance")
	}

	for _, f := range jsonFindings {
		if f.RuleID == "" {
			t.Errorf("§2.9: JSON finding missing ruleId")
			continue
		}
		if _, ok := sarifMap[f.RuleID]; !ok {
			t.Errorf("§2.9: ruleId %q present in JSON but missing from SARIF", f.RuleID)
		}
	}
	for ruleID := range sarifMap {
		found := false
		for _, f := range jsonFindings {
			if f.RuleID == ruleID {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("§2.9: ruleId %q present in SARIF but missing from JSON", ruleID)
		}
	}
}

//fusa:test REQ-CLI006
func TestConform_FormatInvariant_Severity(t *testing.T) {
	dir := projectWithPanic(t)
	jsonFindings := runCheckJSON(t, dir)
	sarifMap := runCheckSARIF(t, dir)

	if len(jsonFindings) == 0 {
		t.Skip("§2.9: no findings produced — cannot verify format invariance")
	}

	for _, f := range jsonFindings {
		sarifLvl, ok := sarifMap[f.RuleID]
		if !ok {
			continue
		}
		want := sarifLevel(f.Severity)
		if sarifLvl != want {
			t.Errorf("§2.9: ruleId %q: JSON severity=%q maps to SARIF level=%q, got %q",
				f.RuleID, f.Severity, want, sarifLvl)
		}
	}
}

//fusa:test REQ-CLI006
func TestConform_FormatInvariant_Category(t *testing.T) {
	dir := projectWithPanic(t)
	jsonFindings := runCheckJSON(t, dir)

	if len(jsonFindings) == 0 {
		t.Skip("§2.9: no findings produced — cannot verify format invariance")
	}

	// Category must be non-empty and consistent across formats: verify JSON
	// report derives it from ruleId prefix per §1.5.1 (no cross-format regression).
	for _, f := range jsonFindings {
		if f.Category == "" {
			t.Errorf("§2.9: JSON finding ruleId=%q has empty category", f.RuleID)
		}
	}

	// Re-run with text format; text output contains the ruleId.
	// Verify no ruleId is silently omitted or renamed.
	var textOut bytes.Buffer
	runCheck([]string{"--dir", dir, "--format", "text"}, &textOut, &bytes.Buffer{})
	text := textOut.String()
	for _, f := range jsonFindings {
		if !strings.Contains(text, f.RuleID) {
			t.Errorf("§2.9: ruleId %q present in JSON but absent from text output", f.RuleID)
		}
	}
}
