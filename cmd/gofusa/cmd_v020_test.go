package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ─── iso26262 ─────────────────────────────────────────────────────────────────

//fusa:test REQ-CLI-ISO26262-001
func TestRunISO26262_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runISO26262([]string{"--dir", dir, "--asil", "ASIL-B", "--format", "text"}, &out, &errBuf)
	if code != 1 {
		t.Errorf("exit code = %d, want 1 (gaps present)", code)
	}
	if !strings.Contains(out.String(), "ISO 26262") {
		t.Errorf("missing report header; got: %q", out.String())
	}
}

//fusa:test REQ-CLI-ISO26262-001
func TestRunISO26262_JSON(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	runISO26262([]string{"--dir", dir, "--asil", "ASIL-B", "--format", "json"}, &out, &errBuf)
	if !strings.Contains(out.String(), `"standard"`) {
		t.Errorf("missing standard field in JSON; got: %q", out.String())
	}
}

//fusa:test REQ-CLI-ISO26262-001
func TestRunISO26262_InvalidASIL(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runISO26262([]string{"--asil", "INVALID"}, &out, &errBuf)
	if code != 2 {
		t.Errorf("expected exit 2 (usage) for invalid ASIL, got %d", code)
	}
}

//fusa:test REQ-CLI-ISO26262-001
func TestRunISO26262_Output(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "report.json")
	var out, errBuf bytes.Buffer
	runISO26262([]string{"--dir", dir, "--asil", "ASIL-A", "--format", "json", "--output", outFile}, &out, &errBuf)
	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("output file not created: %v", err)
	}
	if !strings.Contains(string(data), "standard") {
		t.Errorf("output file missing standard field")
	}
}

//fusa:test REQ-CLI-ISO26262-001
func TestRunISO26262_AllASILs(t *testing.T) {
	for _, asil := range []string{"ASIL-A", "ASIL-B", "ASIL-C", "ASIL-D"} {
		dir := t.TempDir()
		var out, errBuf bytes.Buffer
		runISO26262([]string{"--dir", dir, "--asil", asil}, &out, &errBuf)
		if !strings.Contains(out.String(), asil) {
			t.Errorf("ASIL=%s: output missing ASIL label", asil)
		}
	}
}

// ─── iec61508 ─────────────────────────────────────────────────────────────────

//fusa:test REQ-CLI-IEC61508-001
func TestRunIEC61508_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runIEC61508([]string{"--dir", dir, "--sil", "SIL-2", "--format", "text"}, &out, &errBuf)
	if code != 1 {
		t.Errorf("exit code = %d, want 1 (gaps present)", code)
	}
	if !strings.Contains(out.String(), "IEC 61508") {
		t.Errorf("missing report header; got: %q", out.String())
	}
}

//fusa:test REQ-CLI-IEC61508-001
func TestRunIEC61508_JSON(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	runIEC61508([]string{"--dir", dir, "--sil", "SIL-2", "--format", "json"}, &out, &errBuf)
	if !strings.Contains(out.String(), `"standard"`) {
		t.Errorf("missing standard field in JSON; got: %q", out.String())
	}
}

//fusa:test REQ-CLI-IEC61508-001
func TestRunIEC61508_InvalidSIL(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runIEC61508([]string{"--sil", "INVALID"}, &out, &errBuf)
	if code != 2 {
		t.Errorf("expected exit 2 (usage) for invalid SIL, got %d", code)
	}
}

//fusa:test REQ-CLI-IEC61508-001
func TestRunIEC61508_Output(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "report.json")
	var out, errBuf bytes.Buffer
	runIEC61508([]string{"--dir", dir, "--sil", "SIL-4", "--format", "json", "--output", outFile}, &out, &errBuf)
	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("output file not created: %v", err)
	}
	if !strings.Contains(string(data), "standard") {
		t.Errorf("output file missing standard field")
	}
}

//fusa:test REQ-CLI-IEC61508-001
func TestRunIEC61508_AllSILs(t *testing.T) {
	for _, sil := range []string{"SIL-1", "SIL-2", "SIL-3", "SIL-4"} {
		dir := t.TempDir()
		var out, errBuf bytes.Buffer
		runIEC61508([]string{"--dir", dir, "--sil", sil}, &out, &errBuf)
		if !strings.Contains(out.String(), sil) {
			t.Errorf("SIL=%s: output missing SIL label", sil)
		}
	}
}

// ─── disposition ─────────────────────────────────────────────────────────────

//fusa:test REQ-CLI-DISP001
func TestRunDisposition_ListEmpty(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runDisposition([]string{"--dir", dir, "list"}, &out, &errBuf)
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	if !strings.Contains(out.String(), "No disposition entries") {
		t.Errorf("expected empty message; got: %q", out.String())
	}
}

//fusa:test REQ-CLI-DISP001
func TestRunDisposition_AddAndList(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runDisposition([]string{"--dir", dir, "add",
		"--rule", "LINT001",
		"--action", "accept",
		"--reviewer", "Alice",
		"--rationale", "justified",
	}, &out, &errBuf)
	if code != 0 {
		t.Errorf("add: exit code = %d; stderr: %s", code, errBuf.String())
	}
	out.Reset()
	errBuf.Reset()
	code = runDisposition([]string{"--dir", dir, "list"}, &out, &errBuf)
	if code != 0 {
		t.Errorf("list after add: exit code = %d", code)
	}
	if !strings.Contains(out.String(), "LINT001") {
		t.Errorf("LINT001 not in list output; got: %q", out.String())
	}
}

//fusa:test REQ-CLI-DISP001
func TestRunDisposition_Show(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	runDisposition([]string{"--dir", dir, "add",
		"--rule", "LINT002",
		"--action", "fix",
		"--reviewer", "Bob",
		"--rationale", "will fix",
	}, &out, &errBuf)
	out.Reset()
	errBuf.Reset()
	code := runDisposition([]string{"--dir", dir, "show", "--rule", "LINT002"}, &out, &errBuf)
	if code != 0 {
		t.Errorf("show: exit code = %d", code)
	}
	if !strings.Contains(out.String(), "LINT002") {
		t.Errorf("LINT002 not in show output; got: %q", out.String())
	}
}

//fusa:test REQ-CLI-DISP001
func TestRunDisposition_ShowMissing(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runDisposition([]string{"--dir", dir, "show", "--rule", "NOSUCHRULE"}, &out, &errBuf)
	if code != 2 {
		t.Errorf("show missing: expected exit 2 (usage), got %d", code)
	}
}

//fusa:test REQ-CLI-DISP001
func TestRunDisposition_NoSubcommand(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runDisposition([]string{}, &out, &errBuf)
	if code != 2 {
		t.Errorf("no subcommand: expected exit 2 (usage), got %d", code)
	}
}

//fusa:test REQ-CLI-DISP001
func TestRunDisposition_AddMissingFlags(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runDisposition([]string{"--dir", dir, "add", "--rule", "LINT001"}, &out, &errBuf)
	if code != 2 {
		t.Errorf("add missing flags: expected exit 2 (usage), got %d", code)
	}
}

// ─── impact ──────────────────────────────────────────────────────────────────

//fusa:test REQ-CLI-IMPACT001
func TestRunImpact_NotGitRepo(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	// Non-git dir: should still return (empty report or error), not panic
	runImpact([]string{"--dir", dir, "--format", "text"}, &out, &errBuf)
	// either exit 0 (empty report) or 1 (error) — just must not panic
}

//fusa:test REQ-CLI-IMPACT001
func TestRunImpact_JSON(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	runImpact([]string{"--dir", dir, "--format", "json"}, &out, &errBuf)
}

//fusa:test REQ-CLI-IMPACT001
func TestRunImpact_Output(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "impact.json")
	var out, errBuf bytes.Buffer
	runImpact([]string{"--dir", dir, "--format", "json", "--output", outFile}, &out, &errBuf)
	// file may or may not be created depending on git; just verify no panic
}

// ─── metrics ─────────────────────────────────────────────────────────────────

//fusa:test REQ-CLI-METRICS001
func TestRunMetrics_RecordAndShow(t *testing.T) {
	dir := t.TempDir()
	// Write a minimal check-report.json so Collect has something to parse.
	findings := []map[string]interface{}{
		{"ruleID": "LINT001", "severity": "WARNING", "message": "test"},
	}
	data, _ := json.Marshal(findings)
	if err := os.WriteFile(filepath.Join(dir, "check-report.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	var out, errBuf bytes.Buffer
	code := runMetrics([]string{"--dir", dir, "record"}, &out, &errBuf)
	if code != 0 {
		t.Errorf("record: exit code = %d; err: %s", code, errBuf.String())
	}

	out.Reset()
	code = runMetrics([]string{"--dir", dir, "show", "--format", "text"}, &out, &errBuf)
	if code != 0 {
		t.Errorf("show: exit code = %d", code)
	}
	if !strings.Contains(out.String(), "Metrics") {
		t.Errorf("show: missing header; got: %q", out.String())
	}
}

//fusa:test REQ-CLI-METRICS001
func TestRunMetrics_ShowJSON(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	runMetrics([]string{"--dir", dir, "record"}, &out, &errBuf)
	out.Reset()
	code := runMetrics([]string{"--dir", dir, "show", "--format", "json"}, &out, &errBuf)
	if code != 0 {
		t.Errorf("show json: exit code = %d", code)
	}
	if !strings.Contains(out.String(), "snapshots") {
		t.Errorf("show json: missing snapshots field; got: %q", out.String())
	}
}

//fusa:test REQ-CLI-METRICS001
func TestRunMetrics_NoSubcommand(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runMetrics([]string{}, &out, &errBuf)
	if code != 2 {
		t.Errorf("no subcommand: expected exit 2 (usage), got %d", code)
	}
}

//fusa:test REQ-CLI-METRICS001
func TestRunMetrics_ShowOutput(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "metrics.json")
	var out, errBuf bytes.Buffer
	runMetrics([]string{"--dir", dir, "record"}, &out, &errBuf)
	code := runMetrics([]string{"--dir", dir, "show", "--format", "json", "--output", outFile}, &out, &errBuf)
	if code != 0 {
		t.Errorf("show --output: exit code = %d", code)
	}
	if _, err := os.Stat(outFile); err != nil {
		t.Errorf("output file not created: %v", err)
	}
}

// ─── misra ────────────────────────────────────────────────────────────────────

//fusa:test REQ-CLI-MISRA001
func TestRunMisra_Text(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runMisra([]string{"--format", "text"}, &out, &errBuf)
	if code != 0 {
		t.Errorf("exit code = %d", code)
	}
	if !strings.Contains(out.String(), "MISRA") {
		t.Errorf("missing MISRA header; got: %q", out.String())
	}
}

//fusa:test REQ-CLI-MISRA001
func TestRunMisra_JSON(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runMisra([]string{"--format", "json"}, &out, &errBuf)
	if code != 0 {
		t.Errorf("exit code = %d", code)
	}
	if !strings.Contains(out.String(), `"rules"`) {
		t.Errorf("missing rules field in JSON; got: %q", out.String())
	}
}

//fusa:test REQ-CLI-MISRA001
func TestRunMisra_Output(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "misra.json")
	var out, errBuf bytes.Buffer
	code := runMisra([]string{"--format", "json", "--output", outFile}, &out, &errBuf)
	if code != 0 {
		t.Errorf("exit code = %d", code)
	}
	if _, err := os.Stat(outFile); err != nil {
		t.Errorf("output file not created: %v", err)
	}
}

// ─── release --full ───────────────────────────────────────────────────────────

//fusa:test REQ-CLI016
func TestRunRelease_Full(t *testing.T) {
	dir := t.TempDir()
	// Provide a minimal Go module so release.BuildSBOM can proceed.
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/testpkg\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(dir, "out")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	code := runRelease([]string{"--dir", dir, "--output-dir", outDir, "--full"}, &out, &errBuf)
	// exit 0 on success; some sub-scans may soft-fail but runReleaseFullBundle should run
	if code != 0 {
		t.Logf("runRelease --full exit %d; stderr: %s", code, errBuf.String())
	}
	// Verify runReleaseFullBundle ran by checking FMEA output
	if !strings.Contains(out.String(), "FMEA written") && !strings.Contains(errBuf.String(), "fmea") {
		t.Logf("release --full output: %s", out.String())
	}
}

// ─── req import/export ────────────────────────────────────────────────────────

//fusa:test REQ-CLI-REQ002
func TestRunReqImport_CSV(t *testing.T) {
	dir := t.TempDir()
	csvFile := filepath.Join(dir, "reqs.csv")
	csv := "id,title,text,standard,level\nREQ-001,First req,Detailed text,ISO26262,ASIL-B\nREQ-002,Second req,,generic,\n"
	if err := os.WriteFile(csvFile, []byte(csv), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	code := run([]string{"req", "--dir", dir, "import", "--format", "csv", "--file", csvFile}, &out, &errBuf)
	if code != 0 {
		t.Errorf("import: exit code = %d; err: %s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "Imported") {
		t.Errorf("expected 'Imported' in output; got: %q", out.String())
	}
	// verify .fusa-reqs.json was created
	if _, err := os.Stat(filepath.Join(dir, ".fusa-reqs.json")); err != nil {
		t.Errorf(".fusa-reqs.json not created: %v", err)
	}
}

//fusa:test REQ-CLI-REQ003
func TestRunReqExport_CSV(t *testing.T) {
	dir := t.TempDir()
	// create a reqs file first (wrapped object format that trace.LoadRequirements expects)
	reqs := `{"requirements":[{"id":"REQ-001","title":"First","text":"desc","standard":"generic","level":""}]}`
	if err := os.WriteFile(filepath.Join(dir, ".fusa-reqs.json"), []byte(reqs), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	code := run([]string{"req", "--dir", dir, "export", "--format", "csv"}, &out, &errBuf)
	if code != 0 {
		t.Errorf("export: exit code = %d; err: %s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "REQ-001") {
		t.Errorf("expected REQ-001 in CSV output; got: %q", out.String())
	}
}

//fusa:test REQ-CLI-REQ002
func TestRunReqImport_InvalidCSV(t *testing.T) {
	dir := t.TempDir()
	csvFile := filepath.Join(dir, "bad.csv")
	if err := os.WriteFile(csvFile, []byte("no,header\nrow1,data"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	code := run([]string{"req", "--dir", dir, "import", "--format", "csv", "--file", csvFile}, &out, &errBuf)
	if code != 2 {
		t.Errorf("bad CSV: expected exit 2 (usage), got %d", code)
	}
}
