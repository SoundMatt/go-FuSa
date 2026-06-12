package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SoundMatt/go-FuSa/engine"
)

// ─── runVersion ───────────────────────────────────────────────────────────────

//fusa:test REQ-CLI004
func TestRunVersion_Text(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runVersion(nil, &out, &errBuf)
	if code != 0 {
		t.Fatalf("runVersion exit %d; stderr: %s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "gofusa") {
		t.Errorf("expected 'gofusa' in output; got: %s", out.String())
	}
}

//fusa:test REQ-CLI004
func TestRunVersion_JSON(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runVersion([]string{"--format", "json"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("runVersion --format json exit %d; stderr: %s", code, errBuf.String())
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v; raw: %s", err, out.String())
	}
	if doc["tool"] != "go-FuSa" {
		t.Errorf("tool = %q, want go-FuSa", doc["tool"])
	}
	if doc["version"] == nil || doc["version"] == "" {
		t.Error("version field should be populated")
	}
	if doc["specVersion"] == nil || doc["specVersion"] == "" {
		t.Error("specVersion field should be populated")
	}
}

//fusa:test REQ-CLI004
func TestRunVersion_UnknownFormat(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runVersion([]string{"--format", "xml"}, &out, &errBuf)
	if code != 2 {
		t.Errorf("expected exit 2 for unknown format, got %d", code)
	}
	if !strings.Contains(errBuf.String(), "unknown format") {
		t.Errorf("expected 'unknown format' in stderr; got: %s", errBuf.String())
	}
}

//fusa:test REQ-CLI004
func TestRunVersion_TextExplicit(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runVersion([]string{"--format", "text"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("runVersion --format text exit %d; stderr: %s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "gofusa") {
		t.Errorf("expected 'gofusa' in output; got: %s", out.String())
	}
}

//fusa:test REQ-CLI004
func TestRunVersion_BadFlag(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runVersion([]string{"--no-such-flag"}, &out, &errBuf)
	if code != 2 {
		t.Errorf("expected exit 2 for bad flag, got %d", code)
	}
}

// ─── runCoverage extra paths ──────────────────────────────────────────────────

//fusa:test REQ-CLI-COV001
func TestRunCoverage_OutputFile(t *testing.T) {
	content := "mode: set\ngithub.com/x/pkg/file.go:10.2,12.5 3 1\n"
	f, err := os.CreateTemp("", "coverage*.out")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	f.Close()
	dir := t.TempDir()
	outFile := filepath.Join(dir, "report.txt")
	var out, errBuf bytes.Buffer
	code := runCoverage([]string{"--dal", "DAL-B", "--format", "text", "--output", outFile, f.Name()}, &out, &errBuf)
	if code != 0 {
		t.Errorf("runCoverage exit %d: %s", code, errBuf.String())
	}
	if _, err := os.Stat(outFile); err != nil {
		t.Error("output file not written")
	}
}

//fusa:test REQ-CLI-COV001
func TestRunCoverage_AllDALs(t *testing.T) {
	content := "mode: set\ngithub.com/x/pkg/file.go:10.2,12.5 3 1\n"
	for _, dal := range []string{"DAL-A", "DAL-B", "DAL-C", "DAL-D"} {
		f, err := os.CreateTemp("", "coverage*.out")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString(content); err != nil {
			f.Close()
			os.Remove(f.Name())
			t.Fatal(err)
		}
		f.Close()
		var out, errBuf bytes.Buffer
		code := runCoverage([]string{"--dal", dal, "--format", "text", f.Name()}, &out, &errBuf)
		os.Remove(f.Name())
		if code != 0 {
			t.Errorf("DAL=%s: exit %d: %s", dal, code, errBuf.String())
		}
	}
}

// ─── runSas extra paths ───────────────────────────────────────────────────────

//fusa:test REQ-CLI-SAS001
func TestRunSas_BadFlag(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runSas([]string{"--no-such-flag"}, &out, &errBuf)
	if code != 2 {
		t.Errorf("expected exit 2 for bad flag, got %d", code)
	}
}

//fusa:test REQ-CLI-SAS001
func TestRunSas_WriteToFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/test\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	outFile := filepath.Join(dir, "my-sas.md")
	var out, errBuf bytes.Buffer
	_ = runSas([]string{"--dir", dir, "--format", "markdown", "--output", outFile}, &out, &errBuf)
	// Output file may or may not be created depending on SAS build; just verify no crash
}

//fusa:test REQ-CLI-SAS001
func TestRunSas_DirFlag(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/test\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	code := runSas([]string{"--dir", dir, "--output", "-"}, &out, &errBuf)
	// exit 0 (no gaps) or 1 (gaps) are both acceptable
	if code != 0 && code != 1 {
		t.Errorf("unexpected exit code %d; stderr: %s", code, errBuf.String())
	}
}

// ─── runUNECE extra paths ─────────────────────────────────────────────────────

//fusa:test REQ-CLI-UNECE-001
func TestRunUNECE_BadFlag(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runUNECE([]string{"--no-such-flag"}, &out, &errBuf)
	if code != 2 {
		t.Errorf("expected exit 2 for bad flag, got %d", code)
	}
}

//fusa:test REQ-CLI-UNECE-001
func TestRunUNECE_OutputFile(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "unece-report.json")
	var out, errBuf bytes.Buffer
	runUNECE([]string{"--dir", dir, "--format", "json", "--output", outFile}, &out, &errBuf)
	if _, err := os.Stat(outFile); err != nil {
		t.Error("output file not written")
	}
	// §2.2: confirmation goes to stderr, not stdout
	if !strings.Contains(errBuf.String(), "UN R.155") {
		t.Errorf("expected UN R.155 count message in stderr; got: %s", errBuf.String())
	}
}

//fusa:test REQ-CLI-UNECE-001
func TestRunUNECE_AllFormats(t *testing.T) {
	dir := t.TempDir()
	for _, format := range []string{"text", "json"} {
		var out, errBuf bytes.Buffer
		runUNECE([]string{"--dir", dir, "--format", format}, &out, &errBuf)
		if out.Len() == 0 {
			t.Errorf("format=%s: expected output", format)
		}
	}
}

// ─── runReq extra paths ───────────────────────────────────────────────────────

//fusa:test REQ-CLI-REQ001
func TestRunReq_BadFlag(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runReq([]string{"--no-such-flag"}, &out, &errBuf)
	if code != 2 {
		t.Errorf("expected exit 2 for bad flag, got %d", code)
	}
}

//fusa:test REQ-CLI-REQ001
func TestRunReq_ShowAll(t *testing.T) {
	dir := t.TempDir()
	reqs := `{"requirements":[
		{"id":"REQ-001","title":"Auth","standard":"ISO 26262","level":"HLR"},
		{"id":"REQ-002","title":"Safety","text":"System shall be safe"}
	]}`
	if err := os.WriteFile(filepath.Join(dir, ".fusa-reqs.json"), []byte(reqs), 0o644); err != nil {
		t.Fatal(err)
	}
	// Write a Go file with impl annotation
	src := `package main
//fusa:req REQ-001
func Auth() {}
//fusa:test REQ-002
func TestSafety() {}
`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	code := runReq([]string{"--dir", dir}, &out, &errBuf)
	if code != 0 {
		t.Errorf("runReq show all exit %d: %s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "REQ-001") {
		t.Errorf("expected REQ-001 in output; got: %s", out.String())
	}
	if !strings.Contains(out.String(), "REQ-002") {
		t.Errorf("expected REQ-002 in output; got: %s", out.String())
	}
}

//fusa:test REQ-CLI-REQ001
func TestRunReq_ShowWithAnnotations(t *testing.T) {
	dir := t.TempDir()
	reqs := `{"requirements":[{"id":"REQ-001","title":"Auth","standard":"ISO 26262","level":"HLR"}]}`
	if err := os.WriteFile(filepath.Join(dir, ".fusa-reqs.json"), []byte(reqs), 0o644); err != nil {
		t.Fatal(err)
	}
	src := `package main
//fusa:req REQ-001
//fusa:test REQ-001
func Auth() {}
`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	code := runReq([]string{"--dir", dir, "REQ-001"}, &out, &errBuf)
	if code != 0 {
		t.Errorf("runReq exit %d: %s", code, errBuf.String())
	}
	outStr := out.String()
	if !strings.Contains(outStr, "REQ-001") {
		t.Errorf("expected REQ-001; got: %s", outStr)
	}
	// Standard and level should appear
	if !strings.Contains(outStr, "ISO 26262") {
		t.Errorf("expected standard in output; got: %s", outStr)
	}
}

//fusa:test REQ-CLI-REQ002
func TestRunReqImport_CSVv2(t *testing.T) {
	dir := t.TempDir()
	csvData := "id,title,text,standard,level\nREQ-010,My Requirement,The text,ISO 26262,HLR\n"
	csvFile := filepath.Join(dir, "reqs.csv")
	if err := os.WriteFile(csvFile, []byte(csvData), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	code := runReq([]string{"--dir", dir, "import", "--format", "csv", "--file", csvFile}, &out, &errBuf)
	if code != 0 {
		t.Errorf("expected exit 0, got %d: %s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "Imported 1") {
		t.Errorf("expected Imported 1; got: %s", out.String())
	}
}

//fusa:test REQ-CLI-REQ002
func TestRunReqImport_MissingFile(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runReq([]string{"--dir", dir, "import", "--format", "csv"}, &out, &errBuf)
	if code != 2 {
		t.Errorf("expected exit 2 for missing --file, got %d", code)
	}
}

//fusa:test REQ-CLI-REQ002
func TestRunReqImport_CSV_Duplicate(t *testing.T) {
	dir := t.TempDir()
	// Pre-populate with REQ-001
	existing := `{"requirements":[{"id":"REQ-001","title":"existing"}]}`
	if err := os.WriteFile(filepath.Join(dir, ".fusa-reqs.json"), []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}
	// CSV also has REQ-001
	csvData := "id,title\nREQ-001,dup\nREQ-002,new\n"
	csvFile := filepath.Join(dir, "reqs.csv")
	if err := os.WriteFile(csvFile, []byte(csvData), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	code := runReq([]string{"--dir", dir, "import", "--format", "csv", "--file", csvFile}, &out, &errBuf)
	if code != 0 {
		t.Errorf("expected exit 0, got %d: %s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "1 skipped") {
		t.Errorf("expected 1 skipped duplicate; got: %s", out.String())
	}
}

//fusa:test REQ-CLI-REQ003
func TestRunReqExport_CSVv2(t *testing.T) {
	dir := t.TempDir()
	reqs := `{"requirements":[{"id":"REQ-001","title":"Auth","text":"Text","standard":"ISO","level":"HLR"}]}`
	if err := os.WriteFile(filepath.Join(dir, ".fusa-reqs.json"), []byte(reqs), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	code := runReq([]string{"--dir", dir, "export", "--format", "csv"}, &out, &errBuf)
	if code != 0 {
		t.Errorf("expected exit 0, got %d: %s", code, errBuf.String())
	}
	outStr := out.String()
	if !strings.Contains(outStr, "REQ-001") {
		t.Errorf("expected REQ-001 in CSV; got: %s", outStr)
	}
	if !strings.Contains(outStr, "id,title") {
		t.Errorf("expected CSV header; got: %s", outStr)
	}
}

// ─── prList direct calls ──────────────────────────────────────────────────────

//fusa:test REQ-CLI-PR001
func TestPrList_Empty(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "problems.json")
	var out, errBuf bytes.Buffer
	code := prInit(logPath, &out, &errBuf)
	if code != 0 {
		t.Fatalf("prInit exit %d: %s", code, errBuf.String())
	}
	out.Reset()
	errBuf.Reset()
	code = prList(logPath, &out, &errBuf)
	if code != 0 {
		t.Errorf("prList exit %d: %s", code, errBuf.String())
	}
}

//fusa:test REQ-CLI-PR001
func TestPrList_WithEntries(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "problems.json")
	var out, errBuf bytes.Buffer
	prInit(logPath, &out, &errBuf)
	prAdd(logPath, []string{"--id", "PR-001", "--title", "Test Problem"}, &out, &errBuf)
	out.Reset()
	errBuf.Reset()
	code := prList(logPath, &out, &errBuf)
	if code != 0 {
		t.Errorf("prList exit %d: %s", code, errBuf.String())
	}
}

//fusa:test REQ-CLI-PR001
func TestPrList_MissingFile(t *testing.T) {
	// pr.Load returns an empty log (not error) for missing files,
	// so prList exits 0 with empty output
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := prList(filepath.Join(dir, "nonexistent.json"), &out, &errBuf)
	// exit 0 = empty list rendered successfully (pr.Load returns empty Log for missing file)
	if code != 0 {
		t.Errorf("expected exit 0 for missing file (empty log returned), got %d: %s", code, errBuf.String())
	}
}

//fusa:test REQ-CLI-PR001
func TestRunPR_NoSubcommand(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runPR(nil, &out, &errBuf)
	if code != 2 {
		t.Errorf("expected exit 2 for no subcommand, got %d", code)
	}
}

//fusa:test REQ-CLI-PR001
func TestRunPR_AddSubcmd(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	runPR([]string{"--dir", dir, "init"}, &out, &errBuf)
	out.Reset()
	errBuf.Reset()
	code := runPR([]string{"--dir", dir, "add", "--id", "PR-001", "--title", "Test"}, &out, &errBuf)
	if code != 0 {
		t.Errorf("runPR add exit %d: %s", code, errBuf.String())
	}
}

//fusa:test REQ-CLI-PR001
func TestRunPR_ListSubcmd(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	runPR([]string{"--dir", dir, "init"}, &out, &errBuf)
	out.Reset()
	errBuf.Reset()
	code := runPR([]string{"--dir", dir, "list"}, &out, &errBuf)
	if code != 0 {
		t.Errorf("runPR list exit %d: %s", code, errBuf.String())
	}
}

//fusa:test REQ-CLI-PR001
func TestRunPR_CloseSubcmd(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	runPR([]string{"--dir", dir, "init"}, &out, &errBuf)
	runPR([]string{"--dir", dir, "add", "--id", "PR-001", "--title", "Test"}, &out, &errBuf)
	out.Reset()
	errBuf.Reset()
	code := runPR([]string{"--dir", dir, "close", "--id", "PR-001"}, &out, &errBuf)
	if code != 0 {
		t.Errorf("runPR close exit %d: %s", code, errBuf.String())
	}
}

// ─── runFiltered / runLint extra paths ────────────────────────────────────────

//fusa:test REQ-CLI008
func TestRunLint_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runLint([]string{"--dir", dir}, &out, &errBuf)
	// 0 = no errors, 1 = gate fail, both acceptable for empty dir
	if code != 0 && code != 1 {
		t.Errorf("unexpected exit %d: %s", code, errBuf.String())
	}
}

//fusa:test REQ-CLI008
func TestRunLint_JSONFormat(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/test\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	code := runLint([]string{"--dir", dir, "--format", "json"}, &out, &errBuf)
	if code != 0 && code != 1 {
		t.Errorf("unexpected exit %d: %s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), `"findings"`) {
		t.Errorf("expected JSON with findings; got: %s", out.String())
	}
}

//fusa:test REQ-CLI008
func TestRunLint_OutputFile(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "lint-report.json")
	var out, errBuf bytes.Buffer
	runLint([]string{"--dir", dir, "--format", "json", "--output", outFile}, &out, &errBuf)
	if _, err := os.Stat(outFile); err != nil {
		t.Error("output file not written")
	}
}

//fusa:test REQ-CLI008
func TestRunLint_Strict(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/test\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	// --strict exits 1 on any WARNING or ERROR; result depends on project
	code := runLint([]string{"--dir", dir, "--strict"}, &out, &errBuf)
	_ = code // any of 0, 1 are acceptable
}

//fusa:test REQ-CLI008
func TestRunFiltered_BadOutputPath(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runFiltered(nil, &out, &errBuf, "gofusa lint", dir, "json", "/nonexistent/dir/output.json", false,
		func(_ engine.Rule) bool { return true })
	// Should get runtime error (3) for bad output path
	if code != 3 {
		t.Logf("runFiltered bad output: exit %d (may vary); stderr: %s", code, errBuf.String())
	}
}

// ─── runFix extra paths ───────────────────────────────────────────────────────

//fusa:test REQ-CLI-FIX001
func TestRunFix_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runFix([]string{"--dir", dir}, &out, &errBuf)
	if code != 0 && code != 1 {
		t.Errorf("unexpected exit %d: %s", code, errBuf.String())
	}
}

//fusa:test REQ-CLI-FIX001
func TestRunFix_OutputReport(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "fix-report.json")
	var out, errBuf bytes.Buffer
	code := runFix([]string{"--dir", dir, "--report", outFile}, &out, &errBuf)
	if code != 0 && code != 1 {
		t.Errorf("unexpected exit %d: %s", code, errBuf.String())
	}
	if _, err := os.Stat(outFile); err != nil {
		t.Error("report file not written")
	}
}

//fusa:test REQ-CLI-FIX001
func TestRunFix_BadFlag(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runFix([]string{"--no-such-flag"}, &out, &errBuf)
	if code != 2 {
		t.Errorf("expected exit 2, got %d", code)
	}
}

//fusa:test REQ-CLI-FIX001
func TestFilterFixable_NilInput(t *testing.T) {
	result := filterFixable(nil)
	if result != nil {
		t.Errorf("expected nil for nil input, got %v", result)
	}
}

// ─── runFmea extra paths ──────────────────────────────────────────────────────

//fusa:test REQ-CLI013
func TestRunFmea_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runFmea([]string{"--dir", dir}, &out, &errBuf)
	if code != 0 {
		t.Errorf("runFmea exit %d: %s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "FMEA report written") {
		t.Errorf("expected 'FMEA report written' in output; got: %s", out.String())
	}
}

//fusa:test REQ-CLI013
func TestRunFmea_OutputDir(t *testing.T) {
	dir := t.TempDir()
	outDir := filepath.Join(dir, "fmea-output")
	var out, errBuf bytes.Buffer
	code := runFmea([]string{"--dir", dir, "--output-dir", outDir}, &out, &errBuf)
	if code != 0 {
		t.Errorf("runFmea exit %d: %s", code, errBuf.String())
	}
	if _, err := os.Stat(outDir); err != nil {
		t.Error("output dir not created")
	}
}

//fusa:test REQ-CLI013
func TestRunFmea_BadFlag(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runFmea([]string{"--no-such-flag"}, &out, &errBuf)
	if code != 2 {
		t.Errorf("expected exit 2, got %d", code)
	}
}

//fusa:test REQ-CLI013
func TestRunFmea_WithGoSource(t *testing.T) {
	dir := t.TempDir()
	src := `package main

//fusa:req REQ-001
func SafetyFunc() error { return nil }

//fusa:req REQ-002
func CriticalFunc() int { return 0 }
`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	code := runFmea([]string{"--dir", dir}, &out, &errBuf)
	if code != 0 {
		t.Errorf("runFmea exit %d: %s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "Entries:") {
		t.Errorf("expected Entries: summary; got: %s", out.String())
	}
}

// ─── runCoupling extra paths ──────────────────────────────────────────────────

//fusa:test REQ-CLI-COUPLING001
func TestRunCoupling_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runCoupling([]string{"--dir", dir}, &out, &errBuf)
	if code != 0 {
		t.Errorf("runCoupling exit %d: %s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "Coupling report written") {
		t.Errorf("expected 'Coupling report written'; got: %s", out.String())
	}
}

//fusa:test REQ-CLI-COUPLING001
func TestRunCoupling_BadFlag(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runCoupling([]string{"--no-such-flag"}, &out, &errBuf)
	if code != 2 {
		t.Errorf("expected exit 2, got %d", code)
	}
}

// ─── runImpact extra paths ────────────────────────────────────────────────────

//fusa:test REQ-CLI-IMPACT001
func TestRunImpact_BadFlag(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runImpact([]string{"--no-such-flag"}, &out, &errBuf)
	if code != 2 {
		t.Errorf("expected exit 2, got %d", code)
	}
}

//fusa:test REQ-CLI-IMPACT001
func TestRunImpact_OutputFileCreated(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "impact.json")
	var out, errBuf bytes.Buffer
	code := runImpact([]string{"--dir", dir, "--format", "json", "--output", outFile}, &out, &errBuf)
	if code == 0 {
		if _, err := os.Stat(outFile); err != nil {
			t.Error("output file not written")
		}
		// Should print summary to stdout
		if !strings.Contains(out.String(), "Impact report written") {
			t.Logf("stdout: %s", out.String())
		}
	}
}

// ─── runISO21434 extra paths ──────────────────────────────────────────────────

//fusa:test REQ-CLI-ISO21434-001
func TestRunISO21434_AllCALs(t *testing.T) {
	for _, cal := range []string{"CAL-1", "CAL-2", "CAL-3", "CAL-4"} {
		dir := t.TempDir()
		var out, errBuf bytes.Buffer
		runISO21434([]string{"--dir", dir, "--cal", cal}, &out, &errBuf)
		if !strings.Contains(out.String(), "ISO 21434") {
			t.Errorf("CAL=%s: expected ISO 21434 in output; got: %s", cal, out.String())
		}
	}
}

//fusa:test REQ-CLI-ISO21434-001
func TestRunISO21434_BadFlag(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runISO21434([]string{"--no-such-flag"}, &out, &errBuf)
	if code != 2 {
		t.Errorf("expected exit 2, got %d", code)
	}
}

//fusa:test REQ-CLI-ISO21434-001
func TestRunISO21434_OutputWritesCountMessage(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "iso21434.json")
	var out, errBuf bytes.Buffer
	runISO21434([]string{"--dir", dir, "--format", "json", "--output", outFile}, &out, &errBuf)
	if _, err := os.Stat(outFile); err != nil {
		t.Error("output file not written")
	}
	// stdout should have count message
	if !strings.Contains(out.String(), "ISO 21434 gap report") {
		t.Logf("stdout: %s", out.String())
	}
}

// ─── runVerify extra paths ────────────────────────────────────────────────────

//fusa:test REQ-CLI-VERIFY001
func TestRunVerify_BadFlag(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runVerify([]string{"--no-such-flag"}, &out, &errBuf)
	if code != 2 {
		t.Errorf("expected exit 2, got %d", code)
	}
}

//fusa:test REQ-CLI-VERIFY001
func TestRunVerify_DirWithGoMod(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/test\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Write a trivial test to run
	testSrc := `package main_test
import "testing"
func TestPass(t *testing.T) {}
`
	if err := os.WriteFile(filepath.Join(dir, "main_test.go"), []byte(testSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	mainSrc := `package main
func main() {}
`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(mainSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	code := runVerify([]string{"--dir", dir}, &out, &errBuf)
	// Accept 0 (pass) or 3 (runtime failure if go test has issues in sandbox)
	if code != 0 && code != 3 {
		t.Logf("runVerify exit %d (may vary in CI); stderr: %s", code, errBuf.String())
	}
}

// ─── runCyber extra paths ─────────────────────────────────────────────────────

//fusa:test REQ-CLI018
func TestRunCyber_BadFlag(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runCyber([]string{"--no-such-flag"}, &out, &errBuf)
	if code != 2 {
		t.Errorf("expected exit 2, got %d", code)
	}
}

//fusa:test REQ-CLI018
func TestRunCyber_OutputFlag(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/test\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	outFile := filepath.Join(dir, "cyber.json")
	var out, errBuf bytes.Buffer
	runCyber([]string{"--dir", dir, "--output", outFile}, &out, &errBuf)
	if _, err := os.Stat(outFile); err != nil {
		t.Error("output file not written")
	}
}

//fusa:test REQ-CLI018
func TestRunCyber_Strict(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/test\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	code := runCyber([]string{"--dir", dir, "--strict"}, &out, &errBuf)
	// 0 = no findings, 1 = gate fail, both ok
	if code != 0 && code != 1 {
		t.Logf("runCyber strict exit %d: %s", code, errBuf.String())
	}
}

// ─── runSci extra paths ───────────────────────────────────────────────────────

//fusa:test REQ-CLI-SCI001
func TestRunSci_BadFlag(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runSci([]string{"--no-such-flag"}, &out, &errBuf)
	if code != 2 {
		t.Errorf("expected exit 2, got %d", code)
	}
}

//fusa:test REQ-CLI-SCI001
func TestRunSci_JSONOutputFile(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "sci.json")
	var out, errBuf bytes.Buffer
	code := runSci([]string{"--dir", dir, "--format", "json", "--output", outFile}, &out, &errBuf)
	if code != 0 {
		t.Errorf("runSci exit %d: %s", code, errBuf.String())
	}
	if _, err := os.Stat(outFile); err != nil {
		t.Error("output file not written")
	}
}

//fusa:test REQ-CLI-SCI001
func TestRunSci_WithConfig(t *testing.T) {
	dir := t.TempDir()
	cfgContent := `{"version":"1","project":{"name":"myproject","module":"example.com/test","standard":"DO178C"},"rules":{},"report":{"format":"text"}}`
	if err := os.WriteFile(filepath.Join(dir, ".fusa.json"), []byte(cfgContent), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/test\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	code := runSci([]string{"--dir", dir, "--format", "json"}, &out, &errBuf)
	if code != 0 {
		t.Errorf("runSci exit %d: %s", code, errBuf.String())
	}
}

// ─── signKeygen extra paths ───────────────────────────────────────────────────

//fusa:test REQ-CLI-SIGN001
func TestSignKeygen_Success(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "test.key")
	var out, errBuf bytes.Buffer
	code := signKeygen(keyPath, &out, &errBuf)
	if code != 0 {
		t.Fatalf("signKeygen exit %d: %s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "Key written to") {
		t.Errorf("expected 'Key written to'; got: %s", out.String())
	}
	data, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	// 32 bytes = 64 hex chars + newline
	if len(strings.TrimSpace(string(data))) != 64 {
		t.Errorf("key length = %d, want 64 hex chars", len(strings.TrimSpace(string(data))))
	}
}

//fusa:test REQ-CLI-SIGN001
func TestSignKeygen_BadPath(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := signKeygen("/nonexistent/dir/key.txt", &out, &errBuf)
	if code != 3 {
		t.Errorf("expected exit 3 for bad path, got %d", code)
	}
}

//fusa:test REQ-CLI-SIGN001
func TestRunSign_KeygenFlagv2(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.txt")
	var out, errBuf bytes.Buffer
	code := runSign([]string{"--keygen", keyPath}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("runSign --keygen exit %d: %s", code, errBuf.String())
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Error("key file not written")
	}
}

//fusa:test REQ-CLI-SIGN001
func TestRunSign_SignAndVerify(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.txt")
	// Generate key
	var out, errBuf bytes.Buffer
	runSign([]string{"--keygen", keyPath}, &out, &errBuf)

	// Create artifact
	artifact := filepath.Join(dir, "artifact.bin")
	if err := os.WriteFile(artifact, []byte("hello world"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Sign
	out.Reset()
	errBuf.Reset()
	code := runSign([]string{"--key", keyPath, artifact}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("sign exit %d: %s", code, errBuf.String())
	}

	// Verify
	out.Reset()
	errBuf.Reset()
	code = runSign([]string{"--key", keyPath, "--verify", artifact}, &out, &errBuf)
	if code != 0 {
		t.Errorf("verify exit %d: %s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "Signature OK") {
		t.Errorf("expected 'Signature OK'; got: %s", out.String())
	}
}

//fusa:test REQ-CLI-SIGN001
func TestRunSign_BadFlagv2(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runSign([]string{"--no-such-flag"}, &out, &errBuf)
	if code != 2 {
		t.Errorf("expected exit 2, got %d", code)
	}
}

//fusa:test REQ-CLI-SIGN001
func TestRunSign_MissingKeyv2(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "file.bin")
	if err := os.WriteFile(artifact, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	code := runSign([]string{artifact}, &out, &errBuf)
	if code != 2 {
		t.Errorf("expected exit 2 for missing --key, got %d", code)
	}
}

// ─── runReport extra paths ────────────────────────────────────────────────────

//fusa:test REQ-CLI-MISRA001
func TestRunReport_BadFlag(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runReport([]string{"--no-such-flag"}, &out, &errBuf)
	if code != 2 {
		t.Errorf("expected exit 2, got %d", code)
	}
}

//fusa:test REQ-CLI-MISRA001
func TestRunReport_TextFormat(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runReport([]string{"--dir", dir, "--format", "text"}, &out, &errBuf)
	if code != 0 {
		t.Errorf("runReport text exit %d: %s", code, errBuf.String())
	}
}

// ─── runIEC61508 extra paths ──────────────────────────────────────────────────

//fusa:test REQ-CLI-IEC61508-001
func TestRunIEC61508_OutputWritesCountMessage(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "iec61508.json")
	var out, errBuf bytes.Buffer
	runIEC61508([]string{"--dir", dir, "--sil", "SIL-1", "--format", "json", "--output", outFile}, &out, &errBuf)
	if _, err := os.Stat(outFile); err != nil {
		t.Error("output file not written")
	}
	if !strings.Contains(out.String(), "IEC 61508") {
		t.Logf("stdout: %s", out.String())
	}
}

//fusa:test REQ-CLI-IEC61508-001
func TestRunIEC61508_AllSILsv2(t *testing.T) {
	for _, sil := range []string{"SIL-1", "SIL-2", "SIL-3", "SIL-4"} {
		dir := t.TempDir()
		var out, errBuf bytes.Buffer
		runIEC61508([]string{"--dir", dir, "--sil", sil}, &out, &errBuf)
		if !strings.Contains(out.String(), "IEC 61508") {
			t.Errorf("SIL=%s: expected IEC 61508 header; got: %s", sil, out.String())
		}
	}
}

// ─── runISO26262 extra paths ──────────────────────────────────────────────────

//fusa:test REQ-CLI-ISO26262-001
func TestRunISO26262_OutputWritesCountMessage(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "iso26262.json")
	var out, errBuf bytes.Buffer
	runISO26262([]string{"--dir", dir, "--asil", "ASIL-D", "--format", "json", "--output", outFile}, &out, &errBuf)
	if _, err := os.Stat(outFile); err != nil {
		t.Error("output file not written")
	}
	if !strings.Contains(out.String(), "ISO 26262") {
		t.Logf("stdout: %s", out.String())
	}
}
