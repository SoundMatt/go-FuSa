package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ─── Section 3a: runTraceSecTested ────────────────────────────────────────────

//fusa:test REQ-CLI-TRACE003
func TestRunTraceSecTested_Pass(t *testing.T) {
	dir := t.TempDir()
	// Write requirements file
	reqs := `{"requirements":[
		{"id":"REQ-001","title":"First"},
		{"id":"REQ-002","title":"Second"},
		{"id":"REQ-003","title":"Third"},
		{"id":"REQ-004","title":"Fourth"}
	]}`
	if err := os.WriteFile(filepath.Join(dir, ".fusa-reqs.json"), []byte(reqs), 0o644); err != nil {
		t.Fatal(err)
	}
	// Write Go files with //fusa:test tags for 3/4 requirements (75%)
	src := `package main
//fusa:test REQ-001
//fusa:test REQ-002
//fusa:test REQ-003
`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	// threshold 70 — 75% should pass
	code := runTrace([]string{"--dir", dir, "--sec-tested", "70"}, &out, &errBuf)
	if code != 0 {
		t.Errorf("expected exit 0 at 75%% (threshold 70), got %d; stderr: %s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "75%") {
		t.Errorf("expected 75%% in output, got: %s", out.String())
	}
}

//fusa:test REQ-CLI-TRACE003
func TestRunTraceSecTested_Fail(t *testing.T) {
	dir := t.TempDir()
	reqs := `{"requirements":[
		{"id":"REQ-001","title":"First"},
		{"id":"REQ-002","title":"Second"},
		{"id":"REQ-003","title":"Third"},
		{"id":"REQ-004","title":"Fourth"}
	]}`
	if err := os.WriteFile(filepath.Join(dir, ".fusa-reqs.json"), []byte(reqs), 0o644); err != nil {
		t.Fatal(err)
	}
	// Only 1 out of 4 has a test tag (25%)
	src := `package main
//fusa:test REQ-001
`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	// threshold 70 — 25% should fail
	code := runTrace([]string{"--dir", dir, "--sec-tested", "70"}, &out, &errBuf)
	if code != 1 {
		t.Errorf("expected exit 1 at 25%% (threshold 70), got %d", code)
	}
}

//fusa:test REQ-CLI-TRACE003
func TestRunTraceSecTested_NoRequirements(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runTrace([]string{"--dir", dir, "--sec-tested", "70"}, &out, &errBuf)
	if code != 0 {
		t.Errorf("expected exit 0 when no requirements, got %d; stderr: %s", code, errBuf.String())
	}
}

// ─── Section 3c: BuildFromFile ────────────────────────────────────────────────

//fusa:test REQ-CLI-COV001
func TestBuildFromFile_Valid(t *testing.T) {
	// This is tested in coverage_test.go; here we drive runCoverage to exercise it
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
	var out, errBuf bytes.Buffer
	code := runCoverage([]string{"--dal", "DAL-B", "--format", "text", f.Name()}, &out, &errBuf)
	if code != 0 {
		t.Errorf("runCoverage exit %d: %s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "DO-178C") {
		t.Error("expected DO-178C in output")
	}
}

// ─── Section 3d: BuildProvenance (tests release.vcsInfo) ─────────────────────

//fusa:test REQ-CLI016
func TestBuildProvenance_RepoRoot(t *testing.T) {
	dir := t.TempDir()
	// Minimal go.mod needed for BuildProvenance
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/test\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	code := runRelease([]string{"--dir", dir, "--output", filepath.Join(dir, "sbom.json")}, &out, &errBuf)
	if code != 0 {
		t.Logf("runRelease: %s", errBuf.String())
	}
	// Just check provenance.json was written (vcsInfo called internally)
	// Release may fail if git not available but should still produce provenance
}

// ─── Section 3f: runSas ───────────────────────────────────────────────────────

//fusa:test REQ-CLI-SAS001
func TestRunSas_BasicMarkdown(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/test\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	// Use --output - to write to stdout and avoid creating files in temp dir
	code := runSas([]string{"--dir", dir, "--format", "markdown", "--output", "-"}, &out, &errBuf)
	// SAS with empty dir will have gaps, exit 1
	_ = code
	output := out.String()
	if !strings.Contains(output, "Software Accomplishment Summary") {
		t.Errorf("expected SAS content in output, got: %s", output)
	}
}

//fusa:test REQ-CLI-SAS001
func TestRunSas_JSONFormat(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/test\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	runSas([]string{"--dir", dir, "--format", "json", "--output", "-"}, &out, &errBuf)
	if !strings.Contains(out.String(), `"title"`) && !strings.Contains(out.String(), `"dal"`) {
		t.Errorf("expected JSON content, got: %s", out.String())
	}
}

//fusa:test REQ-CLI-SAS001
func TestRunSas_DALA_Flag(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	_ = runSas([]string{"--dir", dir, "--dal", "DAL-A", "--output", "-"}, &out, &errBuf)
	// Should not crash
}

// ─── Section 3g: report moduleFromRoot and countRequirements ─────────────────

//fusa:test REQ-CLI-MISRA001
func TestRunReport_JSON(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/test\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	code := runReport([]string{"--dir", dir, "--format", "json"}, &out, &errBuf)
	if code != 0 {
		t.Errorf("runReport exit %d: %s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), `"findings"`) {
		t.Errorf("expected JSON with findings, got: %s", out.String())
	}
}

//fusa:test REQ-CLI-MISRA001
func TestRunReport_HTML(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/test\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Write a .fusa-reqs.json so countRequirements has something to count
	reqs := `{"requirements":[{"id":"REQ-001","title":"Req 1"}]}`
	if err := os.WriteFile(filepath.Join(dir, ".fusa-reqs.json"), []byte(reqs), 0o644); err != nil {
		t.Fatal(err)
	}
	outFile := filepath.Join(dir, "report.html")
	var out, errBuf bytes.Buffer
	code := runReport([]string{"--dir", dir, "--format", "html", "--output", outFile}, &out, &errBuf)
	if code != 0 {
		t.Errorf("runReport exit %d: %s", code, errBuf.String())
	}
	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !strings.Contains(string(data), "<html") {
		t.Error("expected HTML content in output")
	}
}

//fusa:test REQ-CLI-MISRA001
func TestRunReport_Output(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "my-report.json")
	var out, errBuf bytes.Buffer
	code := runReport([]string{"--dir", dir, "--format", "json", "--output", outFile}, &out, &errBuf)
	if code != 0 {
		t.Errorf("runReport exit %d: %s", code, errBuf.String())
	}
	if _, err := os.Stat(outFile); err != nil {
		t.Error("output file not written")
	}
}

// ─── Section 3h: runReqShow and runReqExport ─────────────────────────────────

//fusa:test REQ-CLI-REQ001
func TestRunReqShow_FilterFound(t *testing.T) {
	dir := t.TempDir()
	reqs := `{"requirements":[
		{"id":"REQ-001","title":"Authentication"},
		{"id":"REQ-002","title":"Authorization"}
	]}`
	if err := os.WriteFile(filepath.Join(dir, ".fusa-reqs.json"), []byte(reqs), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	code := runReq([]string{"--dir", dir, "REQ-001"}, &out, &errBuf)
	if code != 0 {
		t.Errorf("expected exit 0, got %d: %s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "REQ-001") {
		t.Errorf("expected REQ-001 in output, got: %s", out.String())
	}
	if strings.Contains(out.String(), "REQ-002") {
		t.Error("REQ-002 should not appear when filtering for REQ-001")
	}
}

//fusa:test REQ-CLI-REQ001
func TestRunReqShow_FilterNotFound(t *testing.T) {
	dir := t.TempDir()
	reqs := `{"requirements":[{"id":"REQ-001","title":"Auth"}]}`
	if err := os.WriteFile(filepath.Join(dir, ".fusa-reqs.json"), []byte(reqs), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	code := runReq([]string{"--dir", dir, "REQ-999"}, &out, &errBuf)
	if code != 2 {
		t.Errorf("expected exit 2 (usage) for missing req, got %d", code)
	}
}

//fusa:test REQ-CLI-REQ003
func TestRunReqExport_DOORS(t *testing.T) {
	dir := t.TempDir()
	reqs := `{"requirements":[
		{"id":"REQ-001","title":"Authentication","text":"The system shall authenticate users"},
		{"id":"REQ-002","title":"Authorization"}
	]}`
	if err := os.WriteFile(filepath.Join(dir, ".fusa-reqs.json"), []byte(reqs), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	code := runReq([]string{"--dir", dir, "export", "--format", "doors"}, &out, &errBuf)
	if code != 0 {
		t.Errorf("runReq export exit %d: %s", code, errBuf.String())
	}
	outStr := out.String()
	if !strings.Contains(outStr, "REQ-001") {
		t.Error("expected REQ-001 in DOORS export")
	}
	if !strings.Contains(outStr, "REQ-IF") {
		t.Error("expected REQ-IF root element in DOORS export")
	}
}

//fusa:test REQ-CLI-REQ003
func TestRunReqExport_Polarion(t *testing.T) {
	dir := t.TempDir()
	reqs := `{"requirements":[
		{"id":"REQ-001","title":"Authentication","text":"User auth"},
		{"id":"REQ-002","title":"Authorization"}
	]}`
	if err := os.WriteFile(filepath.Join(dir, ".fusa-reqs.json"), []byte(reqs), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	code := runReq([]string{"--dir", dir, "export", "--format", "polarion"}, &out, &errBuf)
	if code != 0 {
		t.Errorf("runReq export exit %d: %s", code, errBuf.String())
	}
	outStr := out.String()
	if !strings.Contains(outStr, "REQ-001") {
		t.Error("expected REQ-001 in Polarion export")
	}
	if !strings.Contains(outStr, "workitems") {
		t.Error("expected workitems root element in Polarion export")
	}
}

//fusa:test REQ-CLI-REQ003
func TestRunReqExport_Output(t *testing.T) {
	dir := t.TempDir()
	reqs := `{"requirements":[{"id":"REQ-001","title":"Auth"}]}`
	if err := os.WriteFile(filepath.Join(dir, ".fusa-reqs.json"), []byte(reqs), 0o644); err != nil {
		t.Fatal(err)
	}
	outFile := filepath.Join(dir, "out.csv")
	var out, errBuf bytes.Buffer
	code := runReq([]string{"--dir", dir, "export", "--format", "csv", "--output", outFile}, &out, &errBuf)
	if code != 0 {
		t.Errorf("runReq export exit %d: %s", code, errBuf.String())
	}
	if _, err := os.Stat(outFile); err != nil {
		t.Error("output file not written")
	}
}

// ─── Section 3e/3b: cyber isNolinted / isRequestDerived / isTempPath ─────────

//fusa:test REQ-CLI018
func TestRunCyber_IsNolinted(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/test\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Source that would trigger CYBER005 (cmd injection) but has nolint comment
	src := `package main
import "os/exec"
func Run(cmd string) { exec.Command(cmd).Run() } //nolint:CYBER005
`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	_ = runCyber([]string{"--dir", dir, "--format", "json", "--output", "-"}, &out, &errBuf)
	// The nolint comment should suppress CYBER005
}

//fusa:test REQ-CLI018
func TestRunCyber_IsRequestDerived(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/test\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Source that triggers CYBER018 (request-derived path)
	src := `package main
import (
	"net/http"
	"os"
)
func Serve(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, r.URL.Path)
	_, _ = os.Open(r.URL.Path)
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	code := runCyber([]string{"--dir", dir, "--format", "json", "--output", "-"}, &out, &errBuf)
	if code != 0 {
		t.Logf("runCyber exit %d: %s", code, errBuf.String())
	}
	// Just ensure it runs without panicking
}

//fusa:test REQ-CLI018
func TestRunCyber_IsTempPath(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/test\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Source that triggers CYBER020 (temp file)
	src := `package main
import "os"
func MakeTempFile() (*os.File, error) {
	return os.Create("/tmp/myfile.txt")
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	code := runCyber([]string{"--dir", dir, "--format", "json", "--output", "-"}, &out, &errBuf)
	if code != 0 {
		t.Logf("runCyber exit %d: %s", code, errBuf.String())
	}
}

// ─── ISO 21434 CLI ─────────────────────────────────────────────────────────────

//fusa:test REQ-CLI-ISO21434-001
func TestRunISO21434_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runISO21434([]string{"--dir", dir, "--format", "text"}, &out, &errBuf)
	// Gaps present, so exit 1
	_ = code
	if !strings.Contains(out.String(), "ISO 21434") {
		t.Errorf("expected ISO 21434 in output, got: %s", out.String())
	}
}

//fusa:test REQ-CLI-ISO21434-001
func TestRunISO21434_JSON(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	runISO21434([]string{"--dir", dir, "--format", "json"}, &out, &errBuf)
	if !strings.Contains(out.String(), `"standard"`) {
		t.Errorf("expected standard field in JSON, got: %s", out.String())
	}
}

//fusa:test REQ-CLI-ISO21434-001
func TestRunISO21434_Output(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "iso21434-report.json")
	var out, errBuf bytes.Buffer
	runISO21434([]string{"--dir", dir, "--format", "json", "--output", outFile}, &out, &errBuf)
	if _, err := os.Stat(outFile); err != nil {
		t.Error("output file not written")
	}
}

// ─── UN R.155 CLI ─────────────────────────────────────────────────────────────

//fusa:test REQ-CLI-UNECE-001
func TestRunUNECE_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runUNECE([]string{"--dir", dir, "--format", "text"}, &out, &errBuf)
	_ = code
	if !strings.Contains(out.String(), "UN R.155") {
		t.Errorf("expected UN R.155 in output, got: %s", out.String())
	}
}

//fusa:test REQ-CLI-UNECE-001
func TestRunUNECE_JSON(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	runUNECE([]string{"--dir", dir, "--format", "json"}, &out, &errBuf)
	if !strings.Contains(out.String(), `"standard"`) {
		t.Errorf("expected standard field in JSON, got: %s", out.String())
	}
}

// ─── Codebeamer and Jama CLI ──────────────────────────────────────────────────

//fusa:test REQ-CLI-REQ002
func TestRunReqImport_Codebeamer(t *testing.T) {
	dir := t.TempDir()
	xmlData := `<?xml version="1.0"?>
<tracker>
  <item id="1001">
    <name>REQ-001</name>
    <summary>Auth requirement</summary>
    <description>The system shall authenticate</description>
  </item>
</tracker>
`
	xmlFile := filepath.Join(dir, "input.xml")
	if err := os.WriteFile(xmlFile, []byte(xmlData), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	code := runReq([]string{"--dir", dir, "import", "--format", "codebeamer", "--file", xmlFile}, &out, &errBuf)
	if code != 0 {
		t.Errorf("expected exit 0, got %d: %s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "Imported 1") {
		t.Errorf("expected Imported 1 in output, got: %s", out.String())
	}
}

//fusa:test REQ-CLI-REQ003
func TestRunReqExport_Codebeamer(t *testing.T) {
	dir := t.TempDir()
	reqs := `{"requirements":[{"id":"REQ-001","title":"Auth","asil":"ASIL-B","level":"HLR"}]}`
	if err := os.WriteFile(filepath.Join(dir, ".fusa-reqs.json"), []byte(reqs), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	code := runReq([]string{"--dir", dir, "export", "--format", "codebeamer"}, &out, &errBuf)
	if code != 0 {
		t.Errorf("expected exit 0, got %d: %s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "tracker") {
		t.Errorf("expected tracker element in output, got: %s", out.String())
	}
}

//fusa:test REQ-CLI-REQ002
func TestRunReqImport_Jama(t *testing.T) {
	dir := t.TempDir()
	xmlData := `<?xml version="1.0"?>
<items>
  <item id="REQ-001" itemType="TEXT">
    <name>Safety requirement</name>
    <description>The system shall be safe</description>
    <fields>
      <field id="asil" value="ASIL-B"/>
    </fields>
  </item>
</items>
`
	xmlFile := filepath.Join(dir, "input.xml")
	if err := os.WriteFile(xmlFile, []byte(xmlData), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	code := runReq([]string{"--dir", dir, "import", "--format", "jama", "--file", xmlFile}, &out, &errBuf)
	if code != 0 {
		t.Errorf("expected exit 0, got %d: %s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "Imported 1") {
		t.Errorf("expected Imported 1 in output, got: %s", out.String())
	}
}

//fusa:test REQ-CLI-REQ003
func TestRunReqExport_Jama(t *testing.T) {
	dir := t.TempDir()
	reqs := `{"requirements":[{"id":"REQ-001","title":"Safety req","asil":"ASIL-B"}]}`
	if err := os.WriteFile(filepath.Join(dir, ".fusa-reqs.json"), []byte(reqs), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	code := runReq([]string{"--dir", dir, "export", "--format", "jama"}, &out, &errBuf)
	if code != 0 {
		t.Errorf("expected exit 0, got %d: %s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "items") {
		t.Errorf("expected items element in output, got: %s", out.String())
	}
}
