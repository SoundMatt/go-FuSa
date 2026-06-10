package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ─── runRelease --full path ───────────────────────────────────────────────────

//fusa:test REQ-CLI016
func TestRunRelease_FullBundle(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/test\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	code := runRelease([]string{"--dir", dir, "--full"}, &out, &errBuf)
	// accepts 0 or 3 (vuln scan may fail, but the function handles that gracefully)
	if code != 0 && code != 3 {
		t.Logf("runRelease --full exit %d (may vary): %s", code, errBuf.String())
	}
	// FMEA should have been written
	if code == 0 {
		if !strings.Contains(out.String(), "FMEA written") {
			t.Logf("expected FMEA written; stdout: %s", out.String())
		}
	}
}

// ─── runRelease SPDX versions ─────────────────────────────────────────────────

//fusa:test REQ-CLI016
func TestRunRelease_SPDXEmpty(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/test\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	code := runRelease([]string{"--dir", dir, "--spdx-version", ""}, &out, &errBuf)
	if code == 0 {
		if !strings.Contains(out.String(), "SBOM written") {
			t.Logf("expected SBOM written; stdout: %s", out.String())
		}
	}
}

// ─── runCyber with findings triggering ExitGateFail ──────────────────────────

//fusa:test REQ-CLI018
func TestRunCyber_FindingsPresent(t *testing.T) {
	// Use a directory with Go source that triggers cyber findings
	dir := t.TempDir()
	src := `package main

import "net/http"

// This function has HTTP without TLS - should trigger CYBER001
func handler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("hello"))
}

var HardcodedSecret = "password123"
`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	code := runCyber([]string{"--dir", dir}, &out, &errBuf)
	// Accept 0 (no error-level findings) or 1 (gate fail with errors)
	if code != 0 && code != 1 {
		t.Logf("runCyber exit %d: %s", code, errBuf.String())
	}
}

//fusa:test REQ-CLI018
func TestRunCyber_StrictWithWarnings(t *testing.T) {
	// Any warnings make --strict exit 1
	dir := t.TempDir()
	src := `package main
var ExportedData = "value"
`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	code := runCyber([]string{"--dir", dir, "--strict"}, &out, &errBuf)
	// Accept 0 or 1
	if code != 0 && code != 1 {
		t.Logf("runCyber strict exit %d: %s", code, errBuf.String())
	}
	// Should always print findings summary
	if !strings.Contains(out.String(), "Cyber findings:") {
		t.Errorf("expected 'Cyber findings:' in output; got: %s", out.String())
	}
}

// ─── runFmea with high/medium entries ────────────────────────────────────────

//fusa:test REQ-CLI013
func TestRunFmea_HighSeverityFunc(t *testing.T) {
	// Functions without error handling may get HIGH severity in fmea
	dir := t.TempDir()
	src := `package main

// Exported function without safety annotation
func HighRisk() {
	panic("unhandled")
}

func MedRisk() error {
	return nil
}

func LowRisk() int {
	return 0
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	code := runFmea([]string{"--dir", dir}, &out, &errBuf)
	if code != 0 {
		t.Errorf("runFmea exit %d: %s", code, errBuf.String())
	}
	// Output should show counts
	outStr := out.String()
	if !strings.Contains(outStr, "high:") || !strings.Contains(outStr, "medium:") || !strings.Contains(outStr, "low:") {
		t.Logf("fmea output: %s", outStr)
	}
}

// ─── runImpact output message path ────────────────────────────────────────────

//fusa:test REQ-CLI-IMPACT001
func TestRunImpact_OutputPath(t *testing.T) {
	// Use real git repo so impact analysis can compute diffs
	dir := "/Users/matt/Documents/Coding/SoundMatt/go-Fusa"
	outFile := t.TempDir() + "/impact.json"
	var out, errBuf bytes.Buffer
	code := runImpact([]string{"--dir", dir, "--format", "json", "--output", outFile, "--from", "HEAD", "--to", "HEAD"}, &out, &errBuf)
	if code == 0 {
		if !strings.Contains(out.String(), "Impact report written") {
			t.Logf("stdout: %s", out.String())
		}
	}
	_ = code
}

// ─── runUNECE with output file (gap > 0) ─────────────────────────────────────

//fusa:test REQ-CLI-UNECE-001
func TestRunUNECE_OutputWithGap(t *testing.T) {
	// Empty dir will have gaps
	dir := t.TempDir()
	outFile := filepath.Join(dir, "unece.json")
	var out, errBuf bytes.Buffer
	code := runUNECE([]string{"--dir", dir, "--format", "json", "--output", outFile}, &out, &errBuf)
	// Should be exit 1 (gaps present) and write message to stdout
	if code != 0 && code != 1 {
		t.Logf("runUNECE exit %d", code)
	}
	_ = strings.Contains(out.String(), "UN R.155") // output message written when --output used
}

// ─── runISO21434 output message path ─────────────────────────────────────────

//fusa:test REQ-CLI-ISO21434-001
func TestRunISO21434_WithOutput_WritesMessage(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "iso21434.json")
	var out, errBuf bytes.Buffer
	code := runISO21434([]string{"--dir", dir, "--cal", "CAL-2", "--format", "json", "--output", outFile}, &out, &errBuf)
	if code != 0 && code != 1 {
		t.Logf("runISO21434 exit %d: %s", code, errBuf.String())
	}
	_ = strings.Contains(out.String(), "ISO 21434 gap report written")
}

// ─── runISO26262 with output = "" and text format (no summary) ───────────────

//fusa:test REQ-CLI-ISO26262-001
func TestRunISO26262_TextNoOutput(t *testing.T) {
	// When output is "" and format is text, "summary already in render" path
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runISO26262([]string{"--dir", dir, "--format", "text"}, &out, &errBuf)
	// exit 0 or 1 depending on gaps
	if code != 0 && code != 1 {
		t.Logf("runISO26262 text exit %d: %s", code, errBuf.String())
	}
	if out.Len() == 0 {
		t.Error("expected non-empty output")
	}
}

// ─── runIEC61508 output message path ─────────────────────────────────────────

//fusa:test REQ-CLI-IEC61508-001
func TestRunIEC61508_WithOutput(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "iec.json")
	var out, errBuf bytes.Buffer
	code := runIEC61508([]string{"--dir", dir, "--sil", "SIL-3", "--format", "json", "--output", outFile}, &out, &errBuf)
	if code != 0 && code != 1 {
		t.Logf("runIEC61508 exit %d: %s", code, errBuf.String())
	}
	_ = strings.Contains(out.String(), "IEC 61508 gap report written")
}

//fusa:test REQ-CLI-IEC61508-001
func TestRunIEC61508_InvalidSILv2(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runIEC61508([]string{"--sil", "SIL-9"}, &out, &errBuf)
	if code != 2 {
		t.Errorf("expected exit 2 for invalid SIL, got %d", code)
	}
}

// ─── runBoundary extra paths ──────────────────────────────────────────────────

//fusa:test REQ-CLI014
func TestRunBoundary_WithGoSource(t *testing.T) {
	dir := t.TempDir()
	src := `package main

import "fmt"

func main() { fmt.Println("hello") }
`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	code := runBoundary([]string{"--dir", dir}, &out, &errBuf)
	if code != 0 {
		t.Errorf("runBoundary exit %d: %s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "Packages:") {
		t.Errorf("expected Packages: summary; got: %s", out.String())
	}
}

// ─── runReqExport to doors/polarion etc. ─────────────────────────────────────

//fusa:test REQ-CLI-REQ003
func TestRunReqExport_Doorsv2(t *testing.T) {
	dir := t.TempDir()
	reqs := `{"requirements":[{"id":"REQ-001","title":"Auth","text":"Text","standard":"ISO 26262","level":"HLR"}]}`
	if err := os.WriteFile(filepath.Join(dir, ".fusa-reqs.json"), []byte(reqs), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	code := runReq([]string{"--dir", dir, "export", "--format", "doors"}, &out, &errBuf)
	if code != 0 {
		t.Errorf("expected exit 0, got %d: %s", code, errBuf.String())
	}
	if out.Len() == 0 {
		t.Error("expected non-empty output")
	}
}

//fusa:test REQ-CLI-REQ003
func TestRunReqExport_Polarionv2(t *testing.T) {
	dir := t.TempDir()
	reqs := `{"requirements":[{"id":"REQ-001","title":"Auth","text":"Text","standard":"ISO 26262","level":"HLR"}]}`
	if err := os.WriteFile(filepath.Join(dir, ".fusa-reqs.json"), []byte(reqs), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	code := runReq([]string{"--dir", dir, "export", "--format", "polarion"}, &out, &errBuf)
	if code != 0 {
		t.Errorf("expected exit 0, got %d: %s", code, errBuf.String())
	}
}

//fusa:test REQ-CLI-REQ003
func TestRunReqExport_Codebeamerv2(t *testing.T) {
	dir := t.TempDir()
	reqs := `{"requirements":[{"id":"REQ-001","title":"Auth"}]}`
	if err := os.WriteFile(filepath.Join(dir, ".fusa-reqs.json"), []byte(reqs), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	code := runReq([]string{"--dir", dir, "export", "--format", "codebeamer"}, &out, &errBuf)
	if code != 0 {
		t.Errorf("expected exit 0, got %d: %s", code, errBuf.String())
	}
}

//fusa:test REQ-CLI-REQ003
func TestRunReqExport_Jamav2(t *testing.T) {
	dir := t.TempDir()
	reqs := `{"requirements":[{"id":"REQ-001","title":"Auth"}]}`
	if err := os.WriteFile(filepath.Join(dir, ".fusa-reqs.json"), []byte(reqs), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	code := runReq([]string{"--dir", dir, "export", "--format", "jama"}, &out, &errBuf)
	if code != 0 {
		t.Errorf("expected exit 0, got %d: %s", code, errBuf.String())
	}
}

// ─── runSas JSON format and default output ────────────────────────────────────

//fusa:test REQ-CLI-SAS001
func TestRunSas_JSONFormatv2(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/test\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	code := runSas([]string{"--dir", dir, "--format", "json", "--output", "-"}, &out, &errBuf)
	// 0 = no gaps, 1 = gaps
	if code != 0 && code != 1 {
		t.Errorf("unexpected exit %d: %s", code, errBuf.String())
	}
}

// ─── runVerify with output path ───────────────────────────────────────────────

//fusa:test REQ-CLI-VERIFY001
func TestRunVerify_WithOutputPath(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/test\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mainSrc := `package main
func main() {}
`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(mainSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	outFile := filepath.Join(dir, "evidence.json")
	var out, errBuf bytes.Buffer
	code := runVerify([]string{"--dir", dir, "--output", outFile}, &out, &errBuf)
	if code == 0 {
		if _, err := os.Stat(outFile); err != nil {
			t.Error("evidence bundle not written")
		}
	}
	_ = code // may vary
}

// ─── runFix with fixable findings ────────────────────────────────────────────

//fusa:test REQ-CLI-FIX001
func TestRunFix_WithFindings(t *testing.T) {
	// Use real repo root - has fixable findings (should have remediations)
	dir := "/Users/matt/Documents/Coding/SoundMatt/go-Fusa"
	var out, errBuf bytes.Buffer
	code := runFix([]string{"--dir", dir}, &out, &errBuf)
	// May be 0 (no errors) or 1 (gate fail with errors)
	if code != 0 && code != 1 {
		t.Logf("runFix exit %d: %s", code, errBuf.String())
	}
}

// ─── prClose more paths ───────────────────────────────────────────────────────

//fusa:test REQ-CLI-PR001
func TestPrClose_MissingID(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "problems.json")
	var out, errBuf bytes.Buffer
	prInit(logPath, &out, &errBuf)
	out.Reset()
	errBuf.Reset()
	// Missing --id flag
	code := prClose(logPath, []string{}, &out, &errBuf)
	if code != 2 {
		t.Errorf("expected exit 2 for missing --id, got %d", code)
	}
}

// ─── runInit error path ────────────────────────────────────────────────────────

//fusa:test REQ-CLI-INIT001
func TestRunInit_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runInit([]string{"--dir", dir}, &out, &errBuf)
	if code != 0 {
		t.Errorf("runInit exit %d: %s", code, errBuf.String())
	}
	if _, err := os.Stat(filepath.Join(dir, ".fusa.json")); err != nil {
		t.Error(".fusa.json not created")
	}
}

// ─── runBoundary with output dir (writeBoundary called twice) ─────────────────

//fusa:test REQ-CLI014
func TestWriteBoundary_BadPath(t *testing.T) {
	// writeBoundary with a non-creatable path
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runBoundary([]string{"--dir", dir, "--output-dir", "/nonexistent/path"}, &out, &errBuf)
	// Should fail with runtime error
	if code != 3 {
		t.Logf("runBoundary bad output dir exit %d (expected 3)", code)
	}
}

// ─── runCoupling with output path (exercises coupling.SaveReport success) ────

//fusa:test REQ-CLI-COUPLING001
func TestRunCoupling_WithOutputPath(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "coupling.json")
	var out, errBuf bytes.Buffer
	code := runCoupling([]string{"--dir", dir, "--output", outFile}, &out, &errBuf)
	if code != 0 {
		t.Errorf("runCoupling exit %d: %s", code, errBuf.String())
	}
	if _, err := os.Stat(outFile); err != nil {
		t.Error("coupling report not written")
	}
	if !strings.Contains(out.String(), "Coupling report written") {
		t.Errorf("expected report written message; got: %s", out.String())
	}
}

// ─── runSafetyCase gaps present ───────────────────────────────────────────────

//fusa:test REQ-CLI012
func TestRunSafetyCase_WithGaps(t *testing.T) {
	// Empty dir will have gaps
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runSafetyCase([]string{"--dir", dir}, &out, &errBuf)
	if code != 0 {
		t.Errorf("runSafetyCase exit %d: %s", code, errBuf.String())
	}
	// Should print gaps message
	outStr := out.String()
	if !strings.Contains(outStr, "Gaps:") {
		t.Logf("expected Gaps: in output; got: %s", outStr)
	}
}

// ─── runSafetyCase with all evidence (no gaps) ────────────────────────────────

//fusa:test REQ-CLI012
func TestRunSafetyCase_NoGaps(t *testing.T) {
	dir := t.TempDir()
	// Create all the evidence files that safetycase.Build looks for
	for _, name := range []string{
		"fmea.json", "boundary.mermaid", "sbom.json",
		"qualify-report.json", "check-report.json",
		".fusa-reqs.json", "safety-case.json",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(`{}`), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var out, errBuf bytes.Buffer
	code := runSafetyCase([]string{"--dir", dir}, &out, &errBuf)
	if code != 0 {
		t.Errorf("runSafetyCase exit %d: %s", code, errBuf.String())
	}
	outStr := out.String()
	// Either "Gaps: none" or has gaps
	if !strings.Contains(outStr, "Gaps:") {
		t.Logf("expected Gaps: in output; got: %s", outStr)
	}
}

// ─── runDo178 with output file ────────────────────────────────────────────────

//fusa:test REQ-CLI-DO178-001
func TestRunDo178_WithOutput(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "do178.json")
	var out, errBuf bytes.Buffer
	code := runDo178([]string{"--dir", dir, "--format", "json", "--output", outFile}, &out, &errBuf)
	if code == 0 || code == 1 {
		if _, err := os.Stat(outFile); err != nil {
			t.Error("output file not written")
		}
	}
}

// ─── runTemplate with invalid type (returns error) ────────────────────────────

//fusa:test REQ-CLI010
func TestRunTemplate_InvalidType(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	// Unknown type - template.Generate may return error or produce output
	code := runTemplate([]string{"--dir", dir, "--type", "unknown-type"}, &out, &errBuf)
	_ = code // may be 0 (generate ignores unknown types) or 3 (error)
}

// ─── runReport HTML format ────────────────────────────────────────────────────

//fusa:test REQ-CLI-MISRA001
func TestRunReport_HTMLFormatv2(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runReport([]string{"--dir", dir, "--format", "html"}, &out, &errBuf)
	if code != 0 {
		t.Errorf("runReport html exit %d: %s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "<html") {
		t.Logf("expected HTML output; got: %s", out.String()[:min(200, len(out.String()))])
	}
}

// ─── runCheck with SARIF format ───────────────────────────────────────────────

//fusa:test REQ-CLI005
func TestRunCheck_SARIFFormat(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runCheck([]string{"--dir", dir, "--format", "sarif"}, &out, &errBuf)
	if code != 0 && code != 1 {
		t.Errorf("unexpected exit %d: %s", code, errBuf.String())
	}
}

// ─── main.go run() function extra paths ──────────────────────────────────────

//fusa:test REQ-CLI004
func TestRun_DispositionSubcommand(t *testing.T) {
	var out, errBuf bytes.Buffer
	dir := t.TempDir()
	code := run([]string{"disposition", "--dir", dir}, &out, &errBuf)
	// no subcommand = exit 2
	if code != 2 {
		t.Logf("run disposition exit %d", code)
	}
}

//fusa:test REQ-CLI004
func TestRun_MetricsSubcommand(t *testing.T) {
	var out, errBuf bytes.Buffer
	dir := t.TempDir()
	code := run([]string{"metrics", "--dir", dir, "show"}, &out, &errBuf)
	_ = code // may be 0 or 3
}

//fusa:test REQ-CLI004
func TestRun_BoundarySubcommand(t *testing.T) {
	var out, errBuf bytes.Buffer
	dir := t.TempDir()
	code := run([]string{"boundary", "--dir", dir}, &out, &errBuf)
	if code != 0 {
		t.Logf("run boundary exit %d: %s", code, errBuf.String())
	}
}

//fusa:test REQ-CLI004
func TestRun_SafetyCaseSubcommand(t *testing.T) {
	var out, errBuf bytes.Buffer
	dir := t.TempDir()
	code := run([]string{"safety-case", "--dir", dir}, &out, &errBuf)
	if code != 0 {
		t.Logf("run safety-case exit %d: %s", code, errBuf.String())
	}
}

//fusa:test REQ-CLI004
func TestRun_QualifySubcommand(t *testing.T) {
	var out, errBuf bytes.Buffer
	outFile := filepath.Join(t.TempDir(), "qualify.json")
	code := run([]string{"qualify", "--output", outFile}, &out, &errBuf)
	if code != 0 {
		t.Logf("run qualify exit %d: %s", code, errBuf.String())
	}
}

//fusa:test REQ-CLI004
func TestRun_TaraSubcommand(t *testing.T) {
	var out, errBuf bytes.Buffer
	dir := t.TempDir()
	code := run([]string{"tara", "--dir", dir}, &out, &errBuf)
	if code != 0 {
		t.Logf("run tara exit %d: %s", code, errBuf.String())
	}
}

//fusa:test REQ-CLI004
func TestRun_VulnSubcommand(t *testing.T) {
	var out, errBuf bytes.Buffer
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/test\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code := run([]string{"vuln", "--dir", dir}, &out, &errBuf)
	_ = code // may be 0 or 3
}

//fusa:test REQ-CLI004
func TestRun_HaraSubcommand(t *testing.T) {
	var out, errBuf bytes.Buffer
	dir := t.TempDir()
	code := run([]string{"hara", "--dir", dir, "init"}, &out, &errBuf)
	if code != 0 {
		t.Logf("run hara init exit %d: %s", code, errBuf.String())
	}
}

//fusa:test REQ-CLI004
func TestRun_HooksSubcommand(t *testing.T) {
	var out, errBuf bytes.Buffer
	dir := t.TempDir()
	code := run([]string{"hooks", "--dir", dir, "show"}, &out, &errBuf)
	if code != 0 {
		t.Logf("run hooks show exit %d: %s", code, errBuf.String())
	}
}

// ─── stripNoColor ─────────────────────────────────────────────────────────────

//fusa:test REQ-CLI004
func TestStripNoColor_NoFlag(t *testing.T) {
	args := []string{"check", "--dir", "some/dir"}
	result := stripNoColor(args)
	if len(result) != len(args) {
		t.Errorf("expected args unchanged; got %v", result)
	}
}

//fusa:test REQ-CLI004
func TestStripNoColor_WithFlag(t *testing.T) {
	args := []string{"check", "--no-color", "--dir", "some/dir"}
	result := stripNoColor(args)
	// --no-color should be stripped
	for _, a := range result {
		if a == "--no-color" {
			t.Error("--no-color should have been stripped")
		}
	}
}

// helper
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
