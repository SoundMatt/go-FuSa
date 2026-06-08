package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SoundMatt/go-FuSa/testutil"
)

//fusa:test REQ-CLI001
func TestRun_NoArgs(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run(nil, &out, &errOut)
	if code == 0 {
		t.Error("run(nil): expected non-zero exit code")
	}
}

//fusa:test REQ-CLI002
func TestRun_UnknownCommand(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"bogus"}, &out, &errOut)
	if code == 0 {
		t.Error("run(bogus): expected non-zero exit code")
	}
}

//fusa:test REQ-CLI003
func TestRun_Help(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"help"}, &out, &errOut)
	if code != 0 {
		t.Errorf("run(help): exit code = %d, want 0", code)
	}
	if !strings.Contains(out.String(), "gofusa") {
		t.Error("help output missing 'gofusa'")
	}
}

//fusa:test REQ-CLI004
func TestRun_Version(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"version"}, &out, &errOut)
	if code != 0 {
		t.Errorf("run(version): exit code = %d, want 0", code)
	}
	if !strings.Contains(out.String(), "gofusa") {
		t.Error("version output missing 'gofusa'")
	}
}

//fusa:test REQ-CLI005
func TestRun_Check_CleanProject(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	var out, errOut bytes.Buffer
	code := run([]string{"check", "--dir", dir, "--format", "text"}, &out, &errOut)
	if code != 0 {
		t.Errorf("check clean project: exit code = %d, want 0\nstdout: %s\nstderr: %s",
			code, out.String(), errOut.String())
	}
}

//fusa:test REQ-CLI006
func TestRun_Check_MissingConfig_FallsBack(t *testing.T) {
	// A project without .fusa.json should still run (engine provides defaults).
	dir := testutil.ProjectDir(t, map[string]string{
		"go.mod":                   "module github.com/x/y\n\ngo 1.22\n",
		"LICENSE":                  "MPL 2.0\n",
		"README.md":                "# y\n",
		".github/workflows/ci.yml": "name: CI\n",
	})
	var out, errOut bytes.Buffer
	// FUSA001 (missing .fusa.json) will produce an ERROR → exit 1.
	code := run([]string{"check", "--dir", dir}, &out, &errOut)
	if code == 0 {
		t.Error("check without .fusa.json: expected exit 1 (FUSA001 error)")
	}
}

func TestRun_Check_JSONFormat(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	var out, errOut bytes.Buffer
	code := run([]string{"check", "--dir", dir, "--format", "json"}, &out, &errOut)
	if code != 0 {
		t.Errorf("check json: exit code = %d\n%s", code, errOut.String())
	}
	if !strings.Contains(out.String(), `"summary"`) {
		t.Error("JSON output missing 'summary' field")
	}
}

func TestRun_Check_OutputFile(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	outFile := filepath.Join(t.TempDir(), "report.txt")
	var out, errOut bytes.Buffer
	code := run([]string{"check", "--dir", dir, "--output", outFile}, &out, &errOut)
	if code != 0 {
		t.Errorf("check --output: exit code = %d\n%s", code, errOut.String())
	}
}

func TestRun_Report(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	var out, errOut bytes.Buffer
	code := run([]string{"report", "--dir", dir}, &out, &errOut)
	if code != 0 {
		t.Errorf("report: exit code = %d\n%s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "Summary") {
		t.Error("report output missing 'Summary'")
	}
}

func TestRun_Init(t *testing.T) {
	dir := testutil.ProjectDir(t, map[string]string{
		"go.mod": "module github.com/example/newproject\n\ngo 1.22\n",
	})
	var out, errOut bytes.Buffer
	code := run([]string{"init", "--dir", dir}, &out, &errOut)
	if code != 0 {
		t.Errorf("init: exit code = %d\n%s", code, errOut.String())
	}
	if !strings.Contains(out.String(), ".fusa.json") {
		t.Error("init output missing .fusa.json")
	}
}

func TestRun_Init_AlreadyExists(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	var out, errOut bytes.Buffer
	code := run([]string{"init", "--dir", dir}, &out, &errOut)
	if code == 0 {
		t.Error("init existing: expected non-zero exit code")
	}
}

func TestRun_Init_WithDocs(t *testing.T) {
	dir := testutil.ProjectDir(t, map[string]string{
		"go.mod": "module github.com/example/newproject\n\ngo 1.22\n",
	})
	var out, errOut bytes.Buffer
	code := run([]string{"init", "--dir", dir, "--docs"}, &out, &errOut)
	if code != 0 {
		t.Errorf("init --docs: exit code = %d\n%s", code, errOut.String())
	}
}

// ─── lint ─────────────────────────────────────────────────────────────────────

//fusa:test REQ-CLI008
func TestRun_Lint_CleanProject(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	var out, errOut bytes.Buffer
	code := run([]string{"lint", "--dir", dir}, &out, &errOut)
	if code != 0 {
		t.Errorf("lint clean project: exit code = %d\n%s", code, errOut.String())
	}
}

func TestRun_Lint_OnlyLintFindings(t *testing.T) {
	src := "package main\n\nimport \"os\"\n\nfunc f() {\n\tx, _ := os.Open(\"\")\n\t_ = x\n}\n"
	files := testutil.MinimalProject()
	files["bad.go"] = src
	dir := testutil.ProjectDir(t, files)
	var out, errOut bytes.Buffer
	code := run([]string{"lint", "--dir", dir, "--format", "text"}, &out, &errOut)
	if code != 0 {
		t.Errorf("lint: unexpected exit code %d\n%s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "LINT001") {
		t.Error("lint: expected LINT001 in output")
	}
}

func TestRun_Lint_Help(t *testing.T) {
	var out, errOut bytes.Buffer
	_ = run([]string{"lint", "--help"}, &out, &errOut)
	if !strings.Contains(out.String()+errOut.String(), "gofusa lint") {
		t.Error("lint --help: output missing 'gofusa lint'")
	}
}

func TestRun_Lint_Strict_FailsOnWarning(t *testing.T) {
	src := "package main\n\nimport \"os\"\n\nfunc f() {\n\tx, _ := os.Open(\"\")\n\t_ = x\n}\n"
	files := testutil.MinimalProject()
	files["bad.go"] = src
	dir := testutil.ProjectDir(t, files)
	var out, errOut bytes.Buffer
	code := run([]string{"lint", "--dir", dir, "--strict"}, &out, &errOut)
	if code == 0 {
		t.Error("lint --strict: expected exit 1 when LINT001 WARNING present")
	}
}

func TestRun_Lint_BadConfig(t *testing.T) {
	dir := testutil.ProjectDir(t, map[string]string{
		"go.mod":     "module github.com/x/y\n\ngo 1.22\n",
		".fusa.json": "not valid json",
	})
	var out, errOut bytes.Buffer
	code := run([]string{"lint", "--dir", dir}, &out, &errOut)
	if code == 0 {
		t.Error("lint with bad config: expected non-zero exit code")
	}
}

// ─── analyze ──────────────────────────────────────────────────────────────────

//fusa:test REQ-CLI009
func TestRun_Analyze_CleanProject(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	var out, errOut bytes.Buffer
	code := run([]string{"analyze", "--dir", dir}, &out, &errOut)
	if code != 0 {
		t.Errorf("analyze clean project: exit code = %d\n%s", code, errOut.String())
	}
}

func TestRun_Analyze_Help(t *testing.T) {
	var out, errOut bytes.Buffer
	_ = run([]string{"analyze", "--help"}, &out, &errOut)
	if !strings.Contains(out.String()+errOut.String(), "gofusa analyze") {
		t.Error("analyze --help: output missing 'gofusa analyze'")
	}
}

// ─── template ─────────────────────────────────────────────────────────────────

//fusa:test REQ-CLI010
func TestRun_Template_SafetyPlan(t *testing.T) {
	dir := t.TempDir()
	var out, errOut bytes.Buffer
	code := run([]string{"template", "--dir", dir, "--type", "safety-plan"}, &out, &errOut)
	if code != 0 {
		t.Errorf("template safety-plan: exit code = %d\n%s", code, errOut.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "SAFETY_PLAN.md")); err != nil {
		t.Errorf("template: expected SAFETY_PLAN.md to exist: %v", err)
	}
}

func TestRun_Template_All(t *testing.T) {
	dir := t.TempDir()
	var out, errOut bytes.Buffer
	code := run([]string{"template", "--dir", dir, "--type", "all"}, &out, &errOut)
	if code != 0 {
		t.Errorf("template all: exit code = %d\n%s", code, errOut.String())
	}
	for _, name := range []string{"SAFETY_PLAN.md", "TEST_EVIDENCE.md", "HARA.md"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("template: expected %s to exist: %v", name, err)
		}
	}
}

func TestRun_Template_Help(t *testing.T) {
	var out, errOut bytes.Buffer
	_ = run([]string{"template", "--help"}, &out, &errOut)
	if !strings.Contains(out.String()+errOut.String(), "gofusa template") {
		t.Error("template --help: output missing 'gofusa template'")
	}
}

// ─── check --strict ───────────────────────────────────────────────────────────

//fusa:test REQ-CLI011
func TestRun_Check_Strict_FailsOnWarning(t *testing.T) {
	// MinimalProject has no sbom.json → RELEASE001 WARNING.
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	var out, errOut bytes.Buffer
	code := run([]string{"check", "--dir", dir, "--strict"}, &out, &errOut)
	if code == 0 {
		t.Error("check --strict: expected exit 1 when WARNING findings exist")
	}
}

func TestRun_Check_Strict_PassesOnInfoOnly(t *testing.T) {
	files := testutil.MinimalProject()
	files["sbom.json"] = `{"@context":"https://spdx.org/rdf/3.0.1/spdx-context.jsonld","@graph":[]}`
	files["provenance.json"] = `{"format":"go-FuSa Provenance v1"}`
	files[".fusa-evidence.json"] = `{"generatedAt":"2026-01-01T00:00:00Z","projectRoot":".","goVersion":"go1.22","results":[],"summary":{"total":0,"passed":0,"failed":0,"skipped":0}}`
	files["qualify-report.json"] = `{"generatedAt":"2026-01-01T00:00:00Z","total":44,"passed":44,"failed":0,"results":[],"hash":"x"}`
	dir := testutil.ProjectDir(t, files)
	var out, errOut bytes.Buffer
	code := run([]string{"check", "--dir", dir, "--strict"}, &out, &errOut)
	if code != 0 {
		t.Errorf("check --strict with INFO-only: exit code = %d\nstdout: %s\nstderr: %s",
			code, out.String(), errOut.String())
	}
}

// ─── trace ────────────────────────────────────────────────────────────────────

func TestRun_Trace_Help(t *testing.T) {
	var out, errOut bytes.Buffer
	// --help exits non-zero with flag.ContinueOnError; we only check output.
	_ = run([]string{"trace", "--help"}, &out, &errOut)
	combined := out.String() + errOut.String()
	if !strings.Contains(combined, "gofusa trace") {
		t.Error("trace --help: output missing 'gofusa trace'")
	}
}

func TestRun_Trace_NoReqs(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	var out, errOut bytes.Buffer
	code := run([]string{"trace", "--dir", dir}, &out, &errOut)
	if code != 0 {
		t.Errorf("trace (no reqs): exit code = %d\n%s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "Traceability") {
		t.Error("trace output missing 'Traceability'")
	}
}

func TestRun_Trace_JSONFormat(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	var out, errOut bytes.Buffer
	code := run([]string{"trace", "--dir", dir, "--format", "json"}, &out, &errOut)
	if code != 0 {
		t.Errorf("trace --format json: exit code = %d\n%s", code, errOut.String())
	}
	if !strings.Contains(out.String(), `"requirements"`) {
		t.Error("trace json: output missing 'requirements' field")
	}
}

func TestRun_Trace_OutputFile(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	outFile := filepath.Join(t.TempDir(), "matrix.txt")
	var out, errOut bytes.Buffer
	code := run([]string{"trace", "--dir", dir, "--output", outFile}, &out, &errOut)
	if code != 0 {
		t.Errorf("trace --output: exit code = %d\n%s", code, errOut.String())
	}
}

// ─── qualify ──────────────────────────────────────────────────────────────────

func TestRun_Qualify_Help(t *testing.T) {
	var out, errOut bytes.Buffer
	_ = run([]string{"qualify", "--help"}, &out, &errOut)
	combined := out.String() + errOut.String()
	if !strings.Contains(combined, "gofusa qualify") {
		t.Error("qualify --help: output missing 'gofusa qualify'")
	}
}

//fusa:test REQ-CLI007
func TestRun_Qualify_AllPass(t *testing.T) {
	outFile := filepath.Join(t.TempDir(), "qualify-report.json")
	var out, errOut bytes.Buffer
	code := run([]string{"qualify", "--output", outFile}, &out, &errOut)
	if code != 0 {
		t.Errorf("qualify: exit code = %d\nstdout: %s\nstderr: %s",
			code, out.String(), errOut.String())
	}
	if _, err := os.Stat(outFile); err != nil {
		t.Errorf("qualify: expected %s to exist: %v", outFile, err)
	}
	if !strings.Contains(out.String(), "passed") {
		t.Error("qualify: output missing 'passed'")
	}
}

// ─── release ──────────────────────────────────────────────────────────────────

func TestRun_Release_Help(t *testing.T) {
	var out, errOut bytes.Buffer
	run([]string{"release", "--help"}, &out, &errOut)
	combined := out.String() + errOut.String()
	if !strings.Contains(combined, "gofusa release") {
		t.Error("release --help: output missing 'gofusa release'")
	}
}

func TestRun_Release_GeneratesFiles(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	outDir := t.TempDir()
	var out, errOut bytes.Buffer
	code := run([]string{"release", "--dir", dir, "--output-dir", outDir}, &out, &errOut)
	if code != 0 {
		t.Errorf("release: exit code = %d\n%s", code, errOut.String())
	}
	for _, name := range []string{"sbom.json", "provenance.json", "artifact-manifest.json"} {
		if _, err := os.Stat(filepath.Join(outDir, name)); err != nil {
			t.Errorf("release: expected %s to exist: %v", name, err)
		}
	}
}

// ─── safety-case ──────────────────────────────────────────────────────────────

func TestRun_SafetyCase_Help(t *testing.T) {
	var out, errOut bytes.Buffer
	_ = run([]string{"safety-case", "--help"}, &out, &errOut)
	combined := out.String() + errOut.String()
	if !strings.Contains(combined, "gofusa safety-case") {
		t.Error("safety-case --help: output missing 'gofusa safety-case'")
	}
}

//fusa:test REQ-CLI012
func TestRun_SafetyCase_GeneratesFiles(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	outDir := t.TempDir()
	var out, errOut bytes.Buffer
	code := run([]string{"safety-case", "--dir", dir, "--output-dir", outDir}, &out, &errOut)
	if code != 0 {
		t.Errorf("safety-case: exit code = %d\n%s", code, errOut.String())
	}
	for _, name := range []string{"safety-case.json", "safety-case.md", "safety-case.mermaid"} {
		if _, err := os.Stat(filepath.Join(outDir, name)); err != nil {
			t.Errorf("safety-case: expected %s to exist: %v", name, err)
		}
	}
	if !strings.Contains(out.String(), "Safety case written") {
		t.Error("safety-case: output missing 'Safety case written'")
	}
}

func TestRun_SafetyCase_WithAllEvidence(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	// plant evidence files so all items are present
	for name, content := range map[string]string{
		"check-report.json":   `{"summary":{"total":0,"errors":0,"warnings":0,"infos":0}}`,
		".fusa-reqs.json":     `{"requirements":[{"id":"REQ-001"}]}`,
		".fusa-evidence.json": `{"summary":{"total":5,"passed":5,"failed":0,"skipped":0}}`,
		"qualify-report.json": `{"total":44,"passed":44,"failed":0}`,
		"sbom.json":           `{"@context":"x","@graph":[]}`,
		"provenance.json":     `{"format":"go-FuSa Provenance v1"}`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	outDir := t.TempDir()
	var out, errOut bytes.Buffer
	code := run([]string{"safety-case", "--dir", dir, "--output-dir", outDir}, &out, &errOut)
	if code != 0 {
		t.Errorf("safety-case all-evidence: exit code = %d\n%s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "Gaps: none") {
		t.Errorf("safety-case all-evidence: expected 'Gaps: none'\nout: %s", out.String())
	}
}

// ─── fmea ─────────────────────────────────────────────────────────────────────

func TestRun_FMEA_Help(t *testing.T) {
	var out, errOut bytes.Buffer
	_ = run([]string{"fmea", "--help"}, &out, &errOut)
	if !strings.Contains(out.String()+errOut.String(), "gofusa fmea") {
		t.Error("fmea --help: output missing 'gofusa fmea'")
	}
}

//fusa:test REQ-CLI013
func TestRun_FMEA_GeneratesFiles(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	outDir := t.TempDir()
	var out, errOut bytes.Buffer
	code := run([]string{"fmea", "--dir", dir, "--output-dir", outDir}, &out, &errOut)
	if code != 0 {
		t.Errorf("fmea: exit code = %d\n%s", code, errOut.String())
	}
	for _, name := range []string{"fmea.json", "fmea.csv"} {
		if _, err := os.Stat(filepath.Join(outDir, name)); err != nil {
			t.Errorf("fmea: expected %s to exist: %v", name, err)
		}
	}
	if !strings.Contains(out.String(), "Entries:") {
		t.Error("fmea: output missing 'Entries:'")
	}
}

func TestRun_FMEA_WithGoSource(t *testing.T) {
	files := testutil.GoSource("mypkg/work.go", `package mypkg

//fusa:req REQ-TEST001
func DoWork() error { return nil }
`)
	dir := testutil.ProjectDir(t, files)
	outDir := t.TempDir()
	var out, errOut bytes.Buffer
	code := run([]string{"fmea", "--dir", dir, "--output-dir", outDir}, &out, &errOut)
	if code != 0 {
		t.Errorf("fmea with source: exit code = %d\n%s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "high:") {
		t.Error("fmea with source: expected high severity entry for safety-req function")
	}
}

// ─── boundary ─────────────────────────────────────────────────────────────────

func TestRun_Boundary_Help(t *testing.T) {
	var out, errOut bytes.Buffer
	_ = run([]string{"boundary", "--help"}, &out, &errOut)
	if !strings.Contains(out.String()+errOut.String(), "gofusa boundary") {
		t.Error("boundary --help: output missing 'gofusa boundary'")
	}
}

//fusa:test REQ-CLI014
func TestRun_Boundary_GeneratesFiles(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	outDir := t.TempDir()
	var out, errOut bytes.Buffer
	code := run([]string{"boundary", "--dir", dir, "--output-dir", outDir}, &out, &errOut)
	if code != 0 {
		t.Errorf("boundary: exit code = %d\n%s", code, errOut.String())
	}
	for _, name := range []string{"boundary.mermaid", "boundary.dot"} {
		if _, err := os.Stat(filepath.Join(outDir, name)); err != nil {
			t.Errorf("boundary: expected %s to exist: %v", name, err)
		}
	}
	if !strings.Contains(out.String(), "Packages:") {
		t.Error("boundary: output missing 'Packages:'")
	}
}

func TestRun_Boundary_WithPackages(t *testing.T) {
	files := testutil.MinimalProject()
	files["pkga/a.go"] = `package pkga
import "github.com/example/test/pkgb"
func DoA() { pkgb.DoB() }
`
	files["pkgb/b.go"] = `package pkgb
func DoB() {}
`
	dir := testutil.ProjectDir(t, files)
	outDir := t.TempDir()
	var out, errOut bytes.Buffer
	code := run([]string{"boundary", "--dir", dir, "--output-dir", outDir}, &out, &errOut)
	if code != 0 {
		t.Errorf("boundary with packages: exit code = %d\n%s", code, errOut.String())
	}
	mermaid, err := os.ReadFile(filepath.Join(outDir, "boundary.mermaid"))
	if err != nil {
		t.Fatalf("boundary.mermaid not found: %v", err)
	}
	if !strings.Contains(string(mermaid), "-->") {
		t.Error("boundary.mermaid: expected edges (-->)")
	}
}
