package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SoundMatt/go-FuSa/testutil"
)

func TestRun_NoArgs(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run(nil, &out, &errOut)
	if code == 0 {
		t.Error("run(nil): expected non-zero exit code")
	}
}

func TestRun_UnknownCommand(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"bogus"}, &out, &errOut)
	if code == 0 {
		t.Error("run(bogus): expected non-zero exit code")
	}
}

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

func TestRun_Check_CleanProject(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	var out, errOut bytes.Buffer
	code := run([]string{"check", "--dir", dir, "--format", "text"}, &out, &errOut)
	if code != 0 {
		t.Errorf("check clean project: exit code = %d, want 0\nstdout: %s\nstderr: %s",
			code, out.String(), errOut.String())
	}
}

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
	for _, name := range []string{"sbom.json", "provenance.json"} {
		if _, err := os.Stat(filepath.Join(outDir, name)); err != nil {
			t.Errorf("release: expected %s to exist: %v", name, err)
		}
	}
}
