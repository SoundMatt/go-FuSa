package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SoundMatt/go-FuSa/testutil"
)

// ─── runTraceFuncCoverage unit tests ─────────────────────────────────────────

//fusa:test REQ-CLI-TRACE004
func TestRunTraceFuncCoverage_Pass(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.GoSource("work.go",
		"package main\n\n// DoWork does work.\n//\n//fusa:req REQ-001\nfunc DoWork() error { return nil }\n"))
	var out, errOut bytes.Buffer
	code := runTraceFuncCoverage(dir, 80, &out, &errOut)
	if code != 0 {
		t.Errorf("expected 0, got %d\nstderr: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "100%") {
		t.Error("output should contain 100%")
	}
}

func TestRunTraceFuncCoverage_Fail(t *testing.T) {
	// Exported func with no directly-attached //fusa:req tag → 0%.
	dir := testutil.ProjectDir(t, testutil.GoSource("work.go",
		"package main\n\nfunc DoWork() error { return nil }\n"))
	var out, errOut bytes.Buffer
	code := runTraceFuncCoverage(dir, 80, &out, &errOut)
	if code == 0 {
		t.Error("expected exit 1 when func coverage is below threshold")
	}
	if !strings.Contains(errOut.String(), "func-coverage gate failed") {
		t.Errorf("stderr should mention func-coverage gate failure: %s", errOut.String())
	}
}

func TestRunTraceFuncCoverage_NoFunctions(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	var out, errOut bytes.Buffer
	code := runTraceFuncCoverage(dir, 80, &out, &errOut)
	if code != 0 {
		t.Errorf("expected 0 for project with no exported functions, got %d\nstderr: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "N/A") {
		t.Error("output should contain 'N/A' when there are no exported functions")
	}
}

func TestRunTraceFuncCoverage_FileLevelTagInsufficient(t *testing.T) {
	// A //fusa:req tag that is NOT directly above the function must not
	// count — this is the function-level distinction from --req-coverage's
	// metric 2 (file-level ScanFuncCoverage).
	dir := testutil.ProjectDir(t, testutil.GoSource("work.go",
		"package main\n\n//fusa:req REQ-001\nfunc Tagged() {}\n\nfunc NotDirectlyTagged() {}\n"))
	var out, errOut bytes.Buffer
	code := runTraceFuncCoverage(dir, 80, &out, &errOut)
	if code == 0 {
		t.Error("expected exit 1: only 1/2 functions are directly tagged (50% < 80%)")
	}
	if !strings.Contains(out.String(), "UNTAGGED") {
		t.Error("output should list the untagged function")
	}
}

func TestRunTraceFuncCoverage_UncoveredListTruncated(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	var funcs strings.Builder
	funcs.WriteString("package main\n\n")
	for i := 0; i < 25; i++ {
		funcs.WriteString("func Fn")
		funcs.WriteByte(byte('A' + i))
		funcs.WriteString("() {}\n")
	}
	if err := os.WriteFile(filepath.Join(dir, "fns.go"), []byte(funcs.String()), 0o640); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	runTraceFuncCoverage(dir, 80, &out, &errOut)
	if !strings.Contains(out.String(), "... and") {
		t.Error("expected truncation message for >20 uncovered functions")
	}
}

// ─── CLI integration ──────────────────────────────────────────────────────────

func TestRun_Trace_FuncCoverage_Pass(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.GoSource("work.go",
		"package main\n\n// DoWork does work.\n//\n//fusa:req REQ-001\nfunc DoWork() error { return nil }\n"))
	var out, errOut bytes.Buffer
	code := run([]string{"trace", "--dir", dir, "--func-coverage", "80"}, &out, &errOut)
	if code != 0 {
		t.Errorf("trace --func-coverage 80: exit code = %d\nstdout: %s\nstderr: %s",
			code, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "Function Tag Coverage Report") {
		t.Error("output missing 'Function Tag Coverage Report'")
	}
}

func TestRun_Trace_FuncCoverage_Fail(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.GoSource("work.go",
		"package main\n\nfunc DoWork() error { return nil }\n"))
	var out, errOut bytes.Buffer
	code := run([]string{"trace", "--dir", dir, "--func-coverage", "80"}, &out, &errOut)
	if code == 0 {
		t.Error("trace --func-coverage 80: expected exit 1 for untagged project")
	}
}

func TestRun_Trace_FuncCoverage_Zero_Disabled(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	var out, errOut bytes.Buffer
	code := run([]string{"trace", "--dir", dir, "--func-coverage", "0"}, &out, &errOut)
	if code != 0 {
		t.Errorf("trace --func-coverage 0 (disabled): exit code = %d\nstderr: %s",
			code, errOut.String())
	}
	if strings.Contains(out.String(), "Function Tag Coverage Report") {
		t.Error("disabled gate should not show coverage report")
	}
}
