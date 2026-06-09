package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SoundMatt/go-FuSa/testutil"
	"github.com/SoundMatt/go-FuSa/trace"
)

// ─── runTraceReqCoverage unit tests ──────────────────────────────────────────

func tracedDir(t *testing.T) string {
	t.Helper()
	// One requirement, one impl tag in an annotated file with one exported func.
	dir := testutil.ProjectDir(t, testutil.GoSource("work.go",
		"package main\n\n//fusa:req REQ-001\nfunc DoWork() error { return nil }\n"))
	if err := trace.SaveRequirements(dir, []trace.Requirement{
		{ID: "REQ-001", Title: "Do something"},
	}); err != nil {
		t.Fatalf("SaveRequirements: %v", err)
	}
	return dir
}

//fusa:test REQ-CLI-TRACE003
func TestRunTraceReqCoverage_BothPass(t *testing.T) {
	dir := tracedDir(t)
	matrix, err := trace.Build(dir)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	var out, errOut bytes.Buffer
	code := runTraceReqCoverage(dir, matrix, 80, &out, &errOut)
	if code != 0 {
		t.Errorf("expected 0, got %d\nstderr: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "100%") {
		t.Error("output should contain 100%")
	}
}

func TestRunTraceReqCoverage_Metric1Fail(t *testing.T) {
	// Requirement with no impl tag → 0% metric 1.
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	if err := trace.SaveRequirements(dir, []trace.Requirement{
		{ID: "REQ-001", Title: "Do something"},
	}); err != nil {
		t.Fatalf("SaveRequirements: %v", err)
	}
	// Add a source file with annotated func so metric 2 passes.
	src := "package main\n\n//fusa:req REQ-001\nfunc DoWork() error { return nil }\n"
	if err := os.WriteFile(filepath.Join(dir, "work.go"), []byte(src), 0o640); err != nil {
		t.Fatal(err)
	}
	// Now remove the req annotation so metric 1 fails.
	src2 := "package main\n\nfunc DoWork() error { return nil }\n"
	if err := os.WriteFile(filepath.Join(dir, "work.go"), []byte(src2), 0o640); err != nil {
		t.Fatal(err)
	}
	matrix, err := trace.Build(dir)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	var out, errOut bytes.Buffer
	code := runTraceReqCoverage(dir, matrix, 80, &out, &errOut)
	if code == 0 {
		t.Error("expected exit 1 when metric 1 fails")
	}
	if !strings.Contains(errOut.String(), "metric 1") {
		t.Errorf("stderr should mention metric 1: %s", errOut.String())
	}
}

func TestRunTraceReqCoverage_Metric2Fail(t *testing.T) {
	// Source file with exported func but no annotation → 0% metric 2.
	dir := tracedDir(t)
	// Add a second file with unannotated exported func to drop density below 80%.
	src := "package main\n\nfunc OtherFunc() {}\nfunc AnotherFunc() {}\nfunc ThirdFunc() {}\nfunc FourthFunc() {}\nfunc FifthFunc() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "other.go"), []byte(src), 0o640); err != nil {
		t.Fatal(err)
	}
	matrix, err := trace.Build(dir)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	var out, errOut bytes.Buffer
	code := runTraceReqCoverage(dir, matrix, 80, &out, &errOut)
	if code == 0 {
		t.Error("expected exit 1 when metric 2 falls below threshold")
	}
	if !strings.Contains(errOut.String(), "metric 2") {
		t.Errorf("stderr should mention metric 2: %s", errOut.String())
	}
}

func TestRunTraceReqCoverage_NoRequirementsNoFunctions(t *testing.T) {
	// Empty project: no reqs, no exported funcs → both N/A → exit 0.
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	matrix, err := trace.Build(dir)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	var out, errOut bytes.Buffer
	code := runTraceReqCoverage(dir, matrix, 80, &out, &errOut)
	if code != 0 {
		t.Errorf("expected 0 for empty project, got %d\nstderr: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "N/A") {
		t.Error("output should contain 'N/A' for both metrics")
	}
}

func TestRunTraceReqCoverage_UncoveredListTruncated(t *testing.T) {
	// More than 20 unannotated functions → output should be truncated.
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	var funcs strings.Builder
	funcs.WriteString("package main\n\n")
	for i := 0; i < 25; i++ {
		funcs.WriteString("func ")
		funcs.WriteString("Fn")
		for _, d := range []byte{byte('A' + i)} {
			funcs.WriteByte(d)
		}
		funcs.WriteString("() {}\n")
	}
	if err := os.WriteFile(filepath.Join(dir, "fns.go"), []byte(funcs.String()), 0o640); err != nil {
		t.Fatal(err)
	}
	matrix, err := trace.Build(dir)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	var out, errOut bytes.Buffer
	runTraceReqCoverage(dir, matrix, 80, &out, &errOut)
	if !strings.Contains(out.String(), "... and") {
		t.Error("expected truncation message for >20 uncovered functions")
	}
}

// ─── CLI integration ──────────────────────────────────────────────────────────

func TestRun_Trace_ReqCoverage_Pass(t *testing.T) {
	dir := tracedDir(t)
	var out, errOut bytes.Buffer
	code := run([]string{"trace", "--dir", dir, "--req-coverage", "80"}, &out, &errOut)
	if code != 0 {
		t.Errorf("trace --req-coverage 80: exit code = %d\nstdout: %s\nstderr: %s",
			code, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "Requirement Coverage Report") {
		t.Error("output missing 'Requirement Coverage Report'")
	}
}

func TestRun_Trace_ReqCoverage_Fail(t *testing.T) {
	// No requirements, but has unannotated exported func → metric 2 fails.
	dir := testutil.ProjectDir(t, testutil.GoSource("work.go",
		"package main\n\nfunc DoWork() error { return nil }\n"))
	var out, errOut bytes.Buffer
	code := run([]string{"trace", "--dir", dir, "--req-coverage", "80"}, &out, &errOut)
	if code == 0 {
		t.Error("trace --req-coverage 80: expected exit 1 for unannotated project")
	}
}

func TestRun_Trace_ReqCoverage_Zero_Disabled(t *testing.T) {
	// --req-coverage 0 is disabled — should just show the matrix.
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	var out, errOut bytes.Buffer
	code := run([]string{"trace", "--dir", dir, "--req-coverage", "0"}, &out, &errOut)
	if code != 0 {
		t.Errorf("trace --req-coverage 0 (disabled): exit code = %d\nstderr: %s",
			code, errOut.String())
	}
	// Should show the regular matrix output, not the coverage report.
	if strings.Contains(out.String(), "Requirement Coverage Report") {
		t.Error("disabled gate should not show coverage report")
	}
}
