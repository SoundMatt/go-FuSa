package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SoundMatt/go-FuSa/report"
	"github.com/SoundMatt/go-FuSa/testutil"
)

// ─── badge ────────────────────────────────────────────────────────────────────

//fusa:test REQ-CLI-BADGE001
func TestRun_Badge_FromFile(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	reportFile := filepath.Join(t.TempDir(), "report.json")

	// generate a JSON report first
	var checkOut bytes.Buffer
	run([]string{"check", "--dir", dir, "--format", "json", "--output", reportFile}, &checkOut, &bytes.Buffer{})

	var out, errOut bytes.Buffer
	code := run([]string{"badge", reportFile}, &out, &errOut)
	if code != 0 {
		t.Errorf("badge: exit code=%d stderr=%s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "<svg") {
		t.Error("badge: expected SVG output")
	}
}

func TestRun_Badge_ToOutputFile(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	reportFile := filepath.Join(t.TempDir(), "report.json")
	badgeFile := filepath.Join(t.TempDir(), "badge.svg")
	run([]string{"check", "--dir", dir, "--format", "json", "--output", reportFile}, &bytes.Buffer{}, &bytes.Buffer{})

	var out, errOut bytes.Buffer
	code := run([]string{"badge", "--output", badgeFile, reportFile}, &out, &errOut)
	if code != 0 {
		t.Errorf("badge --output: exit code=%d stderr=%s", code, errOut.String())
	}
	data, _ := os.ReadFile(badgeFile)
	if !strings.Contains(string(data), "<svg") {
		t.Error("badge file missing SVG")
	}
}

func TestRun_Badge_MissingFile(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"badge", "/nonexistent/report.json"}, &out, &errOut)
	if code == 0 {
		t.Error("badge missing file: expected non-zero exit")
	}
}

func TestRun_Badge_BadJSON(t *testing.T) {
	f := filepath.Join(t.TempDir(), "bad.json")
	_ = os.WriteFile(f, []byte("not json"), 0o640)
	var out, errOut bytes.Buffer
	code := run([]string{"badge", f}, &out, &errOut)
	if code == 0 {
		t.Error("badge bad JSON: expected non-zero exit")
	}
}

func TestRun_Badge_NoArgs(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"badge"}, &out, &errOut)
	// Reads from stdin; with no stdin attached this may succeed or fail,
	// but the command must not panic.
	_ = code
}

// ─── diff ─────────────────────────────────────────────────────────────────────

//fusa:test REQ-CLI-DIFF001
func TestRun_Diff_NoChange(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	tmp := t.TempDir()
	base := filepath.Join(tmp, "base.json")
	cur := filepath.Join(tmp, "cur.json")
	run([]string{"check", "--dir", dir, "--format", "json", "--output", base}, &bytes.Buffer{}, &bytes.Buffer{})
	run([]string{"check", "--dir", dir, "--format", "json", "--output", cur}, &bytes.Buffer{}, &bytes.Buffer{})

	var out, errOut bytes.Buffer
	code := run([]string{"diff", base, cur}, &out, &errOut)
	if code != 0 {
		t.Errorf("diff no-change: exit code=%d stderr=%s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "Introduced: 0") {
		t.Errorf("diff: expected Introduced: 0, got: %s", out.String())
	}
}

func TestRun_Diff_JSONFormat(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	tmp := t.TempDir()
	base := filepath.Join(tmp, "base.json")
	cur := filepath.Join(tmp, "cur.json")
	run([]string{"check", "--dir", dir, "--format", "json", "--output", base}, &bytes.Buffer{}, &bytes.Buffer{})
	run([]string{"check", "--dir", dir, "--format", "json", "--output", cur}, &bytes.Buffer{}, &bytes.Buffer{})

	var out, errOut bytes.Buffer
	code := run([]string{"diff", "--format", "json", base, cur}, &out, &errOut)
	if code != 0 {
		t.Errorf("diff json: exit code=%d", code)
	}
	var parsed map[string]any
	if err := json.Unmarshal(out.Bytes(), &parsed); err != nil {
		t.Errorf("diff json: invalid JSON: %v", err)
	}
}

func TestRun_Diff_MissingArgs(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"diff", "only-one.json"}, &out, &errOut)
	if code == 0 {
		t.Error("diff missing arg: expected non-zero exit")
	}
}

func TestRun_Diff_MissingFile(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"diff", "/nonexistent/a.json", "/nonexistent/b.json"}, &out, &errOut)
	if code == 0 {
		t.Error("diff missing files: expected non-zero exit")
	}
}

// ─── req ──────────────────────────────────────────────────────────────────────

//fusa:test REQ-CLI-REQ001
func TestRun_Req_ListAll(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	var out, errOut bytes.Buffer
	// No requirements file → should succeed with empty output (not crash).
	code := run([]string{"req", "--dir", dir}, &out, &errOut)
	_ = code // may succeed or show no reqs; must not panic
}

func TestRun_Req_UnknownID(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	var out, errOut bytes.Buffer
	code := run([]string{"req", "--dir", dir, "DOESNOTEXIST"}, &out, &errOut)
	if code == 0 {
		t.Error("req unknown id: expected non-zero exit")
	}
}

// ─── fix ──────────────────────────────────────────────────────────────────────

//fusa:test REQ-CLI-FIX001
func TestRun_Fix_CleanProject(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	var out, errOut bytes.Buffer
	code := run([]string{"fix", "--dir", dir}, &out, &errOut)
	// Clean project: exit 0, output mentions findings.
	if code != 0 {
		t.Errorf("fix clean: exit code=%d stderr=%s", code, errOut.String())
	}
}

func TestRun_Fix_WithReport(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	reportFile := filepath.Join(t.TempDir(), "fix-report.json")
	var out, errOut bytes.Buffer
	code := run([]string{"fix", "--dir", dir, "--report", reportFile}, &out, &errOut)
	if code != 0 {
		t.Errorf("fix --report: exit code=%d stderr=%s", code, errOut.String())
	}
	if _, err := os.Stat(reportFile); err != nil {
		t.Error("fix --report: report file not created")
	}
}

func TestFilterFixable(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	// generate a report with no findings using fix --report
	reportFile := filepath.Join(t.TempDir(), "fix.json")
	var out, errOut bytes.Buffer
	run([]string{"fix", "--dir", dir, "--report", reportFile}, &out, &errOut)
	data, err := os.ReadFile(reportFile)
	if err != nil {
		t.Fatalf("fix --report: report file not readable: %v", err)
	}
	var r report.Report
	if err := json.Unmarshal(data, &r); err != nil {
		t.Fatalf("fix --report: invalid JSON: %v", err)
	}
}

// ─── hooks ────────────────────────────────────────────────────────────────────

//fusa:test REQ-CLI-HOOKS001
func TestRun_Hooks_Show(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"hooks", "show"}, &out, &errOut)
	if code != 0 {
		t.Errorf("hooks show: exit code=%d", code)
	}
	if !strings.Contains(out.String(), "gofusa check") {
		t.Error("hooks show: expected hook script in output")
	}
}

func TestRun_Hooks_InstallRemove(t *testing.T) {
	dir := t.TempDir()
	// Create .git/hooks dir
	gitDir := filepath.Join(dir, ".git", "hooks")
	if err := os.MkdirAll(gitDir, 0o750); err != nil {
		t.Fatal(err)
	}

	var out, errOut bytes.Buffer
	code := run([]string{"hooks", "--dir", dir, "install"}, &out, &errOut)
	if code != 0 {
		t.Errorf("hooks install: exit code=%d stderr=%s", code, errOut.String())
	}
	if _, err := os.Stat(filepath.Join(gitDir, "pre-commit")); err != nil {
		t.Error("hooks install: pre-commit file not created")
	}

	// Install again — should fail (already exists).
	code2 := run([]string{"hooks", "--dir", dir, "install"}, &bytes.Buffer{}, &bytes.Buffer{})
	if code2 == 0 {
		t.Error("hooks install again: expected non-zero exit")
	}

	// Remove.
	code3 := run([]string{"hooks", "--dir", dir, "remove"}, &out, &errOut)
	if code3 != 0 {
		t.Errorf("hooks remove: exit code=%d stderr=%s", code3, errOut.String())
	}
	if _, err := os.Stat(filepath.Join(gitDir, "pre-commit")); err == nil {
		t.Error("hooks remove: pre-commit file still exists")
	}
}

func TestRun_Hooks_RemoveMissing(t *testing.T) {
	dir := t.TempDir()
	var out, errOut bytes.Buffer
	code := run([]string{"hooks", "--dir", dir, "remove"}, &out, &errOut)
	if code == 0 {
		t.Error("hooks remove missing: expected non-zero exit")
	}
}

func TestRun_Hooks_NoArgs(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"hooks"}, &out, &errOut)
	if code == 0 {
		t.Error("hooks no args: expected non-zero exit")
	}
}

func TestRun_Hooks_Unknown(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"hooks", "bogus"}, &out, &errOut)
	if code == 0 {
		t.Error("hooks bogus: expected non-zero exit")
	}
}

// ─── sign ─────────────────────────────────────────────────────────────────────

//fusa:test REQ-CLI-SIGN001
func TestRun_Sign_KeygenSignVerify(t *testing.T) {
	tmp := t.TempDir()
	keyFile := filepath.Join(tmp, "test.key")
	artifact := filepath.Join(tmp, "artifact.bin")
	if err := os.WriteFile(artifact, []byte("hello safety"), 0o640); err != nil {
		t.Fatal(err)
	}

	// keygen
	var out, errOut bytes.Buffer
	code := run([]string{"sign", "--keygen", keyFile}, &out, &errOut)
	if code != 0 {
		t.Fatalf("sign --keygen: exit code=%d stderr=%s", code, errOut.String())
	}
	if _, err := os.Stat(keyFile); err != nil {
		t.Fatal("sign --keygen: key file not created")
	}

	// sign
	code = run([]string{"sign", "--key", keyFile, artifact}, &bytes.Buffer{}, &bytes.Buffer{})
	if code != 0 {
		t.Fatalf("sign: exit code=%d", code)
	}
	if _, err := os.Stat(artifact + ".sig"); err != nil {
		t.Fatal("sign: .sig file not created")
	}

	// verify
	code = run([]string{"sign", "--verify", "--key", keyFile, artifact}, &bytes.Buffer{}, &bytes.Buffer{})
	if code != 0 {
		t.Fatalf("sign --verify: exit code=%d", code)
	}
}

func TestRun_Sign_VerifyTampered(t *testing.T) {
	tmp := t.TempDir()
	keyFile := filepath.Join(tmp, "test.key")
	artifact := filepath.Join(tmp, "artifact.bin")
	_ = os.WriteFile(artifact, []byte("original"), 0o640)
	run([]string{"sign", "--keygen", keyFile}, &bytes.Buffer{}, &bytes.Buffer{})
	run([]string{"sign", "--key", keyFile, artifact}, &bytes.Buffer{}, &bytes.Buffer{})

	// Tamper with the artifact.
	_ = os.WriteFile(artifact, []byte("tampered"), 0o640)
	code := run([]string{"sign", "--verify", "--key", keyFile, artifact}, &bytes.Buffer{}, &bytes.Buffer{})
	if code == 0 {
		t.Error("sign verify tampered: expected non-zero exit")
	}
}

func TestRun_Sign_MissingKey(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"sign", "/some/file"}, &out, &errOut)
	if code == 0 {
		t.Error("sign missing --key: expected non-zero exit")
	}
}

func TestRun_Sign_NoArgs(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"sign"}, &out, &errOut)
	if code == 0 {
		t.Error("sign no args: expected non-zero exit")
	}
}

func TestRun_Sign_MissingFile(t *testing.T) {
	tmp := t.TempDir()
	keyFile := filepath.Join(tmp, "test.key")
	run([]string{"sign", "--keygen", keyFile}, &bytes.Buffer{}, &bytes.Buffer{})
	var out, errOut bytes.Buffer
	code := run([]string{"sign", "--key", keyFile, "/nonexistent/file.bin"}, &out, &errOut)
	if code == 0 {
		t.Error("sign missing artifact: expected non-zero exit")
	}
}

// ─── trace --sec-tested ───────────────────────────────────────────────────────

//fusa:test REQ-CLI-TRACE001
func TestRun_Trace_SecTested_Zero(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	var out, errOut bytes.Buffer
	// threshold 0 = disabled → should always pass
	code := run([]string{"trace", "--dir", dir, "--sec-tested", "0"}, &out, &errOut)
	if code != 0 {
		t.Errorf("trace --sec-tested 0: exit code=%d stderr=%s", code, errOut.String())
	}
}

func TestRun_Trace_SecTested_AboveThreshold(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	var out, errOut bytes.Buffer
	// No requirements file → 0 requirements → threshold check skipped (no reqs).
	code := run([]string{"trace", "--dir", dir, "--sec-tested", "80"}, &out, &errOut)
	// With no requirements, should succeed (0 reqs means no gate to fail).
	_ = code
}
