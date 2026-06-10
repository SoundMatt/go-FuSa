package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ─── hooksInstall success path ────────────────────────────────────────────────

func TestHooksInstall_Success_V025(t *testing.T) {
	dir := t.TempDir()
	hookPath := filepath.Join(dir, ".git", "hooks", "pre-commit")
	var out, errBuf bytes.Buffer
	code := hooksInstall(hookPath, &out, &errBuf)
	if code != 0 {
		t.Fatalf("hooksInstall: exit %d, stderr: %s", code, errBuf.String())
	}
	if _, err := os.Stat(hookPath); err != nil {
		t.Errorf("hook file not created: %v", err)
	}
	if !strings.Contains(out.String(), "pre-commit hook installed") {
		t.Errorf("expected installed message, got: %s", out.String())
	}
}

// ─── hooksRemove success path ─────────────────────────────────────────────────

func TestHooksRemove_Success_V025(t *testing.T) {
	dir := t.TempDir()
	hookPath := filepath.Join(dir, "pre-commit")
	if err := os.WriteFile(hookPath, []byte("#!/bin/sh\n"), 0o750); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	code := hooksRemove(hookPath, &out, &errBuf)
	if code != 0 {
		t.Fatalf("hooksRemove: exit %d, stderr: %s", code, errBuf.String())
	}
	if _, err := os.Stat(hookPath); !os.IsNotExist(err) {
		t.Error("hook file still exists after remove")
	}
	if !strings.Contains(out.String(), "pre-commit hook removed") {
		t.Errorf("expected removed message, got: %s", out.String())
	}
}

// ─── runHaraShow paths ────────────────────────────────────────────────────────

func TestRunHaraShow_JSON_V025(t *testing.T) {
	dir := t.TempDir()
	var initOut, initErr bytes.Buffer
	if code := run([]string{"hara", "--dir", dir, "init"}, &initOut, &initErr); code != 0 {
		t.Fatalf("hara init: %s", initErr.String())
	}
	var out, errBuf bytes.Buffer
	code := runHaraShow([]string{"-format", "json"}, dir, &out, &errBuf)
	if code != 0 {
		t.Fatalf("runHaraShow json: exit %d, stderr: %s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), `"project"`) {
		t.Errorf("expected json output, got: %s", out.String())
	}
}

func TestRunHaraShow_Markdown_Output(t *testing.T) {
	dir := t.TempDir()
	var initOut, initErr bytes.Buffer
	if code := run([]string{"hara", "--dir", dir, "init"}, &initOut, &initErr); code != 0 {
		t.Fatalf("hara init: %s", initErr.String())
	}
	outFile := filepath.Join(dir, "hara.md")
	var out, errBuf bytes.Buffer
	code := runHaraShow([]string{"-format", "markdown", "-output", outFile}, dir, &out, &errBuf)
	if code != 0 {
		t.Fatalf("runHaraShow markdown: exit %d, stderr: %s", code, errBuf.String())
	}
	if _, err := os.Stat(outFile); err != nil {
		t.Errorf("output file not created: %v", err)
	}
}

func TestRunHaraShow_BadFlag(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runHaraShow([]string{"--no-such-flag"}, t.TempDir(), &out, &errBuf)
	if code != 2 {
		t.Errorf("expected exit 2 (usage), got %d", code)
	}
}

// ─── runRelease --full ────────────────────────────────────────────────────────

func TestRunRelease_Full_V025(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/test\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(dir, "out")
	var out, errBuf bytes.Buffer
	code := runRelease([]string{"--dir", dir, "--output-dir", outDir, "--full"}, &out, &errBuf)
	// exit 0 (success) or 1 (gate) or 3 (runtime) — any is valid, must not panic
	if code > 3 {
		t.Errorf("unexpected exit %d; stderr: %s", code, errBuf.String())
	}
}

// ─── runLint --output path ────────────────────────────────────────────────────

func TestRunLint_WithOutput(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/test\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	outFile := filepath.Join(dir, "lint.json")
	var out, errBuf bytes.Buffer
	code := runLint([]string{"--dir", dir, "--format", "json", "--output", outFile}, &out, &errBuf)
	if code != 0 && code != 1 {
		t.Errorf("runLint with output: unexpected exit %d; stderr: %s", code, errBuf.String())
	}
	if _, err := os.Stat(outFile); err != nil {
		t.Errorf("output file not created: %v", err)
	}
}

// ─── runUNECE additional paths ────────────────────────────────────────────────

func TestRunUNECE_Text(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	runUNECE([]string{"--dir", dir, "--format", "text"}, &out, &errBuf)
}

func TestRunUNECE_GateFail(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runUNECE([]string{"--dir", dir}, &out, &errBuf)
	if code != 1 {
		t.Errorf("empty dir: expected exit 1 (gate fail), got %d", code)
	}
}

// ─── runISO21434 additional paths ─────────────────────────────────────────────

func TestRunISO21434_Text(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runISO21434([]string{"--dir", dir, "--format", "text"}, &out, &errBuf)
	if code != 0 && code != 1 {
		t.Errorf("iso21434 text: unexpected exit %d; stderr: %s", code, errBuf.String())
	}
}

// ─── runIEC61508 text ─────────────────────────────────────────────────────────

func TestRunIEC61508_Text(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	runIEC61508([]string{"--dir", dir, "--sil", "SIL-3", "--format", "text"}, &out, &errBuf)
}

// ─── runISO26262 text + ASIL-D ────────────────────────────────────────────────

func TestRunISO26262_Text(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	runISO26262([]string{"--dir", dir, "--asil", "ASIL-C", "--format", "text"}, &out, &errBuf)
}

func TestRunISO26262_ASILD(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runISO26262([]string{"--dir", dir, "--asil", "ASIL-D"}, &out, &errBuf)
	if code != 0 && code != 1 {
		t.Errorf("ASIL-D: unexpected exit %d", code)
	}
}

// ─── runVersion invalid format ────────────────────────────────────────────────

func TestRunVersion_InvalidFormat(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runVersion([]string{"--format", "xml"}, &out, &errBuf)
	// invalid format is a usage error (exit 2)
	if code != 2 {
		t.Errorf("invalid format: expected exit 2 (usage), got %d", code)
	}
}

// ─── runImpact text ───────────────────────────────────────────────────────────

func TestRunImpact_Text(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	runImpact([]string{"--dir", dir, "--format", "text"}, &out, &errBuf)
}

// ─── runFix json ──────────────────────────────────────────────────────────────

func TestRunFix_JSON(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/test\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	runFix([]string{"--dir", dir, "--format", "json"}, &out, &errBuf)
}

// ─── runBoundary paths ────────────────────────────────────────────────────────

func TestRunBoundary_WithOutputDir_V025(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/test\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(dir, "out")
	var out, errBuf bytes.Buffer
	code := runBoundary([]string{"--dir", dir, "--output-dir", outDir}, &out, &errBuf)
	if code != 0 && code != 1 {
		t.Errorf("runBoundary with output-dir: unexpected exit %d; stderr: %s", code, errBuf.String())
	}
}

// ─── runVuln json ─────────────────────────────────────────────────────────────

func TestRunVuln_JSON(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/test\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	runVuln([]string{"--dir", dir, "--format", "json"}, &out, &errBuf)
}

// ─── runTara json ─────────────────────────────────────────────────────────────

func TestRunTara_JSON(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	runTara([]string{"--dir", dir, "--format", "json"}, &out, &errBuf)
}

// ─── runVerify json ───────────────────────────────────────────────────────────

func TestRunVerify_JSON(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	runVerify([]string{"--dir", dir, "--format", "json"}, &out, &errBuf)
}

// ─── signKeygen overwrites existing file ─────────────────────────────────────

func TestSignKeygen_Overwrite(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "fusa.key")
	if err := os.WriteFile(keyFile, []byte("old-content\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	code := signKeygen(keyFile, &out, &errBuf)
	if code != 0 {
		t.Fatalf("signKeygen overwrite: exit %d, stderr: %s", code, errBuf.String())
	}
	// key should have been replaced with a 32-byte hex string
	data, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) == "old-content\n" {
		t.Error("key file was not overwritten")
	}
	if len(strings.TrimSpace(string(data))) != 64 {
		t.Errorf("unexpected key content length: %q", string(data))
	}
}

// ─── gap-report commands: render error path (bad format) ─────────────────────

func TestRunUNECE_BadFormat(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runUNECE([]string{"--dir", dir, "--format", "xml"}, &out, &errBuf)
	if code != 3 {
		t.Errorf("bad format: expected exit 3 (runtime), got %d", code)
	}
}

func TestRunISO21434_BadFormat(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runISO21434([]string{"--dir", dir, "--format", "xml"}, &out, &errBuf)
	if code != 3 {
		t.Errorf("bad format: expected exit 3 (runtime), got %d", code)
	}
}

func TestRunIEC61508_BadFormat(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runIEC61508([]string{"--dir", dir, "--sil", "SIL-1", "--format", "xml"}, &out, &errBuf)
	if code != 3 {
		t.Errorf("bad format: expected exit 3 (runtime), got %d", code)
	}
}

func TestRunISO26262_BadFormat(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runISO26262([]string{"--dir", dir, "--asil", "ASIL-B", "--format", "xml"}, &out, &errBuf)
	if code != 3 {
		t.Errorf("bad format: expected exit 3 (runtime), got %d", code)
	}
}

// ─── gap-report commands: output file creation error ─────────────────────────

func TestRunUNECE_BadOutput(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runUNECE([]string{"--dir", dir, "--output", "/nonexistent/dir/file.json"}, &out, &errBuf)
	if code != 3 {
		t.Errorf("bad output: expected exit 3 (runtime), got %d", code)
	}
}

func TestRunISO21434_BadOutput(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runISO21434([]string{"--dir", dir, "--output", "/nonexistent/dir/file.json"}, &out, &errBuf)
	if code != 3 {
		t.Errorf("bad output: expected exit 3 (runtime), got %d", code)
	}
}

func TestRunIEC61508_BadOutput(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runIEC61508([]string{"--dir", dir, "--sil", "SIL-2", "--output", "/nonexistent/dir/file.json"}, &out, &errBuf)
	if code != 3 {
		t.Errorf("bad output: expected exit 3 (runtime), got %d", code)
	}
}

func TestRunISO26262_BadOutput(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runISO26262([]string{"--dir", dir, "--asil", "ASIL-B", "--output", "/nonexistent/dir/file.json"}, &out, &errBuf)
	if code != 3 {
		t.Errorf("bad output: expected exit 3 (runtime), got %d", code)
	}
}

// ─── gap-report commands: no --dir (exercises os.Getwd path) ─────────────────

func TestRunUNECE_NoDir(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runUNECE([]string{"--format", "json"}, &out, &errBuf)
	if code > 3 {
		t.Errorf("runUNECE no --dir: unexpected exit %d", code)
	}
}

func TestRunISO21434_NoDir(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runISO21434([]string{"--format", "json"}, &out, &errBuf)
	if code > 3 {
		t.Errorf("runISO21434 no --dir: unexpected exit %d", code)
	}
}

func TestRunIEC61508_NoDir(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runIEC61508([]string{"--sil", "SIL-1", "--format", "json"}, &out, &errBuf)
	if code > 3 {
		t.Errorf("runIEC61508 no --dir: unexpected exit %d", code)
	}
}

func TestRunISO26262_NoDir(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runISO26262([]string{"--asil", "ASIL-A", "--format", "json"}, &out, &errBuf)
	if code > 3 {
		t.Errorf("runISO26262 no --dir: unexpected exit %d", code)
	}
}

// ─── prList error path (bad file) ────────────────────────────────────────────

func TestPrList_BadFile(t *testing.T) {
	dir := t.TempDir()
	badPath := filepath.Join(dir, "notjson.json")
	if err := os.WriteFile(badPath, []byte("not json {"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	code := prList(badPath, &out, &errBuf)
	if code != 3 {
		t.Errorf("bad file: expected exit 3 (runtime), got %d", code)
	}
}

// ─── hooksRemove ExitRuntime (path is non-empty directory) ───────────────────

func TestHooksRemove_RuntimeError(t *testing.T) {
	dir := t.TempDir()
	// Create a non-empty directory at hookPath — os.Remove fails with non-IsNotExist error
	hookPath := filepath.Join(dir, "not-a-hook")
	if err := os.MkdirAll(hookPath, 0o750); err != nil {
		t.Fatal(err)
	}
	// Put a file inside so it's non-empty (os.Remove on non-empty dir = ENOTEMPTY)
	if err := os.WriteFile(filepath.Join(hookPath, "sentinel"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	code := hooksRemove(hookPath, &out, &errBuf)
	if code != 3 {
		t.Errorf("non-empty dir: expected exit 3 (runtime), got %d", code)
	}
}

// ─── hooksInstall MkdirAll error (file occupies hooks dir path) ──────────────

func TestHooksInstall_MkdirAllError(t *testing.T) {
	dir := t.TempDir()
	// Place a regular file where the hooks directory would be created
	hooksDir := filepath.Join(dir, "hooks")
	if err := os.WriteFile(hooksDir, []byte("blocking file"), 0o644); err != nil {
		t.Fatal(err)
	}
	hookPath := filepath.Join(hooksDir, "pre-commit")
	var out, errBuf bytes.Buffer
	// hookPath doesn't exist (parent is a file), Stat fails → not AlreadyExists
	// MkdirAll(hooksDir) fails because hooksDir is a file
	code := hooksInstall(hookPath, &out, &errBuf)
	if code != 3 {
		t.Errorf("file-as-hooksdir: expected exit 3 (runtime), got %d", code)
	}
}

// ─── no-dir tests: exercise os.Getwd() path in each command ──────────────────

// These tests call each command WITHOUT --dir so os.Getwd() is exercised.
// They use temp output dirs / output files to avoid polluting the repo.

func TestRunBoundary_NoDir(t *testing.T) {
	outDir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runBoundary([]string{"--output-dir", outDir}, &out, &errBuf)
	if code > 3 {
		t.Errorf("runBoundary no --dir: unexpected exit %d", code)
	}
}

func TestRunCheck_NoDir(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runCheck([]string{}, &out, &errBuf)
	if code > 3 {
		t.Errorf("runCheck no --dir: unexpected exit %d", code)
	}
}

func TestRunCoupling_NoDir(t *testing.T) {
	outFile := filepath.Join(t.TempDir(), "coupling.json")
	var out, errBuf bytes.Buffer
	code := runCoupling([]string{"--output", outFile}, &out, &errBuf)
	if code > 3 {
		t.Errorf("runCoupling no --dir: unexpected exit %d", code)
	}
}

func TestRunCyber_NoDir(t *testing.T) {
	outFile := filepath.Join(t.TempDir(), "cyber.json")
	var out, errBuf bytes.Buffer
	code := runCyber([]string{"--output", outFile}, &out, &errBuf)
	if code > 3 {
		t.Errorf("runCyber no --dir: unexpected exit %d", code)
	}
}

func TestRunFix_NoDir(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runFix([]string{}, &out, &errBuf)
	if code > 3 {
		t.Errorf("runFix no --dir: unexpected exit %d", code)
	}
}

func TestRunFmea_NoDir(t *testing.T) {
	outDir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runFmea([]string{"--output-dir", outDir}, &out, &errBuf)
	if code > 3 {
		t.Errorf("runFmea no --dir: unexpected exit %d", code)
	}
}

func TestRunImpact_NoDir(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runImpact([]string{}, &out, &errBuf)
	if code > 3 {
		t.Errorf("runImpact no --dir: unexpected exit %d", code)
	}
}

func TestRunLint_NoDir(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runLint([]string{}, &out, &errBuf)
	if code > 3 {
		t.Errorf("runLint no --dir: unexpected exit %d", code)
	}
}

func TestRunReport_NoDir(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runReport([]string{}, &out, &errBuf)
	if code > 3 {
		t.Errorf("runReport no --dir: unexpected exit %d", code)
	}
}

func TestRunReq_NoDir(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runReq([]string{}, &out, &errBuf)
	if code > 3 {
		t.Errorf("runReq no --dir: unexpected exit %d", code)
	}
}

func TestRunSafetyCase_NoDir(t *testing.T) {
	outDir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runSafetyCase([]string{"--output-dir", outDir}, &out, &errBuf)
	if code > 3 {
		t.Errorf("runSafetyCase no --dir: unexpected exit %d", code)
	}
}

func TestRunSas_NoDir(t *testing.T) {
	outFile := filepath.Join(t.TempDir(), "sas.md")
	var out, errBuf bytes.Buffer
	code := runSas([]string{"--output", outFile}, &out, &errBuf)
	if code > 3 {
		t.Errorf("runSas no --dir: unexpected exit %d", code)
	}
}

func TestRunSci_NoDir(t *testing.T) {
	outFile := filepath.Join(t.TempDir(), "sci.json")
	var out, errBuf bytes.Buffer
	code := runSci([]string{"--output", outFile}, &out, &errBuf)
	if code > 3 {
		t.Errorf("runSci no --dir: unexpected exit %d", code)
	}
}

func TestRunTara_NoDir(t *testing.T) {
	outDir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runTara([]string{"--output-dir", outDir}, &out, &errBuf)
	if code > 3 {
		t.Errorf("runTara no --dir: unexpected exit %d", code)
	}
}

func TestRunTrace_NoDir(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runTrace([]string{}, &out, &errBuf)
	if code > 3 {
		t.Errorf("runTrace no --dir: unexpected exit %d", code)
	}
}

func TestRunAuditPack_NoDir(t *testing.T) {
	outFile := filepath.Join(t.TempDir(), "audit-pack.zip")
	var out, errBuf bytes.Buffer
	code := runAuditPack([]string{"--output", outFile}, &out, &errBuf)
	if code > 3 {
		t.Errorf("runAuditPack no --dir: unexpected exit %d", code)
	}
}

// ─── prList with records ──────────────────────────────────────────────────────

func TestPrList_WithRecords(t *testing.T) {
	dir := t.TempDir()
	var initOut, initErr bytes.Buffer
	if code := run([]string{"pr", "--dir", dir, "init"}, &initOut, &initErr); code != 0 {
		t.Fatalf("pr init: exit %d: %s", code, initErr.String())
	}
	var addOut, addErr bytes.Buffer
	if code := run([]string{"pr", "--dir", dir, "add", "--id", "PR-001", "--title", "Test problem"}, &addOut, &addErr); code != 0 {
		t.Fatalf("pr add: exit %d: %s", code, addErr.String())
	}
	// ProblemsFile is ".fusa-problems.json" per pr.ProblemsFile constant
	logPath := filepath.Join(dir, ".fusa-problems.json")
	var out, errBuf bytes.Buffer
	code := prList(logPath, &out, &errBuf)
	if code != 0 {
		t.Fatalf("prList: exit %d, stderr: %s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "PR-001") {
		t.Errorf("expected PR-001 in output, got: %s", out.String())
	}
}
