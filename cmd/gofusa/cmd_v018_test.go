package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ─── do178 ────────────────────────────────────────────────────────────────────

func TestRunDo178_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runDo178([]string{"--dir", dir, "--dal", "DAL-B", "--format", "text"}, &out, &errBuf)
	// Gaps exist in an empty dir, so exit 1 is expected
	if code != 1 {
		t.Errorf("exit code = %d, want 1 (gaps present)", code)
	}
	if !strings.Contains(out.String(), "DO-178C Gap Report") {
		t.Errorf("missing report header; got: %q", out.String())
	}
}

func TestRunDo178_JSON(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	runDo178([]string{"--dir", dir, "--dal", "DAL-B", "--format", "json"}, &out, &errBuf)
	if !strings.Contains(out.String(), `"dal"`) {
		t.Errorf("missing dal field in JSON; got: %q", out.String())
	}
}

func TestRunDo178_InvalidDAL(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runDo178([]string{"--dal", "INVALID"}, &out, &errBuf)
	if code != 1 {
		t.Errorf("expected exit 1 for invalid DAL, got %d", code)
	}
}

func TestRunDo178_Output(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "report.json")
	var out, errBuf bytes.Buffer
	runDo178([]string{"--dir", dir, "--dal", "DAL-C", "--format", "json", "--output", outFile}, &out, &errBuf)
	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("output file not created: %v", err)
	}
	if !strings.Contains(string(data), `"dal"`) {
		t.Error("output file missing dal field")
	}
}

// ─── sas ──────────────────────────────────────────────────────────────────────

func TestRunSas_EmptyDir_ToStdout(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	runSas([]string{"--dir", dir, "--dal", "DAL-B", "--format", "markdown", "--output", "-"}, &out, &errBuf)
	if !strings.Contains(out.String(), "Software Accomplishment Summary") {
		t.Errorf("missing SAS header; got: %q", out.String())
	}
}

func TestRunSas_JSON(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	runSas([]string{"--dir", dir, "--dal", "DAL-B", "--format", "json", "--output", "-"}, &out, &errBuf)
	if !strings.Contains(out.String(), `"project"`) {
		t.Errorf("missing project in JSON; got: %q", out.String())
	}
}

func TestRunSas_GapsExitOne(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runSas([]string{"--dir", dir, "--output", "-"}, &out, &errBuf)
	if code != 1 {
		t.Errorf("expected exit 1 when gaps present, got %d", code)
	}
}

// ─── sci ──────────────────────────────────────────────────────────────────────

func TestRunSci_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runSci([]string{"--dir", dir, "--format", "json"}, &out, &errBuf)
	if code != 0 {
		t.Errorf("exit code = %d, want 0; stderr: %q", code, errBuf.String())
	}
	if !strings.Contains(out.String(), `"project"`) {
		t.Errorf("missing project field; got: %q", out.String())
	}
	if !strings.Contains(out.String(), "SCI:") {
		t.Errorf("missing SCI summary; got: %q", out.String())
	}
}

func TestRunSci_Markdown(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runSci([]string{"--dir", dir, "--format", "markdown"}, &out, &errBuf)
	if code != 0 {
		t.Errorf("exit code = %d; stderr: %q", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "Software Configuration Index") {
		t.Errorf("missing SCI header; got: %q", out.String())
	}
}

func TestRunSci_Output(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "out.json")
	var out, errBuf bytes.Buffer
	runSci([]string{"--dir", dir, "--format", "json", "--output", outFile}, &out, &errBuf)
	if _, err := os.Stat(outFile); err != nil {
		t.Fatalf("output file not created: %v", err)
	}
}

// ─── coverage ─────────────────────────────────────────────────────────────────

func TestRunCoverage_MissingFile(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runCoverage([]string{"/does/not/exist/coverage.out"}, &out, &errBuf)
	if code != 1 {
		t.Errorf("expected exit 1 for missing coverage file, got %d", code)
	}
}

func TestRunCoverage_ValidProfile(t *testing.T) {
	dir := t.TempDir()
	profile := `mode: atomic
example.com/pkg/main.go:10.15,12.3 1 5
example.com/pkg/main.go:14.10,16.3 2 3
`
	profilePath := filepath.Join(dir, "coverage.out")
	if err := os.WriteFile(profilePath, []byte(profile), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	code := runCoverage([]string{"--dal", "DAL-B", "--format", "text", profilePath}, &out, &errBuf)
	if code != 0 {
		t.Errorf("exit code = %d; stderr: %q", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "DO-178C Structural Coverage Report") {
		t.Errorf("missing header; got: %q", out.String())
	}
}

func TestRunCoverage_JSON(t *testing.T) {
	dir := t.TempDir()
	profile := "mode: set\nexample.com/foo.go:1.1,3.1 2 1\n"
	profilePath := filepath.Join(dir, "coverage.out")
	if err := os.WriteFile(profilePath, []byte(profile), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	code := runCoverage([]string{"--dal", "DAL-C", "--format", "json", profilePath}, &out, &errBuf)
	if code != 0 {
		t.Errorf("exit code = %d; stderr: %q", code, errBuf.String())
	}
	if !strings.Contains(out.String(), `"dal"`) {
		t.Errorf("missing dal in JSON; got: %q", out.String())
	}
}

func TestRunCoverage_InvalidDAL(t *testing.T) {
	dir := t.TempDir()
	profilePath := filepath.Join(dir, "coverage.out")
	_ = os.WriteFile(profilePath, []byte("mode: set\n"), 0o644)
	var out, errBuf bytes.Buffer
	code := runCoverage([]string{"--dal", "NOPE", profilePath}, &out, &errBuf)
	if code != 1 {
		t.Errorf("expected exit 1 for invalid DAL, got %d", code)
	}
}

// ─── pr ───────────────────────────────────────────────────────────────────────

func TestRunPR_NoArgs(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runPR([]string{}, &out, &errBuf)
	if code != 1 {
		t.Errorf("expected exit 1 for no args, got %d", code)
	}
}

func TestRunPR_UnknownSubcommand(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runPR([]string{"bogus"}, &out, &errBuf)
	if code != 1 {
		t.Errorf("expected exit 1 for unknown subcommand, got %d", code)
	}
}

func TestRunPR_Init(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runPR([]string{"--dir", dir, "init"}, &out, &errBuf)
	if code != 0 {
		t.Errorf("exit code = %d; stderr: %q", code, errBuf.String())
	}
	if _, err := os.Stat(filepath.Join(dir, ".fusa-problems.json")); err != nil {
		t.Error("expected .fusa-problems.json to be created")
	}
}

func TestRunPR_Init_AlreadyExists(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".fusa-problems.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	code := runPR([]string{"--dir", dir, "init"}, &out, &errBuf)
	if code != 1 {
		t.Errorf("expected exit 1 when file already exists, got %d", code)
	}
}

func TestRunPR_Add_And_List(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	// init first
	runPR([]string{"--dir", dir, "init"}, &out, &errBuf)
	out.Reset()
	// add a report
	code := runPR([]string{"--dir", dir, "add", "--id", "PR-001", "--title", "Test bug", "--severity", "minor"}, &out, &errBuf)
	if code != 0 {
		t.Errorf("add exit code = %d; stderr: %q", code, errBuf.String())
	}
	out.Reset()
	// list
	code = runPR([]string{"--dir", dir, "list"}, &out, &errBuf)
	if code != 0 {
		t.Errorf("list exit code = %d; stderr: %q", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "PR-001") {
		t.Errorf("list missing PR-001; got: %q", out.String())
	}
}

func TestRunPR_Add_MissingID(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, ".fusa-problems.json"), []byte(`{"project":"x"}`), 0o644)
	var out, errBuf bytes.Buffer
	code := runPR([]string{"--dir", dir, "add", "--title", "no id"}, &out, &errBuf)
	if code != 1 {
		t.Errorf("expected exit 1 for missing --id, got %d", code)
	}
}

func TestRunPR_Close(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	runPR([]string{"--dir", dir, "init"}, &out, &errBuf)
	out.Reset()
	runPR([]string{"--dir", dir, "add", "--id", "PR-002", "--title", "Fixed bug"}, &out, &errBuf)
	out.Reset()
	code := runPR([]string{"--dir", dir, "close", "--id", "PR-002", "--resolution", "resolved"}, &out, &errBuf)
	if code != 0 {
		t.Errorf("close exit code = %d; stderr: %q", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "PR-002") {
		t.Errorf("close message missing PR-002; got: %q", out.String())
	}
}

func TestRunPR_Close_MissingID(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runPR([]string{"--dir", dir, "close"}, &out, &errBuf)
	if code != 1 {
		t.Errorf("expected exit 1 for missing --id, got %d", code)
	}
}
