package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ─── gofusa hara ──────────────────────────────────────────────────────────────

func TestRunHara_Help(t *testing.T) {
	var stdout, stderr bytes.Buffer
	// --help exits non-zero with flag.ContinueOnError; only check output.
	_ = run([]string{"hara", "--help"}, &stdout, &stderr)
	combined := stdout.String() + stderr.String()
	if !strings.Contains(combined, "gofusa hara") {
		t.Errorf("hara --help: output missing 'gofusa hara', got: %s", combined)
	}
}

func TestRunHara_Init(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := run([]string{"hara", "--dir", dir, "init"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("hara init: exit %d, stderr: %s", code, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(dir, ".fusa-hara.json")); err != nil {
		t.Errorf(".fusa-hara.json not created: %v", err)
	}
	if !strings.Contains(stdout.String(), ".fusa-hara.json") {
		t.Errorf("expected .fusa-hara.json in output, got: %s", stdout.String())
	}
}

func TestRunHara_InitAlreadyExists(t *testing.T) {
	dir := t.TempDir()
	// Create file first
	if err := os.WriteFile(filepath.Join(dir, ".fusa-hara.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"hara", "--dir", dir, "init"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("hara init existing file: expected exit 1, got %d", code)
	}
	if !strings.Contains(stderr.String(), "already exists") {
		t.Errorf("expected 'already exists' in stderr, got: %s", stderr.String())
	}
}

func TestRunHara_InitWithProject(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := run([]string{"hara", "--dir", dir, "init", "-project", "myapp", "-standard", "IEC 61508"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("hara init -project: exit %d, stderr: %s", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "myapp") {
		t.Errorf("expected project name in output, got: %s", out)
	}
}

func TestRunHara_ShowMissing(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	// No .fusa-hara.json — Load returns empty HARA, show succeeds
	code := run([]string{"hara", "--dir", dir, "show"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("hara show (missing file): exit %d, stderr: %s", code, stderr.String())
	}
}

func TestRunHara_ShowJSON(t *testing.T) {
	dir := t.TempDir()
	// Init first
	var initOut, initErr bytes.Buffer
	if code := run([]string{"hara", "--dir", dir, "init"}, &initOut, &initErr); code != 0 {
		t.Fatalf("hara init: %s", initErr.String())
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"hara", "--dir", dir, "show", "-format", "json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("hara show --format json: exit %d, stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"project"`) {
		t.Errorf("expected JSON output with 'project' key, got: %s", stdout.String())
	}
}

func TestRunHara_ShowOutput(t *testing.T) {
	dir := t.TempDir()
	var initOut, initErr bytes.Buffer
	if code := run([]string{"hara", "--dir", dir, "init"}, &initOut, &initErr); code != 0 {
		t.Fatalf("hara init: %s", initErr.String())
	}
	outFile := filepath.Join(dir, "hara-report.md")
	var stdout, stderr bytes.Buffer
	code := run([]string{"hara", "--dir", dir, "show", "-format", "markdown", "-output", outFile}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("hara show -output: exit %d, stderr: %s", code, stderr.String())
	}
	if _, err := os.Stat(outFile); err != nil {
		t.Errorf("output file not created: %v", err)
	}
}

func TestRunHara_ShowNoSubcommand(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	// No subcommand → defaults to show
	code := run([]string{"hara", "--dir", dir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("hara (no subcommand): exit %d, stderr: %s", code, stderr.String())
	}
}

func TestRunHara_UnknownSubcommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"hara", "nope"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("hara nope: expected exit 1, got %d", code)
	}
}

func TestRunHara_ASIL(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"hara", "asil", "-s", "S2", "-e", "E4", "-c", "C2"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("hara asil: exit %d, stderr: %s", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "ASIL-C") {
		t.Errorf("expected ASIL-C for S2/E4/C2, got: %s", out)
	}
}

func TestRunHara_ASIL_QM(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"hara", "asil", "-s", "S1", "-e", "E1", "-c", "C0"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("hara asil QM: exit %d, stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "QM") {
		t.Errorf("expected QM for S1/E1/C0, got: %s", stdout.String())
	}
}

func TestRunHara_ASIL_MissingFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"hara", "asil", "-s", "S2"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("hara asil missing flags: expected exit 1, got %d", code)
	}
}

func TestRunHara_ASIL_Help(t *testing.T) {
	var stdout, stderr bytes.Buffer
	// --help exits non-zero with flag.ContinueOnError; only check output.
	_ = run([]string{"hara", "asil", "--help"}, &stdout, &stderr)
	combined := stdout.String() + stderr.String()
	if !strings.Contains(combined, "S0") {
		t.Errorf("hara asil --help: output missing severity description, got: %s", combined)
	}
}
