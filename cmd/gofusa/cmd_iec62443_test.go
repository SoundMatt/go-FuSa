package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

//fusa:test REQ-CLI-IEC62443-001
func TestRunIEC62443_TextDefault(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runIEC62443([]string{"--dir", dir}, &out, &errBuf)
	// Gaps on empty dir → exit 1; never runtime error
	if code > 1 {
		t.Errorf("exit %d; stderr: %s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "IEC 62443 Gap Report") {
		t.Errorf("missing report header; output: %s", out.String())
	}
}

//fusa:test REQ-CLI-IEC62443-001
func TestRunIEC62443_JSON(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runIEC62443([]string{"--dir", dir, "--format", "json"}, &out, &errBuf)
	if code > 1 {
		t.Errorf("exit %d; stderr: %s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), `"standard"`) {
		t.Errorf("missing JSON field; output: %s", out.String())
	}
}

//fusa:test REQ-CLI-IEC62443-001
func TestRunIEC62443_AllSLs(t *testing.T) {
	dir := t.TempDir()
	for _, sl := range []string{"SL-1", "SL-2", "SL-3", "SL-4"} {
		var out, errBuf bytes.Buffer
		code := runIEC62443([]string{"--dir", dir, "--sl", sl}, &out, &errBuf)
		if code > 1 {
			t.Errorf("sl %s: exit %d; stderr: %s", sl, code, errBuf.String())
		}
	}
}

//fusa:test REQ-CLI-IEC62443-001
func TestRunIEC62443_BadSL(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runIEC62443([]string{"--dir", dir, "--sl", "SL-5"}, &out, &errBuf)
	if code != 2 {
		t.Errorf("exit %d, want 2 for bad SL", code)
	}
}

//fusa:test REQ-CLI-IEC62443-001
func TestRunIEC62443_BadFormat(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runIEC62443([]string{"--dir", dir, "--format", "xml"}, &out, &errBuf)
	if code != 3 {
		t.Errorf("exit %d, want 3 for unsupported format", code)
	}
}

//fusa:test REQ-CLI-IEC62443-001
func TestRunIEC62443_OutputFile(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "iec62443.json")
	var out, errBuf bytes.Buffer
	code := runIEC62443([]string{"--dir", dir, "--format", "json", "--output", outFile}, &out, &errBuf)
	if code > 1 {
		t.Errorf("exit %d; stderr: %s", code, errBuf.String())
	}
	if _, err := os.Stat(outFile); err != nil {
		t.Errorf("output file not created: %v", err)
	}
	if !strings.Contains(errBuf.String(), "IEC 62443 gap report written to") {
		t.Errorf("missing confirmation message; stderr: %s", errBuf.String())
	}
}

//fusa:test REQ-CLI-IEC62443-001
func TestRunIEC62443_BadOutputPath(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runIEC62443([]string{"--dir", dir, "--output", "/nonexistent/dir/iec62443.json"}, &out, &errBuf)
	if code != 3 {
		t.Errorf("exit %d, want 3 for bad output path", code)
	}
}

//fusa:test REQ-CLI-IEC62443-001
func TestRunIEC62443_NoDir(t *testing.T) {
	outDir := t.TempDir()
	outFile := filepath.Join(outDir, "iec62443.json")
	var out, errBuf bytes.Buffer
	code := runIEC62443([]string{"--format", "json", "--output", outFile}, &out, &errBuf)
	if code > 3 {
		t.Errorf("exit %d; stderr: %s", code, errBuf.String())
	}
}

//fusa:test REQ-CLI-IEC62443-001
func TestRunIEC62443_ZeroGaps_SL1(t *testing.T) {
	dir := t.TempDir()
	evidence := map[string]string{
		".fusa-iec62443.json": `{"target_sl":1}`,
		"check-report.json":   `{}`,
		"sbom.json":           `{}`,
		"provenance.json":     `{"builder":"ci"}`,
		"SECURITY.md":         `# Security`,
	}
	for name, content := range evidence {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var out, errBuf bytes.Buffer
	code := runIEC62443([]string{"--dir", dir, "--sl", "SL-1"}, &out, &errBuf)
	if code != 0 {
		t.Errorf("exit %d, want 0 when all SL-1 evidence present; out=%s", code, out.String())
	}
}

//fusa:test REQ-CLI-IEC62443-001
func TestRunIEC62443_BadFlag(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runIEC62443([]string{"--unknown-flag"}, &out, &errBuf)
	if code != 2 {
		t.Errorf("exit %d, want 2 for unknown flag", code)
	}
}
