package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

//fusa:test REQ-CLI-SLSA-001
func TestRunSLSA_TextDefault(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runSLSA([]string{"--dir", dir}, &out, &errBuf)
	// All gaps → exit 1 (ExitGateFail); never a runtime error
	if code > 1 {
		t.Errorf("exit %d; stderr: %s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "SLSA Supply-Chain Gap Report") {
		t.Errorf("missing report header; output: %s", out.String())
	}
}

//fusa:test REQ-CLI-SLSA-001
func TestRunSLSA_JSON(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runSLSA([]string{"--dir", dir, "--format", "json"}, &out, &errBuf)
	if code > 1 {
		t.Errorf("exit %d; stderr: %s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), `"kind"`) {
		t.Errorf("missing JSON field; output: %s", out.String())
	}
}

//fusa:test REQ-CLI-SLSA-001
func TestRunSLSA_AllLevels(t *testing.T) {
	dir := t.TempDir()
	for _, lvl := range []string{"L1", "L2", "L3", "L4"} {
		var out, errBuf bytes.Buffer
		code := runSLSA([]string{"--dir", dir, "--level", lvl}, &out, &errBuf)
		if code > 1 {
			t.Errorf("level %s: exit %d; stderr: %s", lvl, code, errBuf.String())
		}
	}
}

//fusa:test REQ-CLI-SLSA-001
func TestRunSLSA_BadLevel(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runSLSA([]string{"--dir", dir, "--level", "L5"}, &out, &errBuf)
	if code != 2 {
		t.Errorf("exit %d, want 2 for bad level", code)
	}
}

//fusa:test REQ-CLI-SLSA-001
func TestRunSLSA_BadFormat(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runSLSA([]string{"--dir", dir, "--format", "xml"}, &out, &errBuf)
	if code != 3 {
		t.Errorf("exit %d, want 3 for unsupported format", code)
	}
}

//fusa:test REQ-CLI-SLSA-001
func TestRunSLSA_OutputFile(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "slsa.json")
	var out, errBuf bytes.Buffer
	code := runSLSA([]string{"--dir", dir, "--format", "json", "--output", outFile}, &out, &errBuf)
	if code > 1 {
		t.Errorf("exit %d; stderr: %s", code, errBuf.String())
	}
	if _, err := os.Stat(outFile); err != nil {
		t.Errorf("output file not created: %v", err)
	}
	if !strings.Contains(out.String(), "SLSA gap report written to") {
		t.Errorf("missing confirmation message; stdout: %s", out.String())
	}
}

//fusa:test REQ-CLI-SLSA-001
func TestRunSLSA_BadOutputPath(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runSLSA([]string{"--dir", dir, "--output", "/nonexistent/dir/slsa.json"}, &out, &errBuf)
	if code != 3 {
		t.Errorf("exit %d, want 3 for bad output path", code)
	}
}

//fusa:test REQ-CLI-SLSA-001
func TestRunSLSA_NoDir(t *testing.T) {
	outDir := t.TempDir()
	outFile := filepath.Join(outDir, "slsa.json")
	var out, errBuf bytes.Buffer
	code := runSLSA([]string{"--format", "json", "--output", outFile}, &out, &errBuf)
	if code > 3 {
		t.Errorf("exit %d; stderr: %s", code, errBuf.String())
	}
}

//fusa:test REQ-CLI-SLSA-001
func TestRunSLSA_ZeroGaps(t *testing.T) {
	dir := t.TempDir()
	// Create L1 evidence so at-L1 report has 0 gaps
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module t\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	prov := `{"vcsRevision":"abc","builder":"ci"}`
	if err := os.WriteFile(filepath.Join(dir, "provenance.json"), []byte(prov), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	code := runSLSA([]string{"--dir", dir, "--level", "L1"}, &out, &errBuf)
	if code != 0 {
		t.Errorf("exit %d, want 0 when all L1 evidence present", code)
	}
}

//fusa:test REQ-CLI-SLSA-001
func TestRunSLSA_BadFlag(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runSLSA([]string{"--unknown-flag"}, &out, &errBuf)
	if code != 2 {
		t.Errorf("exit %d, want 2 for unknown flag", code)
	}
}
