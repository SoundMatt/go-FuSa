package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// ─── qualify --dir/--format (x-FuSa spec §6) ──────────────────────────────────
//
// Regression coverage for: gofusa qualify erroring with exit 2 ("flag
// provided but not defined") when --dir or --format is passed, even though
// §6 documents both as part of qualify's CLI surface.

//fusa:test REQ-QUALIFY011
func TestRunQualify_FormatFlag(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "qualify.json")
	var out, errBuf bytes.Buffer
	code := runQualify([]string{"--format", "json", "--output", outFile}, &out, &errBuf)
	if code != 0 {
		t.Errorf("runQualify --format json: exit %d, stderr: %s", code, errBuf.String())
	}
	if _, err := os.Stat(outFile); err != nil {
		t.Error("qualification report not written")
	}
}

//fusa:test REQ-QUALIFY011
func TestRunQualify_DirFlag(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runQualify([]string{"--dir", dir}, &out, &errBuf)
	if code != 0 {
		t.Errorf("runQualify --dir: exit %d, stderr: %s", code, errBuf.String())
	}
	// --output not given, so the report should land under --dir.
	if _, err := os.Stat(filepath.Join(dir, "qualify-report.json")); err != nil {
		t.Errorf("qualification report not written under --dir: %v", err)
	}
}

//fusa:test REQ-QUALIFY011
func TestRunQualify_DirAndFormatFlags(t *testing.T) {
	dir := t.TempDir()
	var out, errBuf bytes.Buffer
	code := runQualify([]string{"--dir", dir, "--format", "json"}, &out, &errBuf)
	if code != 0 {
		t.Errorf("runQualify --dir --format json: exit %d, stderr: %s", code, errBuf.String())
	}
}

//fusa:test REQ-QUALIFY011
func TestRunQualify_InvalidFormat(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runQualify([]string{"--format", "xml"}, &out, &errBuf)
	if code != 2 {
		t.Errorf("runQualify --format xml: expected exit 2, got %d", code)
	}
}
