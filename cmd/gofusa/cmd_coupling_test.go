package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunCoupling_WritesReport(t *testing.T) {
	dir := t.TempDir()
	// write go.mod
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/test\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// write a .go file with an exported var
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n\nvar Exported = 42\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	code := runCoupling([]string{"--dir", dir}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("runCoupling exit %d: %s", code, errBuf.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "coupling-report.json")); err != nil {
		t.Error("coupling-report.json not written")
	}
	if !strings.Contains(out.String(), "coupling-report.json") {
		t.Error("stdout should mention coupling-report.json")
	}
}

func TestRunCoupling_CustomOutput(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/test\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	outFile := filepath.Join(dir, "my-coupling.json")
	var out, errBuf bytes.Buffer
	code := runCoupling([]string{"--dir", dir, "--output", outFile}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("runCoupling exit %d: %s", code, errBuf.String())
	}
	if _, err := os.Stat(outFile); err != nil {
		t.Error("custom output file not written")
	}
}
