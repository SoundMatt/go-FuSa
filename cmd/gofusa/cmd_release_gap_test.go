package main

// Gap tests for runRelease() and runReleaseFullBundle() in cmd_release.go (v0.33.1).
// Covers branches not exercised by the existing cmd_v020/v024c/v024e/v024f/v024g tests.

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SoundMatt/go-FuSa/testutil"
)

// ─── --spdx-version 3.0.1 (not covered by any existing test) ─────────────────

//fusa:test REQ-RELEASE007
func TestRunRelease_SPDX301_Gap(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	outDir := t.TempDir()
	var out, errOut bytes.Buffer
	code := run([]string{"release", "--dir", dir, "--output-dir", outDir, "--spdx-version", "3.0.1"}, &out, &errOut)
	if code != 0 {
		t.Errorf("release --spdx-version 3.0.1: exit %d\nstderr: %s", code, errOut.String())
	}
	if _, err := os.Stat(filepath.Join(outDir, "sbom-spdx-3.0.1.json")); err != nil {
		t.Errorf("sbom-spdx-3.0.1.json not created: %v", err)
	}
	if !strings.Contains(out.String(), "SPDX SBOM written") {
		t.Error("expected 'SPDX SBOM written' in output for --spdx-version 3.0.1")
	}
}

// ─── --builder flag (not covered by any existing test) ───────────────────────

//fusa:test REQ-RELEASE010
func TestRunRelease_WithBuilderFlag(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	outDir := t.TempDir()
	var out, errOut bytes.Buffer
	code := run([]string{"release", "--dir", dir, "--output-dir", outDir, "--builder", "jenkins:my-pipeline"}, &out, &errOut)
	if code != 0 {
		t.Errorf("release --builder: exit %d\nstderr: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "jenkins:my-pipeline") {
		t.Error("expected builder name in provenance output line")
	}
}

// ─── missing go.mod error path ────────────────────────────────────────────────

//fusa:test REQ-RELEASE003
func TestRunRelease_MissingGoModReturnsError(t *testing.T) {
	// A directory with no go.mod causes BuildSBOM to fail.
	dir := t.TempDir()
	var out, errOut bytes.Buffer
	code := run([]string{"release", "--dir", dir}, &out, &errOut)
	if code == 0 {
		t.Error("release with no go.mod: expected non-zero exit code")
	}
}
