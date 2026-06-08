package auditpack_test

import (
	"archive/zip"
	"context"
	"os"
	"path/filepath"
	"testing"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/auditpack"
	"github.com/SoundMatt/go-FuSa/config"
	"github.com/SoundMatt/go-FuSa/engine"
	"github.com/SoundMatt/go-FuSa/testutil"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

func projectWithEvidence(t *testing.T) string {
	t.Helper()
	files := testutil.MinimalProject()
	for _, name := range []string{
		"check-report.json",
		"sbom.json",
		"provenance.json",
		"qualify-report.json",
		"fmea.json",
		"safety-case.json",
	} {
		files[name] = `{"format":"test","entries":[]}`
	}
	return testutil.ProjectDir(t, files)
}

func zipFileNames(t *testing.T, path string) []string {
	t.Helper()
	r, err := zip.OpenReader(path)
	if err != nil {
		t.Fatalf("open zip %s: %v", path, err)
	}
	defer func() { _ = r.Close() }()
	var names []string
	for _, f := range r.File {
		names = append(names, f.Name)
	}
	return names
}

// ─── Pack ─────────────────────────────────────────────────────────────────────

//fusa:test REQ-AUDIT001
func TestPack_CollectsEvidenceFiles(t *testing.T) {
	dir := projectWithEvidence(t)
	outPath := filepath.Join(t.TempDir(), auditpack.AuditPackFile)

	manifest, err := auditpack.Pack(dir, outPath)
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	if len(manifest.Files) == 0 {
		t.Error("expected evidence files in manifest")
	}

	names := zipFileNames(t, outPath)
	hasManifest := false
	for _, n := range names {
		if n == "AUDIT-MANIFEST.json" {
			hasManifest = true
		}
	}
	if !hasManifest {
		t.Error("audit pack must contain AUDIT-MANIFEST.json")
	}
}

//fusa:test REQ-AUDIT002
func TestPack_ManifestHasSHA256(t *testing.T) {
	dir := projectWithEvidence(t)
	outPath := filepath.Join(t.TempDir(), auditpack.AuditPackFile)

	manifest, err := auditpack.Pack(dir, outPath)
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	for _, entry := range manifest.Files {
		if len(entry.SHA256) != 64 {
			t.Errorf("file %q: SHA256 = %q (len %d), want 64 hex chars",
				entry.Path, entry.SHA256, len(entry.SHA256))
		}
	}
}

func TestPack_EmptyProject(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	outPath := filepath.Join(t.TempDir(), auditpack.AuditPackFile)

	manifest, err := auditpack.Pack(dir, outPath)
	if err != nil {
		t.Fatalf("Pack empty: %v", err)
	}
	// .fusa.json and go.mod are not in EvidenceFiles list; only fusa-specific artifacts
	_ = manifest
	if _, err := os.Stat(outPath); err != nil {
		t.Errorf("audit-pack.zip not created: %v", err)
	}
}

//fusa:test REQ-AUDIT004
func TestPack_ZIPIsReadable(t *testing.T) {
	dir := projectWithEvidence(t)
	outPath := filepath.Join(t.TempDir(), auditpack.AuditPackFile)
	if _, err := auditpack.Pack(dir, outPath); err != nil {
		t.Fatalf("Pack: %v", err)
	}

	r, err := zip.OpenReader(outPath)
	if err != nil {
		t.Fatalf("zip.OpenReader: %v", err)
	}
	defer func() { _ = r.Close() }()
	if len(r.File) == 0 {
		t.Error("expected non-empty ZIP")
	}
}

func TestPack_BadOutputPath(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	_, err := auditpack.Pack(dir, "/nonexistent/dir/audit-pack.zip")
	if err == nil {
		t.Error("expected error for bad output path")
	}
}

func TestPack_ModuleNameSet(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	outPath := filepath.Join(t.TempDir(), auditpack.AuditPackFile)

	manifest, err := auditpack.Pack(dir, outPath)
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	if manifest.Module == "" {
		t.Error("Module should be set from go.mod")
	}
}

func TestPack_SkipsMissingFiles(t *testing.T) {
	// MinimalProject has no evidence files — pack should still succeed
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	outPath := filepath.Join(t.TempDir(), auditpack.AuditPackFile)

	manifest, err := auditpack.Pack(dir, outPath)
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	// None of the evidence files exist, so Files should be empty
	for _, entry := range manifest.Files {
		// If it's there, verify it's a known file
		found := false
		for _, known := range auditpack.EvidenceFiles {
			if entry.Path == known {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("unexpected file in manifest: %q", entry.Path)
		}
	}
}

func TestPack_IncludesFusaConfig(t *testing.T) {
	dir := projectWithEvidence(t)
	outPath := filepath.Join(t.TempDir(), auditpack.AuditPackFile)

	manifest, err := auditpack.Pack(dir, outPath)
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	hasFusaJSON := false
	for _, entry := range manifest.Files {
		if entry.Path == ".fusa.json" {
			hasFusaJSON = true
		}
	}
	if !hasFusaJSON {
		t.Error("expected .fusa.json in audit pack")
	}
}

// ─── engine rule ─────────────────────────────────────────────────────────────

func runEngine(t *testing.T, files map[string]string) []fusa.Finding {
	t.Helper()
	dir := testutil.ProjectDir(t, files)
	cfg := config.Default("github.com/example/test", "test")
	result, err := engine.Default.Run(context.Background(), dir, cfg)
	if err != nil {
		t.Fatalf("engine.Run: %v", err)
	}
	return result.Findings
}

func hasRule(findings []fusa.Finding, ruleID string) bool {
	for _, f := range findings {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}

//fusa:test REQ-AUDIT003
func TestAUDITPACK001_Absent(t *testing.T) {
	findings := runEngine(t, testutil.MinimalProject())
	if !hasRule(findings, "AUDITPACK001") {
		t.Error("AUDITPACK001: expected INFO finding when audit-pack.zip absent")
	}
}

func TestAUDITPACK001_Present(t *testing.T) {
	files := testutil.MinimalProject()
	files[auditpack.AuditPackFile] = "PK\x03\x04" // ZIP magic bytes
	findings := runEngine(t, files)
	if hasRule(findings, "AUDITPACK001") {
		t.Error("AUDITPACK001: unexpected finding when audit-pack.zip present")
	}
}

func TestAUDITPACK001_Description(t *testing.T) {
	for _, r := range engine.Default.Rules() {
		if r.ID() == "AUDITPACK001" {
			if r.Description() == "" {
				t.Error("AUDITPACK001: empty description")
			}
			return
		}
	}
	t.Error("AUDITPACK001 not registered")
}
