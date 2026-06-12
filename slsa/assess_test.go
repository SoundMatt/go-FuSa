package slsa_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SoundMatt/go-FuSa/slsa"
)

//fusa:test REQ-SLSA-ASSESS001
func TestAssess_L1_Empty(t *testing.T) {
	dir := t.TempDir()
	rep, err := slsa.Assess(dir, "testproj", slsa.LevelL1)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if rep.Level != slsa.LevelL1 {
		t.Errorf("Level = %v, want L1", rep.Level)
	}
	// Without .git, go.mod, or provenance.json all 3 L1 objectives are gaps.
	if rep.Gap < 3 {
		t.Errorf("expected ≥3 gaps on empty dir, got %d", rep.Gap)
	}
	// N/A count must be 7 (L2 and L3 objectives not applicable for L1).
	if rep.NA != 7 {
		t.Errorf("NA = %d, want 7", rep.NA)
	}
}

//fusa:test REQ-SLSA-ASSESS002
func TestAssess_L1_AllEvidence(t *testing.T) {
	dir := t.TempDir()
	// .git dir
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	// go.mod
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module test\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// provenance.json with vcsRevision and builder
	prov := `{"vcsRevision":"abc123","builder":"github-actions"}`
	if err := os.WriteFile(filepath.Join(dir, "provenance.json"), []byte(prov), 0o644); err != nil {
		t.Fatal(err)
	}

	rep, err := slsa.Assess(dir, "testproj", slsa.LevelL1)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if rep.Pass != 3 {
		t.Errorf("Pass = %d, want 3", rep.Pass)
	}
	if rep.Gap != 0 {
		t.Errorf("Gap = %d, want 0", rep.Gap)
	}
}

//fusa:test REQ-SLSA-ASSESS003
func TestAssess_L2_MissingBuilder(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module test\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// provenance without builder
	if err := os.WriteFile(filepath.Join(dir, "provenance.json"), []byte(`{"vcsRevision":"abc"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sbom.json"), []byte(`{"packages":[{"name":"pkg"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}

	rep, err := slsa.Assess(dir, "proj", slsa.LevelL2)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	// SLSA-L2.1 (builder) should be a gap
	found := false
	for _, obj := range rep.Objectives {
		if obj.ID == "SLSA-L2.1" && obj.Status == "GAP" {
			found = true
		}
	}
	if !found {
		t.Error("expected SLSA-L2.1 to be GAP when builder field missing")
	}
}

//fusa:test REQ-SLSA-ASSESS003
func TestAssess_L2_MissingVCSRevision(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module test\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// provenance without vcsRevision
	if err := os.WriteFile(filepath.Join(dir, "provenance.json"), []byte(`{"builder":"ci"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	rep, err := slsa.Assess(dir, "proj", slsa.LevelL2)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	found := false
	for _, obj := range rep.Objectives {
		if obj.ID == "SLSA-L2.2" && obj.Status == "GAP" {
			found = true
		}
	}
	if !found {
		t.Error("expected SLSA-L2.2 to be GAP when vcsRevision field missing")
	}
}

//fusa:test REQ-SLSA-ASSESS003
func TestAssess_L3_TwoPartyReview_CODEOWNERS(t *testing.T) {
	dir := t.TempDir()
	// Create .github/CODEOWNERS
	if err := os.MkdirAll(filepath.Join(dir, ".github"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".github", "CODEOWNERS"), []byte("* @team\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	rep, err := slsa.Assess(dir, "proj", slsa.LevelL3)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	for _, obj := range rep.Objectives {
		if obj.ID == "SLSA-L3.1" {
			if obj.Status != "PASS" {
				t.Errorf("SLSA-L3.1 = %s, want PASS", obj.Status)
			}
			return
		}
	}
	t.Error("SLSA-L3.1 not found in report")
}

//fusa:test REQ-SLSA-ASSESS003
func TestAssess_L3_ArtifactIntegrity_SHA256SUMS(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte("abc123  binary\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	rep, err := slsa.Assess(dir, "proj", slsa.LevelL3)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	for _, obj := range rep.Objectives {
		if obj.ID == "SLSA-L3.3" {
			if obj.Status != "PASS" {
				t.Errorf("SLSA-L3.3 = %s, want PASS", obj.Status)
			}
			return
		}
	}
	t.Error("SLSA-L3.3 not found in report")
}

//fusa:test REQ-SLSA-ASSESS003
func TestAssess_L3_ArtifactIntegrity_DotSha256(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "binary.sha256"), []byte("abc123\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	rep, err := slsa.Assess(dir, "proj", slsa.LevelL3)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	for _, obj := range rep.Objectives {
		if obj.ID == "SLSA-L3.3" && obj.Status == "PASS" {
			return
		}
	}
	t.Error("expected SLSA-L3.3 PASS with .sha256 file present")
}

//fusa:test REQ-SLSA-ASSESS003
func TestAssess_L3_SBOMHashes_Valid(t *testing.T) {
	dir := t.TempDir()
	sbom := `{"packages":[{"name":"go","version":"1.22","checksums":["SHA256:abc"]}]}`
	if err := os.WriteFile(filepath.Join(dir, "sbom.json"), []byte(sbom), 0o644); err != nil {
		t.Fatal(err)
	}

	rep, err := slsa.Assess(dir, "proj", slsa.LevelL3)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	for _, obj := range rep.Objectives {
		if obj.ID == "SLSA-L3.2" && obj.Status == "PASS" {
			return
		}
	}
	t.Error("expected SLSA-L3.2 PASS when sbom.json has packages")
}

//fusa:test REQ-SLSA-ASSESS003
func TestAssess_L3_SBOMHashes_EmptyPackages(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "sbom.json"), []byte(`{"packages":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}

	rep, err := slsa.Assess(dir, "proj", slsa.LevelL3)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	for _, obj := range rep.Objectives {
		if obj.ID == "SLSA-L3.2" && obj.Status == "GAP" {
			return
		}
	}
	t.Error("expected SLSA-L3.2 GAP when sbom.json has empty packages")
}

//fusa:test REQ-SLSA-ASSESS004
func TestRender_Text(t *testing.T) {
	dir := t.TempDir()
	rep, err := slsa.Assess(dir, "proj", slsa.LevelL2)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	var buf bytes.Buffer
	if err := slsa.Render(&buf, rep, "text"); err != nil {
		t.Fatalf("Render text: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "SLSA Supply-Chain Gap Report") {
		t.Error("missing report header")
	}
	if !strings.Contains(out, "L2") {
		t.Error("missing level in output")
	}
}

//fusa:test REQ-SLSA-ASSESS004
func TestRender_JSON(t *testing.T) {
	dir := t.TempDir()
	rep, err := slsa.Assess(dir, "proj", slsa.LevelL1)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	var buf bytes.Buffer
	if err := slsa.Render(&buf, rep, "json"); err != nil {
		t.Fatalf("Render json: %v", err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("JSON parse: %v", err)
	}
	if doc["standard"] != "slsa" {
		t.Errorf("standard = %v, want slsa", doc["standard"])
	}
	if doc["kind"] != "gap-report" {
		t.Errorf("kind = %v, want gap-report", doc["kind"])
	}
}

//fusa:test REQ-SLSA-ASSESS004
func TestRender_InvalidFormat(t *testing.T) {
	dir := t.TempDir()
	rep, _ := slsa.Assess(dir, "proj", slsa.LevelL1)
	if err := slsa.Render(&bytes.Buffer{}, rep, "xml"); err == nil {
		t.Error("expected error for unsupported format")
	}
}

//fusa:test REQ-SLSA-ASSESS001
func TestLevel_L4_TreatedAsL3(t *testing.T) {
	dir := t.TempDir()
	rep3, _ := slsa.Assess(dir, "proj", slsa.LevelL3)
	rep4, _ := slsa.Assess(dir, "proj", slsa.LevelL4)
	// L4 and L3 should have the same number of applicable objectives.
	if rep3.NA != rep4.NA {
		t.Errorf("L4 NA=%d should equal L3 NA=%d", rep4.NA, rep3.NA)
	}
}

//fusa:test REQ-SLSA-ASSESS003
func TestAssess_ProvenanceMissing_L2(t *testing.T) {
	dir := t.TempDir()
	rep, err := slsa.Assess(dir, "proj", slsa.LevelL2)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	for _, obj := range rep.Objectives {
		if obj.ID == "SLSA-L2.1" && obj.Status == "GAP" {
			return
		}
	}
	t.Error("expected SLSA-L2.1 GAP when provenance.json missing")
}

//fusa:test REQ-SLSA-ASSESS003
func TestAssess_ProvenanceBadJSON_L2(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "provenance.json"), []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := slsa.Assess(dir, "proj", slsa.LevelL2)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	for _, obj := range rep.Objectives {
		if obj.ID == "SLSA-L2.1" && obj.Status == "GAP" {
			return
		}
	}
	t.Error("expected SLSA-L2.1 GAP when provenance.json is invalid JSON")
}
