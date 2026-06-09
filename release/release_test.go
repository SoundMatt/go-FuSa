package release_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/config"
	"github.com/SoundMatt/go-FuSa/engine"
	"github.com/SoundMatt/go-FuSa/release"
	"github.com/SoundMatt/go-FuSa/testutil"
)

// ─── helpers ──────────────────────────────────────────────────────────────────

func moduleDir(t *testing.T, gomod, gosum string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0o640); err != nil {
		t.Fatal(err)
	}
	if gosum != "" {
		if err := os.WriteFile(filepath.Join(dir, "go.sum"), []byte(gosum), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func hasRule(findings []fusa.Finding, ruleID string) bool {
	for _, f := range findings {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}

// ─── BuildSBOM ────────────────────────────────────────────────────────────────

func TestBuildSBOM_NoDeps(t *testing.T) {
	dir := moduleDir(t, "module github.com/example/proj\n\ngo 1.22\n", "")
	sbom, err := release.BuildSBOM(dir)
	if err != nil {
		t.Fatalf("BuildSBOM: %v", err)
	}
	if sbom.Module != "github.com/example/proj" {
		t.Errorf("Module = %q, want github.com/example/proj", sbom.Module)
	}
	if sbom.GoVersion != "1.22" {
		t.Errorf("GoVersion = %q, want 1.22", sbom.GoVersion)
	}
	if len(sbom.Components) != 0 {
		t.Errorf("Components len = %d, want 0", len(sbom.Components))
	}
	if sbom.Format == "" {
		t.Error("Format should be set")
	}
}

//fusa:test REQ-RELEASE003
//fusa:test REQ-RELEASE004
func TestBuildSBOM_WithDeps(t *testing.T) {
	gomod := "module example.com/proj\n\ngo 1.22\n\nrequire (\n\texample.com/dep v1.2.3\n)\n"
	gosum := "example.com/dep v1.2.3 h1:abc123==\nexample.com/dep v1.2.3/go.mod h1:def456==\n"
	dir := moduleDir(t, gomod, gosum)
	sbom, err := release.BuildSBOM(dir)
	if err != nil {
		t.Fatalf("BuildSBOM: %v", err)
	}
	if len(sbom.Components) != 1 {
		t.Fatalf("Components len = %d, want 1", len(sbom.Components))
	}
	c := sbom.Components[0]
	if c.Name != "example.com/dep" {
		t.Errorf("Component.Name = %q, want example.com/dep", c.Name)
	}
	if c.Version != "v1.2.3" {
		t.Errorf("Component.Version = %q, want v1.2.3", c.Version)
	}
	if c.Hash != "h1:abc123==" {
		t.Errorf("Component.Hash = %q, want h1:abc123==", c.Hash)
	}
}

func TestBuildSBOM_MissingGoMod(t *testing.T) {
	_, err := release.BuildSBOM(t.TempDir())
	if err == nil {
		t.Error("BuildSBOM: expected error for missing go.mod")
	}
}

// ─── BuildProvenance ──────────────────────────────────────────────────────────

//fusa:test REQ-RELEASE005
func TestBuildProvenance(t *testing.T) {
	dir := moduleDir(t, "module github.com/example/proj\n\ngo 1.22\n", "")
	prov, err := release.BuildProvenance(context.Background(), dir)
	if err != nil {
		t.Fatalf("BuildProvenance: %v", err)
	}
	if prov.Module != "github.com/example/proj" {
		t.Errorf("Module = %q, want github.com/example/proj", prov.Module)
	}
	if prov.GoVersion == "" {
		t.Error("GoVersion should be set")
	}
	if prov.GOOS == "" {
		t.Error("GOOS should be set")
	}
	if prov.GOARCH == "" {
		t.Error("GOARCH should be set")
	}
	if prov.Format == "" {
		t.Error("Format should be set")
	}
}

// ─── HashFiles ────────────────────────────────────────────────────────────────

func TestHashFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "artifact.bin")
	if err := os.WriteFile(path, []byte("hello"), 0o640); err != nil {
		t.Fatal(err)
	}
	artifacts, err := release.HashFiles([]string{path})
	if err != nil {
		t.Fatalf("HashFiles: %v", err)
	}
	if len(artifacts) != 1 {
		t.Fatalf("HashFiles: got %d artifacts, want 1", len(artifacts))
	}
	if artifacts[0].Hash == "" {
		t.Error("HashFiles: hash should be set")
	}
	if len(artifacts[0].Hash) != 64 {
		t.Errorf("HashFiles: hash length = %d, want 64 (SHA-256 hex)", len(artifacts[0].Hash))
	}
}

func TestHashFiles_Missing(t *testing.T) {
	_, err := release.HashFiles([]string{filepath.Join(t.TempDir(), "missing")})
	if err == nil {
		t.Error("HashFiles: expected error for missing file")
	}
}

// ─── SaveJSON ─────────────────────────────────────────────────────────────────

//fusa:test REQ-RELEASE006
//fusa:test REQ-RELEASE007
func TestSaveJSON_SPDX31(t *testing.T) {
	dir := t.TempDir()
	dir2 := moduleDir(t, "module github.com/example/proj\n\ngo 1.22\n", "")
	sbom, err := release.BuildSBOM(dir2)
	if err != nil {
		t.Fatalf("BuildSBOM: %v", err)
	}
	path := filepath.Join(dir, "sbom.json")
	spdxDoc := release.ToSPDX31(sbom)
	if err = release.SaveJSON(path, spdxDoc); err != nil {
		t.Fatalf("SaveJSON: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !strings.Contains(string(data), "SPDX-3.0.1") {
		t.Error("SaveJSON: expected SPDX-3.0.1 context in SBOM output")
	}
	if !strings.Contains(string(data), "SpdxDocument") {
		t.Error("SaveJSON: expected SpdxDocument element in output")
	}
	var parsed release.SPDX31Document
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("SaveJSON: invalid JSON: %v", err)
	}
	if parsed.Context == "" {
		t.Error("SPDX31Document: @context should be set")
	}
	if len(parsed.Graph) == 0 {
		t.Error("SPDX31Document: @graph should not be empty")
	}
}

func TestToSPDX31_WithComponents(t *testing.T) {
	gomod := "module example.com/proj\n\ngo 1.22\n\nrequire (\n\texample.com/dep v1.2.3\n)\n"
	gosum := "example.com/dep v1.2.3 h1:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=\nexample.com/dep v1.2.3/go.mod h1:def==\n"
	dir := moduleDir(t, gomod, gosum)
	sbom, err := release.BuildSBOM(dir)
	if err != nil {
		t.Fatalf("BuildSBOM: %v", err)
	}
	doc := release.ToSPDX31(sbom)
	var hasPkg bool
	for _, el := range doc.Graph {
		if el.Type == "software_Package" && el.Name == "example.com/dep" {
			hasPkg = true
			if len(el.VerifiedUsing) == 0 {
				t.Error("ToSPDX31: expected VerifiedUsing hash for component with h1: hash")
			}
		}
	}
	if !hasPkg {
		t.Error("ToSPDX31: expected software_Package element for dependency")
	}
}

func TestToSPDX31_ModuleName(t *testing.T) {
	dir := moduleDir(t, "module github.com/example/proj\n\ngo 1.22\n", "")
	sbom, err := release.BuildSBOM(dir)
	if err != nil {
		t.Fatalf("BuildSBOM: %v", err)
	}
	doc := release.ToSPDX31(sbom)
	var hasDoc bool
	for _, el := range doc.Graph {
		if el.Type == "SpdxDocument" && strings.Contains(el.Name, "github.com/example/proj") {
			hasDoc = true
		}
	}
	if !hasDoc {
		t.Error("ToSPDX31: SpdxDocument element not found with correct module name")
	}
}

// ─── BuildManifest ────────────────────────────────────────────────────────────

//fusa:test REQ-RELEASE008
func TestBuildManifest(t *testing.T) {
	dir := t.TempDir()
	p1 := filepath.Join(dir, "a.json")
	p2 := filepath.Join(dir, "b.json")
	if err := os.WriteFile(p1, []byte(`{"a":1}`), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p2, []byte(`{"b":2}`), 0o640); err != nil {
		t.Fatal(err)
	}
	m, err := release.BuildManifest([]string{p1, p2})
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	if len(m.Artifacts) != 2 {
		t.Errorf("Artifacts len = %d, want 2", len(m.Artifacts))
	}
	for _, a := range m.Artifacts {
		if len(a.Hash) != 64 {
			t.Errorf("artifact %s: hash length = %d, want 64", a.Path, len(a.Hash))
		}
	}
	if m.Format == "" {
		t.Error("Manifest.Format should be set")
	}
}

func TestBuildManifest_MissingFile(t *testing.T) {
	_, err := release.BuildManifest([]string{filepath.Join(t.TempDir(), "missing.json")})
	if err == nil {
		t.Error("BuildManifest: expected error for missing file")
	}
}

// ─── Fuzz ─────────────────────────────────────────────────────────────────────

func FuzzBuildSBOM(f *testing.F) {
	f.Add("module example.com/proj\n\ngo 1.22\n")
	f.Add("module x\ngo 1.22\nrequire example.com/dep v1.0.0\n")
	f.Add("")
	f.Add("not a go.mod file at all")
	f.Fuzz(func(t *testing.T, gomod string) {
		dir := t.TempDir()
		_ = os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0o640)
		_, _ = release.BuildSBOM(dir) // must not panic
	})
}

// ─── Engine rules ─────────────────────────────────────────────────────────────

func runRelease(t *testing.T, files map[string]string) []fusa.Finding {
	t.Helper()
	dir := testutil.ProjectDir(t, files)
	cfg := config.Default("github.com/example/test", "test")
	result, err := engine.Default.Run(context.Background(), dir, cfg)
	if err != nil {
		t.Fatalf("engine.Run: %v", err)
	}
	return result.Findings
}

//fusa:test REQ-RELEASE001
func TestRELEASE001_NoSBOM(t *testing.T) {
	findings := runRelease(t, testutil.MinimalProject())
	if !hasRule(findings, "RELEASE001") {
		t.Error("RELEASE001: expected WARNING when sbom.json absent")
	}
}

func TestRELEASE001_SBOMPresent(t *testing.T) {
	files := testutil.MinimalProject()
	files[release.SBOMFile] = `{"@context":"https://spdx.org/rdf/3.0.1/spdx-context.jsonld","@graph":[]}`
	findings := runRelease(t, files)
	if hasRule(findings, "RELEASE001") {
		t.Error("RELEASE001: unexpected finding when sbom.json is present")
	}
}

//fusa:test REQ-RELEASE002
func TestRELEASE002_NoProvenance(t *testing.T) {
	findings := runRelease(t, testutil.MinimalProject())
	if !hasRule(findings, "RELEASE002") {
		t.Error("RELEASE002: expected WARNING when provenance.json absent")
	}
}

func TestRELEASE002_ProvenancePresent(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	prov := &release.Provenance{Format: "go-FuSa Provenance v1"}
	if err := release.SaveJSON(filepath.Join(dir, release.ProvenanceFile), prov); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default("github.com/example/test", "test")
	result, err := engine.Default.Run(context.Background(), dir, cfg)
	if err != nil {
		t.Fatalf("engine.Run: %v", err)
	}
	if hasRule(result.Findings, "RELEASE002") {
		t.Error("RELEASE002: unexpected finding when provenance.json is present")
	}
}

func TestReleaseRules_Description(t *testing.T) {
	for _, r := range engine.Default.Rules() {
		switch r.ID() {
		case "RELEASE001", "RELEASE002":
			if r.Description() == "" {
				t.Errorf("%s Description() is empty", r.ID())
			}
		}
	}
}

// ─── SPDX 2.x ─────────────────────────────────────────────────────────────────

func buildSBOMForSPDX(t *testing.T) *release.SBOM {
	t.Helper()
	const gomod = "module github.com/example/proj\n\ngo 1.22\n\nrequire (\n\tgithub.com/example/dep v1.2.3\n)\n"
	const gosum = "github.com/example/dep v1.2.3 h1:abc123==\n" +
		"github.com/example/dep v1.2.3/go.mod h1:def456==\n"
	dir := moduleDir(t, gomod, gosum)
	sbom, err := release.BuildSBOM(dir)
	if err != nil {
		t.Fatalf("BuildSBOM: %v", err)
	}
	return sbom
}

func TestToSPDX22_VersionString(t *testing.T) {
	sbom := buildSBOMForSPDX(t)
	doc := release.ToSPDX22(sbom)
	if doc.SpdxVersion != "SPDX-2.2" {
		t.Errorf("SpdxVersion = %q, want %q", doc.SpdxVersion, "SPDX-2.2")
	}
}

func TestToSPDX23_VersionString(t *testing.T) {
	sbom := buildSBOMForSPDX(t)
	doc := release.ToSPDX23(sbom)
	if doc.SpdxVersion != "SPDX-2.3" {
		t.Errorf("SpdxVersion = %q, want %q", doc.SpdxVersion, "SPDX-2.3")
	}
}

func TestToSPDX22_RequiredFields(t *testing.T) {
	sbom := buildSBOMForSPDX(t)
	doc := release.ToSPDX22(sbom)
	if doc.SPDXID != "SPDXRef-DOCUMENT" {
		t.Errorf("SPDXID = %q, want %q", doc.SPDXID, "SPDXRef-DOCUMENT")
	}
	if doc.DataLicense != "CC0-1.0" {
		t.Errorf("DataLicense = %q, want %q", doc.DataLicense, "CC0-1.0")
	}
	if doc.Name != "github.com/example/proj" {
		t.Errorf("Name = %q, want %q", doc.Name, "github.com/example/proj")
	}
	if doc.DocumentNamespace == "" {
		t.Error("DocumentNamespace is empty")
	}
	if doc.CreationInfo.Created == "" {
		t.Error("CreationInfo.Created is empty")
	}
	if len(doc.CreationInfo.Creators) == 0 {
		t.Error("CreationInfo.Creators is empty")
	}
}

func TestToSPDX22_Packages(t *testing.T) {
	sbom := buildSBOMForSPDX(t)
	doc := release.ToSPDX22(sbom)
	if len(doc.Packages) != 1 {
		t.Fatalf("len(Packages) = %d, want 1", len(doc.Packages))
	}
	pkg := doc.Packages[0]
	if pkg.Name != "github.com/example/dep" {
		t.Errorf("pkg.Name = %q, want %q", pkg.Name, "github.com/example/dep")
	}
	if pkg.VersionInfo != "v1.2.3" {
		t.Errorf("pkg.VersionInfo = %q, want %q", pkg.VersionInfo, "v1.2.3")
	}
	if pkg.FilesAnalyzed {
		t.Error("pkg.FilesAnalyzed should be false")
	}
}

func TestToSPDX22_Relationships(t *testing.T) {
	sbom := buildSBOMForSPDX(t)
	doc := release.ToSPDX22(sbom)
	if len(doc.Relationships) != 1 {
		t.Fatalf("len(Relationships) = %d, want 1", len(doc.Relationships))
	}
	rel := doc.Relationships[0]
	if rel.SpdxElementID != "SPDXRef-DOCUMENT" {
		t.Errorf("rel.SpdxElementID = %q, want %q", rel.SpdxElementID, "SPDXRef-DOCUMENT")
	}
	if rel.RelationshipType != "DESCRIBES" {
		t.Errorf("rel.RelationshipType = %q, want %q", rel.RelationshipType, "DESCRIBES")
	}
}

func TestToSPDX22_SerializesAsJSON(t *testing.T) {
	sbom := buildSBOMForSPDX(t)
	doc := release.ToSPDX22(sbom)
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("json.MarshalIndent: %v", err)
	}
	if !strings.Contains(string(data), `"SPDX-2.2"`) {
		t.Error("JSON output does not contain SPDX-2.2 version string")
	}
}

func TestToSPDX22_VsToSPDX23_SameStructureDifferentVersion(t *testing.T) {
	sbom := buildSBOMForSPDX(t)
	doc22 := release.ToSPDX22(sbom)
	doc23 := release.ToSPDX23(sbom)
	if doc22.SPDXID != doc23.SPDXID {
		t.Errorf("SPDXID differs: %q vs %q", doc22.SPDXID, doc23.SPDXID)
	}
	if len(doc22.Packages) != len(doc23.Packages) {
		t.Errorf("package count differs: %d vs %d", len(doc22.Packages), len(doc23.Packages))
	}
	if doc22.SpdxVersion == doc23.SpdxVersion {
		t.Error("22 and 23 have the same SpdxVersion, expected different")
	}
}
