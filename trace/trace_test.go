package trace_test

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
	"github.com/SoundMatt/go-FuSa/testutil"
	"github.com/SoundMatt/go-FuSa/trace"
)

// ─── helpers ──────────────────────────────────────────────────────────────────

func writeReqs(t *testing.T, dir string, reqs []trace.Requirement) {
	t.Helper()
	if err := trace.SaveRequirements(dir, reqs); err != nil {
		t.Fatalf("SaveRequirements: %v", err)
	}
}

func runTrace(t *testing.T, files map[string]string) []fusa.Finding {
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

// ─── LoadRequirements / SaveRequirements ──────────────────────────────────────

func TestLoadRequirements_NotFound(t *testing.T) {
	dir := t.TempDir()
	_, err := trace.LoadRequirements(dir)
	if err == nil {
		t.Fatal("LoadRequirements: expected error for missing file")
	}
	if !isNoConfig(err) {
		t.Fatalf("LoadRequirements: expected ErrNoConfig, got %v", err)
	}
}

func TestLoadRequirements_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, trace.ReqsFile)
	if err := os.WriteFile(path, []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := trace.LoadRequirements(dir)
	if err == nil {
		t.Fatal("LoadRequirements: expected error for invalid JSON")
	}
}

func TestSaveAndLoadRequirements_Roundtrip(t *testing.T) {
	dir := t.TempDir()
	reqs := []trace.Requirement{
		{ID: "REQ-001", Title: "Error handling", Standard: "ISO26262", Level: "ASIL-D"},
		{ID: "REQ-002", Title: "No panics", Text: "Panics are prohibited."},
	}
	if err := trace.SaveRequirements(dir, reqs); err != nil {
		t.Fatalf("SaveRequirements: %v", err)
	}
	loaded, err := trace.LoadRequirements(dir)
	if err != nil {
		t.Fatalf("LoadRequirements: %v", err)
	}
	if len(loaded) != len(reqs) {
		t.Fatalf("roundtrip: got %d reqs, want %d", len(loaded), len(reqs))
	}
	for i, r := range reqs {
		if loaded[i].ID != r.ID || loaded[i].Title != r.Title {
			t.Errorf("roundtrip[%d]: got %+v, want %+v", i, loaded[i], r)
		}
	}
}

// ─── ScanTags ─────────────────────────────────────────────────────────────────

func TestScanTags_FindsImplAndTestTags(t *testing.T) {
	dir := t.TempDir()
	src := "package main\n\n//fusa:req REQ-001\nfunc Foo() {}\n"
	testSrc := "package main\n\n//fusa:test REQ-001\nfunc TestFoo(t *testing.T) {}\n"
	if err := os.WriteFile(filepath.Join(dir, "foo.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "foo_test.go"), []byte(testSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	tags, err := trace.ScanTags(dir)
	if err != nil {
		t.Fatalf("ScanTags: %v", err)
	}
	if len(tags) != 2 {
		t.Fatalf("ScanTags: got %d tags, want 2", len(tags))
	}
	var hasImpl, hasTest bool
	for _, tag := range tags {
		if tag.RequirementID != "REQ-001" {
			t.Errorf("unexpected requirement ID %q", tag.RequirementID)
		}
		if tag.Kind == trace.KindImpl {
			hasImpl = true
		}
		if tag.Kind == trace.KindTest {
			hasTest = true
		}
	}
	if !hasImpl {
		t.Error("ScanTags: expected KindImpl tag")
	}
	if !hasTest {
		t.Error("ScanTags: expected KindTest tag")
	}
}

//fusa:test REQ-TRACE005
func TestScanTags_IgnoresVendorAndHidden(t *testing.T) {
	dir := t.TempDir()
	for _, subdir := range []string{"vendor", ".hidden"} {
		if err := os.MkdirAll(filepath.Join(dir, subdir), 0o755); err != nil {
			t.Fatal(err)
		}
		src := "package x\n\n//fusa:req REQ-999\n"
		if err := os.WriteFile(filepath.Join(dir, subdir, "x.go"), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	tags, err := trace.ScanTags(dir)
	if err != nil {
		t.Fatalf("ScanTags: %v", err)
	}
	for _, tag := range tags {
		if tag.RequirementID == "REQ-999" {
			t.Error("ScanTags: should not have scanned vendor or hidden dirs")
		}
	}
}

//fusa:test REQ-TRACE007
func TestScanTags_EmptyID_Skipped(t *testing.T) {
	dir := t.TempDir()
	// Bare annotation with no ID after it should be silently skipped.
	src := "package main\n\n//fusa:req \nfunc Foo() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "foo.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	tags, err := trace.ScanTags(dir)
	if err != nil {
		t.Fatalf("ScanTags: %v", err)
	}
	if len(tags) != 0 {
		t.Errorf("ScanTags: expected 0 tags for bare annotation, got %d", len(tags))
	}
}

// ─── Build ────────────────────────────────────────────────────────────────────

func TestBuild_NoReqsFile(t *testing.T) {
	dir := t.TempDir()
	src := "package main\n\n//fusa:req REQ-001\nfunc Foo() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "foo.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := trace.Build(dir)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(m.Requirements) != 0 {
		t.Error("Build: expected empty requirements when no reqs file")
	}
	if len(m.Tags) != 1 {
		t.Errorf("Build: expected 1 tag, got %d", len(m.Tags))
	}
}

//fusa:test REQ-TRACE003
//fusa:test REQ-TRACE004
func TestBuild_CoverageMetrics(t *testing.T) {
	dir := t.TempDir()
	reqs := []trace.Requirement{
		{ID: "REQ-001", Title: "Req 1"},
		{ID: "REQ-002", Title: "Req 2"},
		{ID: "REQ-003", Title: "Req 3"},
	}
	writeReqs(t, dir, reqs)

	// REQ-001 has impl + test, REQ-002 has impl only, REQ-003 is untraced.
	src := "package main\n\n//fusa:req REQ-001\n//fusa:req REQ-002\nfunc F() {}\n"
	testSrc := "package main\n\n//fusa:test REQ-001\nfunc TestF() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "f.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "f_test.go"), []byte(testSrc), 0o644); err != nil {
		t.Fatal(err)
	}

	m, err := trace.Build(dir)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if m.Coverage.TotalRequirements != 3 {
		t.Errorf("TotalRequirements = %d, want 3", m.Coverage.TotalRequirements)
	}
	if m.Coverage.TracedRequirements != 2 {
		t.Errorf("TracedRequirements = %d, want 2", m.Coverage.TracedRequirements)
	}
	if m.Coverage.TestedRequirements != 1 {
		t.Errorf("TestedRequirements = %d, want 1", m.Coverage.TestedRequirements)
	}
}

// ─── Render ───────────────────────────────────────────────────────────────────

//fusa:test REQ-TRACE006
func TestRender_TextFormat(t *testing.T) {
	dir := t.TempDir()
	reqs := []trace.Requirement{{ID: "REQ-001", Title: "Error handling"}}
	writeReqs(t, dir, reqs)

	m, err := trace.Build(dir)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	var sb strings.Builder
	if err := trace.Render(&sb, m, "text"); err != nil {
		t.Fatalf("Render text: %v", err)
	}
	out := sb.String()
	if !strings.Contains(out, "REQ-001") {
		t.Error("text output missing requirement ID")
	}
	if !strings.Contains(out, "Error handling") {
		t.Error("text output missing requirement title")
	}
}

func TestRender_JSONFormat(t *testing.T) {
	dir := t.TempDir()
	reqs := []trace.Requirement{{ID: "REQ-001", Title: "Error handling"}}
	writeReqs(t, dir, reqs)

	m, err := trace.Build(dir)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	var sb strings.Builder
	if err := trace.Render(&sb, m, "json"); err != nil {
		t.Fatalf("Render json: %v", err)
	}
	var parsed trace.Matrix
	if err := json.Unmarshal([]byte(sb.String()), &parsed); err != nil {
		t.Fatalf("Render json: invalid JSON: %v", err)
	}
}

func TestRender_UnknownFormat(t *testing.T) {
	m := &trace.Matrix{}
	var sb strings.Builder
	if err := trace.Render(&sb, m, "xml"); err == nil {
		t.Error("Render: expected error for unknown format")
	}
}

// ─── Engine rules ─────────────────────────────────────────────────────────────

//fusa:test REQ-TRACE001
func TestTRACE001_NoReqsFile(t *testing.T) {
	findings := runTrace(t, testutil.MinimalProject())
	if !hasRule(findings, "TRACE001") {
		t.Error("TRACE001: expected INFO finding when .fusa-reqs.json absent")
	}
}

func TestTRACE001_ReqsFilePresent(t *testing.T) {
	files := testutil.MinimalProject()
	files[trace.ReqsFile] = `{"requirements":[]}`
	findings := runTrace(t, files)
	if hasRule(findings, "TRACE001") {
		t.Error("TRACE001: unexpected finding when .fusa-reqs.json is present")
	}
}

//fusa:test REQ-TRACE002
func TestTRACE002_UntracedRequirement(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	reqs := []trace.Requirement{{ID: "REQ-001", Title: "Error handling"}}
	writeReqs(t, dir, reqs)

	cfg := config.Default("github.com/example/test", "test")
	result, err := engine.Default.Run(context.Background(), dir, cfg)
	if err != nil {
		t.Fatalf("engine.Run: %v", err)
	}
	if !hasRule(result.Findings, "TRACE002") {
		t.Error("TRACE002: expected WARNING for untraced requirement")
	}
}

func TestTRACE002_TracedRequirement(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.GoSource("impl.go",
		"package main\n\n//fusa:req REQ-001\nfunc Foo() {}\n"))
	reqs := []trace.Requirement{{ID: "REQ-001", Title: "Error handling"}}
	writeReqs(t, dir, reqs)

	cfg := config.Default("github.com/example/test", "test")
	result, err := engine.Default.Run(context.Background(), dir, cfg)
	if err != nil {
		t.Fatalf("engine.Run: %v", err)
	}
	if hasRule(result.Findings, "TRACE002") {
		t.Error("TRACE002: unexpected finding for traced requirement")
	}
}

func TestTRACE002_EmptyRequirements(t *testing.T) {
	files := testutil.MinimalProject()
	files[trace.ReqsFile] = `{"requirements":[]}`
	findings := runTrace(t, files)
	if hasRule(findings, "TRACE002") {
		t.Error("TRACE002: unexpected finding for empty requirements list")
	}
}

func isNoConfig(err error) bool {
	return err != nil && strings.Contains(err.Error(), "no configuration file found")
}
