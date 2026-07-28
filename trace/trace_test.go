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
	"github.com/SoundMatt/go-FuSa/report"
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
	if err := os.WriteFile(path, []byte("not json"), 0o640); err != nil {
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

//fusa:test REQ-TRACE011
func TestScanTags_FindsImplAndTestTags(t *testing.T) {
	dir := t.TempDir()
	src := "package main\n\n//fusa:req REQ-001\nfunc Foo() {}\n"
	testSrc := "package main\n\n//fusa:test REQ-001\nfunc TestFoo(t *testing.T) {}\n"
	if err := os.WriteFile(filepath.Join(dir, "foo.go"), []byte(src), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "foo_test.go"), []byte(testSrc), 0o640); err != nil {
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
		if err := os.MkdirAll(filepath.Join(dir, subdir), 0o750); err != nil {
			t.Fatal(err)
		}
		src := "package x\n\n//fusa:req REQ-999\n"
		if err := os.WriteFile(filepath.Join(dir, subdir, "x.go"), []byte(src), 0o640); err != nil {
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
	if err := os.WriteFile(filepath.Join(dir, "foo.go"), []byte(src), 0o640); err != nil {
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
	if err := os.WriteFile(filepath.Join(dir, "foo.go"), []byte(src), 0o640); err != nil {
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
//fusa:test REQ-REQQ002
//fusa:test REQ-REQQ003
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
	if err := os.WriteFile(filepath.Join(dir, "f.go"), []byte(src), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "f_test.go"), []byte(testSrc), 0o640); err != nil {
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

//fusa:test REQ-TRACE-MD001
func TestRender_MarkdownFormat(t *testing.T) {
	dir := t.TempDir()
	reqs := []trace.Requirement{{ID: "REQ-001", Title: "Error handling"}}
	writeReqs(t, dir, reqs)

	m, err := trace.Build(dir)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	var sb strings.Builder
	if err := trace.Render(&sb, m, "md"); err != nil {
		t.Fatalf("Render md: %v", err)
	}
	out := sb.String()
	if !strings.Contains(out, "# Requirements") {
		t.Errorf("expected markdown heading: %s", out)
	}
	if !strings.Contains(out, "REQ-001") {
		t.Errorf("expected requirement ID in markdown: %s", out)
	}
}

//fusa:test REQ-TRACE-MD001
func TestRender_MarkdownAlias(t *testing.T) {
	m := &trace.Matrix{}
	var sb strings.Builder
	if err := trace.Render(&sb, m, "markdown"); err != nil {
		t.Fatalf("Render markdown: %v", err)
	}
	if !strings.Contains(sb.String(), "# Requirements") {
		t.Errorf("expected markdown output")
	}
}

//fusa:test REQ-TRACE-MD001
func TestRender_Markdown_NoRequirements(t *testing.T) {
	m := &trace.Matrix{}
	var sb strings.Builder
	if err := trace.Render(&sb, m, "md"); err != nil {
		t.Fatalf("Render md: %v", err)
	}
	if !strings.Contains(sb.String(), "No requirements") {
		t.Errorf("expected 'No requirements' message: %s", sb.String())
	}
}

//fusa:test REQ-TRACE-MD001
//fusa:test REQ-TRACE008
func TestRender_Markdown_HLRLLRSummary(t *testing.T) {
	// Build a matrix with an HLRLLRSummary populated so the markdown
	// renderer exercises the HLR/LLR summary section added in v0.32.0.
	m := &trace.Matrix{
		HLRLLRSummary: &trace.HLRLLRSummary{
			HLRCount:  2,
			LLRCount:  3,
			Orphaned:  []string{"REQ-LLR-X"},
			Uncovered: []string{"REQ-HLR-Y"},
		},
	}
	var sb strings.Builder
	if err := trace.Render(&sb, m, "md"); err != nil {
		t.Fatalf("Render md with HLRLLRSummary: %v", err)
	}
	out := sb.String()
	if !strings.Contains(out, "HLRs") {
		t.Errorf("markdown should contain HLR count row; got:\n%s", out)
	}
	if !strings.Contains(out, "LLRs") {
		t.Errorf("markdown should contain LLR count row; got:\n%s", out)
	}
	if !strings.Contains(out, "Orphaned LLRs") {
		t.Errorf("markdown should contain Orphaned LLRs row; got:\n%s", out)
	}
	if !strings.Contains(out, "Uncovered HLRs") {
		t.Errorf("markdown should contain Uncovered HLRs row; got:\n%s", out)
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
//fusa:test REQ-REQQ001
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

// ─── Descriptions ─────────────────────────────────────────────────────────────

func TestTraceRuleDescriptions(t *testing.T) {
	for _, r := range engine.Default.Rules() {
		if len(r.ID()) >= 5 && r.ID()[:5] == "TRACE" {
			if r.Description() == "" {
				t.Errorf("%s: Description() returned empty string", r.ID())
			}
		}
	}
}

// ─── Fuzz ─────────────────────────────────────────────────────────────────────

func FuzzScanTags(f *testing.F) {
	f.Add("package main\n\n//fusa:req REQ-001\nfunc Foo() {}\n")
	f.Add("package main\n\n//fusa:test REQ-001\nfunc TestFoo(t *testing.T) {}\n")
	f.Add("//fusa:req \n")
	f.Add("")
	f.Add("not valid go\x00source")
	f.Fuzz(func(t *testing.T, src string) {
		dir := t.TempDir()
		_ = os.WriteFile(filepath.Join(dir, "fuzz.go"), []byte(src), 0o640)
		_, _ = trace.ScanTags(dir) // must not panic
	})
}

// ─── ScanFuncCoverage ─────────────────────────────────────────────────────────

func TestScanFuncCoverage_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	fc, err := trace.ScanFuncCoverage(dir, nil)
	if err != nil {
		t.Fatalf("ScanFuncCoverage: %v", err)
	}
	if fc.Total != 0 || fc.Covered != 0 || fc.Pct != 0 {
		t.Errorf("empty dir: got %+v, want all zeroes", fc)
	}
}

func TestScanFuncCoverage_UnannotatedFuncs(t *testing.T) {
	dir := t.TempDir()
	src := "package mypkg\n\nfunc DoWork() error { return nil }\nfunc Helper() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "work.go"), []byte(src), 0o640); err != nil {
		t.Fatal(err)
	}
	fc, err := trace.ScanFuncCoverage(dir, nil) // no tags → no annotated files
	if err != nil {
		t.Fatalf("ScanFuncCoverage: %v", err)
	}
	if fc.Total != 2 {
		t.Errorf("Total = %d, want 2", fc.Total)
	}
	if fc.Covered != 0 {
		t.Errorf("Covered = %d, want 0", fc.Covered)
	}
	if fc.Pct != 0 {
		t.Errorf("Pct = %f, want 0", fc.Pct)
	}
	if len(fc.Uncovered) != 2 {
		t.Errorf("Uncovered = %v, want 2 entries", fc.Uncovered)
	}
}

func TestScanFuncCoverage_AnnotatedFile(t *testing.T) {
	dir := t.TempDir()
	src := "package mypkg\n\n//fusa:req REQ-001\nfunc DoWork() error { return nil }\nfunc Helper() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "work.go"), []byte(src), 0o640); err != nil {
		t.Fatal(err)
	}
	tags, err := trace.ScanTags(dir)
	if err != nil {
		t.Fatalf("ScanTags: %v", err)
	}
	fc, err := trace.ScanFuncCoverage(dir, tags)
	if err != nil {
		t.Fatalf("ScanFuncCoverage: %v", err)
	}
	if fc.Total != 2 {
		t.Errorf("Total = %d, want 2", fc.Total)
	}
	if fc.Covered != 2 {
		t.Errorf("Covered = %d, want 2 (whole file is annotated)", fc.Covered)
	}
	if fc.Pct != 100 {
		t.Errorf("Pct = %f, want 100", fc.Pct)
	}
}

func TestScanFuncCoverage_SkipsTestFiles(t *testing.T) {
	dir := t.TempDir()
	src := "package mypkg\n\nfunc DoWork() {}\n"
	testSrc := "package mypkg\n\nfunc TestDoWork(t *testing.T) {}\n"
	if err := os.WriteFile(filepath.Join(dir, "work.go"), []byte(src), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "work_test.go"), []byte(testSrc), 0o640); err != nil {
		t.Fatal(err)
	}
	fc, err := trace.ScanFuncCoverage(dir, nil)
	if err != nil {
		t.Fatalf("ScanFuncCoverage: %v", err)
	}
	// TestDoWork is in a _test.go file — should not be counted.
	if fc.Total != 1 {
		t.Errorf("Total = %d, want 1 (test file excluded)", fc.Total)
	}
}

func TestScanFuncCoverage_SkipsUnexported(t *testing.T) {
	dir := t.TempDir()
	src := "package mypkg\n\nfunc unexported() {}\nfunc Exported() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "f.go"), []byte(src), 0o640); err != nil {
		t.Fatal(err)
	}
	fc, err := trace.ScanFuncCoverage(dir, nil)
	if err != nil {
		t.Fatalf("ScanFuncCoverage: %v", err)
	}
	if fc.Total != 1 {
		t.Errorf("Total = %d, want 1 (unexported excluded)", fc.Total)
	}
}

// ─── TRACE006 ─────────────────────────────────────────────────────────────────

//fusa:test REQ-TRACE006
func TestTRACE006_BelowThreshold(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	// 1 requirement, 0 impl tags → 0% coverage → fires WARNING
	reqs := []trace.Requirement{
		{ID: "REQ-A", Title: "Alpha"},
		{ID: "REQ-B", Title: "Beta"},
	}
	writeReqs(t, dir, reqs)

	cfg := config.Default("github.com/example/test", "test")
	result, err := engine.Default.Run(context.Background(), dir, cfg)
	if err != nil {
		t.Fatalf("engine.Run: %v", err)
	}
	if !hasRule(result.Findings, "TRACE006") {
		t.Error("TRACE006: expected WARNING when req coverage is 0%")
	}
	for _, f := range result.Findings {
		if f.RuleID == "TRACE006" && f.Severity != "WARNING" {
			t.Errorf("TRACE006: expected WARNING severity, got %s", f.Severity)
		}
	}
}

func TestTRACE006_AboveThreshold(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.GoSource("impl.go",
		"package main\n\n//fusa:req REQ-A\n//fusa:req REQ-B\nfunc F() {}\n"))
	reqs := []trace.Requirement{
		{ID: "REQ-A", Title: "Alpha"},
		{ID: "REQ-B", Title: "Beta"},
	}
	writeReqs(t, dir, reqs)

	cfg := config.Default("github.com/example/test", "test")
	result, err := engine.Default.Run(context.Background(), dir, cfg)
	if err != nil {
		t.Fatalf("engine.Run: %v", err)
	}
	if hasRule(result.Findings, "TRACE006") {
		t.Error("TRACE006: unexpected finding when all requirements are traced")
	}
}

func TestTRACE006_NoRequirements(t *testing.T) {
	files := testutil.MinimalProject()
	files[trace.ReqsFile] = `{"requirements":[]}`
	findings := runTrace(t, files)
	if hasRule(findings, "TRACE006") {
		t.Error("TRACE006: unexpected finding when there are no requirements")
	}
}

// ─── TRACE007 ─────────────────────────────────────────────────────────────────

//fusa:test REQ-TRACE007
func TestTRACE007_BelowThreshold(t *testing.T) {
	// File with exported func but no //fusa:req → 0% density → fires INFO
	dir := testutil.ProjectDir(t, testutil.GoSource("work.go",
		"package main\n\nfunc DoWork() error { return nil }\n"))

	cfg := config.Default("github.com/example/test", "test")
	result, err := engine.Default.Run(context.Background(), dir, cfg)
	if err != nil {
		t.Fatalf("engine.Run: %v", err)
	}
	if !hasRule(result.Findings, "TRACE007") {
		t.Error("TRACE007: expected INFO finding when no functions are annotated")
	}
	for _, f := range result.Findings {
		if f.RuleID == "TRACE007" && f.Severity != "INFO" {
			t.Errorf("TRACE007: expected INFO severity, got %s", f.Severity)
		}
	}
}

func TestTRACE007_AboveThreshold(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.GoSource("work.go",
		"package main\n\n//fusa:req REQ-001\nfunc DoWork() error { return nil }\n"))

	cfg := config.Default("github.com/example/test", "test")
	result, err := engine.Default.Run(context.Background(), dir, cfg)
	if err != nil {
		t.Fatalf("engine.Run: %v", err)
	}
	if hasRule(result.Findings, "TRACE007") {
		t.Error("TRACE007: unexpected finding when all functions are in annotated files")
	}
}

func TestTRACE007_NoFunctions(t *testing.T) {
	// MinimalProject has no .go source with exported funcs → Total=0 → silent
	findings := runTrace(t, testutil.MinimalProject())
	if hasRule(findings, "TRACE007") {
		t.Error("TRACE007: unexpected finding when there are no exported functions")
	}
}

// ─── renderText branch coverage ───────────────────────────────────────────────

// TestRenderText_TracedAndTested verifies the "[traced+tested]" status line.
func TestRenderText_TracedAndTested(t *testing.T) {
	dir := t.TempDir()
	reqs := []trace.Requirement{
		{ID: "REQ-001", Title: "Error handling"},
	}
	writeReqs(t, dir, reqs)

	// impl tag in one file, test tag in another
	implSrc := "package main\n\n//fusa:req REQ-001\nfunc Foo() {}\n"
	testSrc := "package main\n\n//fusa:test REQ-001\nfunc TestFoo() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "foo.go"), []byte(implSrc), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "foo_test.go"), []byte(testSrc), 0o640); err != nil {
		t.Fatal(err)
	}

	m, err := trace.Build(dir)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	var sb strings.Builder
	if err := trace.Render(&sb, m, "text"); err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := sb.String()
	if !strings.Contains(out, "[traced+tested]") {
		t.Errorf("renderText: expected '[traced+tested]' status, got:\n%s", out)
	}
}

// TestRenderText_TracedOnly verifies the "[traced]" status line (impl but no test).
func TestRenderText_TracedOnly(t *testing.T) {
	dir := t.TempDir()
	reqs := []trace.Requirement{
		{ID: "REQ-002", Title: "No panics"},
	}
	writeReqs(t, dir, reqs)

	// impl tag only, no test tag
	implSrc := "package main\n\n//fusa:req REQ-002\nfunc Bar() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "bar.go"), []byte(implSrc), 0o640); err != nil {
		t.Fatal(err)
	}

	m, err := trace.Build(dir)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	var sb strings.Builder
	if err := trace.Render(&sb, m, "text"); err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := sb.String()
	if !strings.Contains(out, "[traced]") {
		t.Errorf("renderText: expected '[traced]' status, got:\n%s", out)
	}
}

// TestRenderText_Untraced verifies the "[untraced]" status line (no impl, no test).
func TestRenderText_Untraced(t *testing.T) {
	dir := t.TempDir()
	reqs := []trace.Requirement{
		{ID: "REQ-003", Title: "Watchdog"},
	}
	writeReqs(t, dir, reqs)
	// No source files with annotations → untraced

	m, err := trace.Build(dir)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	var sb strings.Builder
	if err := trace.Render(&sb, m, "text"); err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := sb.String()
	if !strings.Contains(out, "[untraced]") {
		t.Errorf("renderText: expected '[untraced]' status, got:\n%s", out)
	}
}

// TestRenderText_OrphanTags verifies the orphan-tag section when a tag references
// a requirement ID that does not exist in the requirements list.
func TestRenderText_OrphanTags(t *testing.T) {
	dir := t.TempDir()
	// Requirements list is empty, but source has a tag for REQ-ORPHAN
	reqs := []trace.Requirement{}
	writeReqs(t, dir, reqs)

	src := "package main\n\n//fusa:req REQ-ORPHAN\nfunc Orphan() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "orphan.go"), []byte(src), 0o640); err != nil {
		t.Fatal(err)
	}

	m, err := trace.Build(dir)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	var sb strings.Builder
	if err := trace.Render(&sb, m, "text"); err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := sb.String()
	if !strings.Contains(out, "Orphan tags") {
		t.Errorf("renderText: expected orphan tags section, got:\n%s", out)
	}
	if !strings.Contains(out, "REQ-ORPHAN") {
		t.Errorf("renderText: expected REQ-ORPHAN in orphan section, got:\n%s", out)
	}
}

// TestRenderText_NoRequirements verifies the "No requirements defined" branch when
// the matrix has 0 requirements but some tags exist.
func TestRenderText_NoRequirements(t *testing.T) {
	dir := t.TempDir()
	// Write an empty requirements list
	reqs := []trace.Requirement{}
	writeReqs(t, dir, reqs)

	// Add a tag — it will appear as an orphan but the "No requirements defined" line
	// should also be printed.
	src := "package main\n\n//fusa:req REQ-X\nfunc X() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "x.go"), []byte(src), 0o640); err != nil {
		t.Fatal(err)
	}

	m, err := trace.Build(dir)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	var sb strings.Builder
	if err := trace.Render(&sb, m, "text"); err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := sb.String()
	if !strings.Contains(out, "No requirements defined") {
		t.Errorf("renderText: expected 'No requirements defined' line, got:\n%s", out)
	}
}

// ─── TRACE005 branch coverage ─────────────────────────────────────────────────

// TestTRACE005_SameFileFinding verifies that TRACE005 fires when the same file
// contains both //fusa:req and //fusa:test for the same requirement.
//
//fusa:test REQ-TRACE005
func TestTRACE005_SameFileFinding(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	reqs := []trace.Requirement{{ID: "REQ-IND", Title: "Independence check"}}
	writeReqs(t, dir, reqs)

	// Both impl and test annotations in the same file.
	combined := "package main\n\n//fusa:req REQ-IND\n//fusa:test REQ-IND\nfunc DoThing() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "combined.go"), []byte(combined), 0o640); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default("github.com/example/test", "test")
	result, err := engine.Default.Run(context.Background(), dir, cfg)
	if err != nil {
		t.Fatalf("engine.Run: %v", err)
	}
	if !hasRule(result.Findings, "TRACE005") {
		t.Error("TRACE005: expected finding when impl and test are in the same file")
	}
}

// TestTRACE005_DifferentFilesNoFinding verifies that TRACE005 does NOT fire when
// impl and test annotations for the same requirement are in different files.
func TestTRACE005_DifferentFilesNoFinding(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	reqs := []trace.Requirement{{ID: "REQ-IND2", Title: "Independence OK"}}
	writeReqs(t, dir, reqs)

	implSrc := "package main\n\n//fusa:req REQ-IND2\nfunc DoThing2() {}\n"
	testSrc := "package main\n\n//fusa:test REQ-IND2\nfunc TestDoThing2() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "impl.go"), []byte(implSrc), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "impl_test.go"), []byte(testSrc), 0o640); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default("github.com/example/test", "test")
	result, err := engine.Default.Run(context.Background(), dir, cfg)
	if err != nil {
		t.Fatalf("engine.Run: %v", err)
	}
	if hasRule(result.Findings, "TRACE005") {
		t.Error("TRACE005: unexpected finding when impl and test are in different files")
	}
}

// TestTRACE005_NoRequirements verifies that TRACE005 exits early (no findings)
// when the requirements list is empty.
func TestTRACE005_NoRequirements(t *testing.T) {
	files := testutil.MinimalProject()
	files[trace.ReqsFile] = `{"requirements":[]}`
	findings := runTrace(t, files)
	if hasRule(findings, "TRACE005") {
		t.Error("TRACE005: unexpected finding when there are no requirements")
	}
}

// ─── TRACE008: HLR/LLR decomposition ─────────────────────────────────────────

//fusa:test REQ-TRACE008
func TestComputeHLRLLR_NoLevels(t *testing.T) {
	// Requirements without Level set → HLRCount=0, LLRCount=0, no issues.
	reqs := []trace.Requirement{
		{ID: "REQ-001", Title: "A requirement"},
	}
	s := trace.ComputeHLRLLR(reqs)
	if s.HLRCount != 0 || s.LLRCount != 0 {
		t.Errorf("got HLR=%d LLR=%d, want 0 0", s.HLRCount, s.LLRCount)
	}
	if len(s.Orphaned) != 0 || len(s.Uncovered) != 0 {
		t.Errorf("expected no violations, got orphaned=%v uncovered=%v", s.Orphaned, s.Uncovered)
	}
}

//fusa:test REQ-TRACE008
func TestComputeHLRLLR_WellFormed(t *testing.T) {
	reqs := []trace.Requirement{
		{ID: "HLR-001", Title: "High-level", Level: "HLR"},
		{ID: "LLR-001", Title: "Low-level A", Level: "LLR", ParentID: "HLR-001"},
		{ID: "LLR-002", Title: "Low-level B", Level: "LLR", ParentID: "HLR-001"},
	}
	s := trace.ComputeHLRLLR(reqs)
	if s.HLRCount != 1 || s.LLRCount != 2 {
		t.Errorf("got HLR=%d LLR=%d, want 1 2", s.HLRCount, s.LLRCount)
	}
	if len(s.Orphaned) != 0 || len(s.Uncovered) != 0 {
		t.Errorf("well-formed hierarchy: expected no violations, got orphaned=%v uncovered=%v",
			s.Orphaned, s.Uncovered)
	}
}

//fusa:test REQ-TRACE008
func TestComputeHLRLLR_OrphanedLLR(t *testing.T) {
	// LLR with missing or invalid ParentID.
	reqs := []trace.Requirement{
		{ID: "HLR-001", Title: "High-level", Level: "HLR"},
		{ID: "LLR-001", Title: "Orphan", Level: "LLR", ParentID: ""},
		{ID: "LLR-002", Title: "Bad parent", Level: "LLR", ParentID: "NONEXISTENT"},
	}
	s := trace.ComputeHLRLLR(reqs)
	if len(s.Orphaned) != 2 {
		t.Errorf("expected 2 orphaned LLRs, got %v", s.Orphaned)
	}
	if len(s.Uncovered) != 1 || s.Uncovered[0] != "HLR-001" {
		t.Errorf("expected HLR-001 uncovered, got %v", s.Uncovered)
	}
}

//fusa:test REQ-TRACE008
func TestComputeHLRLLR_UncoveredHLR(t *testing.T) {
	// HLR with no LLR children.
	reqs := []trace.Requirement{
		{ID: "HLR-001", Title: "Has children", Level: "HLR"},
		{ID: "HLR-002", Title: "No children", Level: "HLR"},
		{ID: "LLR-001", Title: "Child of HLR-001", Level: "LLR", ParentID: "HLR-001"},
	}
	s := trace.ComputeHLRLLR(reqs)
	if len(s.Uncovered) != 1 || s.Uncovered[0] != "HLR-002" {
		t.Errorf("expected HLR-002 uncovered, got %v", s.Uncovered)
	}
	if len(s.Orphaned) != 0 {
		t.Errorf("expected no orphaned LLRs, got %v", s.Orphaned)
	}
}

//fusa:test REQ-TRACE008
func TestTRACE008_EngineRule_OrphanedLLR(t *testing.T) {
	// Engine rule fires when LLRs have no valid parent HLR.
	files := testutil.MinimalProject()
	files[trace.ReqsFile] = `{"requirements":[
		{"id":"HLR-001","title":"High","level":"HLR"},
		{"id":"LLR-001","title":"Orphan","level":"LLR","parentId":""}
	]}`
	findings := runTrace(t, files)
	if !hasRule(findings, "TRACE008") {
		t.Error("TRACE008: expected finding for orphaned LLR, got none")
	}
}

//fusa:test REQ-TRACE008
func TestTRACE008_EngineRule_NoViolations(t *testing.T) {
	// Engine rule silent when hierarchy is well-formed.
	files := testutil.MinimalProject()
	files[trace.ReqsFile] = `{"requirements":[
		{"id":"HLR-001","title":"High","level":"HLR"},
		{"id":"LLR-001","title":"Low","level":"LLR","parentId":"HLR-001"}
	]}`
	findings := runTrace(t, files)
	if hasRule(findings, "TRACE008") {
		t.Error("TRACE008: unexpected finding for well-formed HLR/LLR hierarchy")
	}
}

//fusa:test REQ-TRACE008
func TestBuild_HLRLLRSummary_Populated(t *testing.T) {
	dir := t.TempDir()
	writeReqs(t, dir, []trace.Requirement{
		{ID: "HLR-001", Title: "High", Level: "HLR"},
		{ID: "LLR-001", Title: "Low", Level: "LLR", ParentID: "HLR-001"},
	})
	m, err := trace.Build(dir)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if m.HLRLLRSummary == nil {
		t.Fatal("HLRLLRSummary is nil for project with HLR/LLR requirements")
	}
	if m.HLRLLRSummary.HLRCount != 1 || m.HLRLLRSummary.LLRCount != 1 {
		t.Errorf("HLRCount=%d LLRCount=%d, want 1 1", m.HLRLLRSummary.HLRCount, m.HLRLLRSummary.LLRCount)
	}
}

//fusa:test REQ-TRACE008
func TestBuild_HLRLLRSummary_NilWhenNoLevels(t *testing.T) {
	dir := t.TempDir()
	writeReqs(t, dir, []trace.Requirement{
		{ID: "REQ-001", Title: "Plain req"},
	})
	m, err := trace.Build(dir)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if m.HLRLLRSummary != nil {
		t.Error("HLRLLRSummary should be nil when no requirements have Level set")
	}
}

//fusa:test REQ-TRACE008
func TestRenderText_HLRLLRSummaryShown(t *testing.T) {
	m := &trace.Matrix{
		Requirements: []trace.Requirement{
			{ID: "HLR-001", Title: "High", Level: "HLR"},
			{ID: "LLR-001", Title: "Low", Level: "LLR", ParentID: "HLR-001"},
		},
		HLRLLRSummary: &trace.HLRLLRSummary{HLRCount: 1, LLRCount: 1},
	}
	var buf strings.Builder
	if err := trace.Render(&buf, m, "text"); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(buf.String(), "HLR/LLR") {
		t.Error("text render should include HLR/LLR summary line")
	}
}

// ─── ScanFuncTagCoverage (x-FuSa spec §1.4.1 item 2) ─────────────────────────

//fusa:test REQ-TRACE009
func TestScanFuncTagCoverage_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	fc, err := trace.ScanFuncTagCoverage(dir)
	if err != nil {
		t.Fatalf("ScanFuncTagCoverage: %v", err)
	}
	if fc.Total != 0 || fc.Covered != 0 || fc.Pct != 0 {
		t.Errorf("empty dir: got %+v, want all zeroes", fc)
	}
}

//fusa:test REQ-TRACE009
func TestScanFuncTagCoverage_DirectlyTaggedFuncCounts(t *testing.T) {
	dir := t.TempDir()
	src := "package mypkg\n\n" +
		"// DoWork does the work.\n" +
		"//\n" +
		"//fusa:req REQ-001\n" +
		"func DoWork() error { return nil }\n" +
		"\n" +
		"func Untagged() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "work.go"), []byte(src), 0o640); err != nil {
		t.Fatal(err)
	}
	fc, err := trace.ScanFuncTagCoverage(dir)
	if err != nil {
		t.Fatalf("ScanFuncTagCoverage: %v", err)
	}
	if fc.Total != 2 {
		t.Errorf("Total = %d, want 2", fc.Total)
	}
	if fc.Covered != 1 {
		t.Errorf("Covered = %d, want 1 (only the directly-tagged func)", fc.Covered)
	}
	if fc.Pct != 50 {
		t.Errorf("Pct = %f, want 50", fc.Pct)
	}
	if len(fc.Uncovered) != 1 || !strings.Contains(fc.Uncovered[0], "Untagged") {
		t.Errorf("Uncovered = %v, want [work.go:Untagged]", fc.Uncovered)
	}
}

// TestScanFuncTagCoverage_FileLevelTagDoesNotCount verifies function-level
// placement (§1.4.1 item 1): a //fusa:req tag elsewhere in the file, not
// directly above a given function, must NOT count that function as covered —
// this is the key difference from the coarser file-level ScanFuncCoverage.
//
//fusa:test REQ-TRACE009
func TestScanFuncTagCoverage_FileLevelTagDoesNotCount(t *testing.T) {
	dir := t.TempDir()
	src := "package mypkg\n\n" +
		"//fusa:req REQ-001\n" +
		"func Tagged() {}\n" +
		"\n" +
		"func NotDirectlyTagged() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "work.go"), []byte(src), 0o640); err != nil {
		t.Fatal(err)
	}
	fc, err := trace.ScanFuncTagCoverage(dir)
	if err != nil {
		t.Fatalf("ScanFuncTagCoverage: %v", err)
	}
	if fc.Total != 2 {
		t.Errorf("Total = %d, want 2", fc.Total)
	}
	if fc.Covered != 1 {
		t.Errorf("Covered = %d, want 1 (file-level co-location must not count for the second func)", fc.Covered)
	}
}

//fusa:test REQ-TRACE009
func TestScanFuncTagCoverage_SkipsTestFiles(t *testing.T) {
	dir := t.TempDir()
	src := "package mypkg\n\nfunc DoWork() {}\n"
	testSrc := "package mypkg\n\nimport \"testing\"\n\nfunc TestDoWork(t *testing.T) {}\n"
	if err := os.WriteFile(filepath.Join(dir, "work.go"), []byte(src), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "work_test.go"), []byte(testSrc), 0o640); err != nil {
		t.Fatal(err)
	}
	fc, err := trace.ScanFuncTagCoverage(dir)
	if err != nil {
		t.Fatalf("ScanFuncTagCoverage: %v", err)
	}
	if fc.Total != 1 {
		t.Errorf("Total = %d, want 1 (test file excluded)", fc.Total)
	}
}

//fusa:test REQ-TRACE009
func TestScanFuncTagCoverage_SkipsUnexported(t *testing.T) {
	dir := t.TempDir()
	src := "package mypkg\n\nfunc unexported() {}\nfunc Exported() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "f.go"), []byte(src), 0o640); err != nil {
		t.Fatal(err)
	}
	fc, err := trace.ScanFuncTagCoverage(dir)
	if err != nil {
		t.Fatalf("ScanFuncTagCoverage: %v", err)
	}
	if fc.Total != 1 {
		t.Errorf("Total = %d, want 1 (unexported excluded)", fc.Total)
	}
}

// TestScanFuncTagCoverage_ExcludesTrivialStringer verifies String()/Error()
// methods are excluded from both numerator and denominator.
//
//fusa:test REQ-TRACE009
func TestScanFuncTagCoverage_ExcludesTrivialStringer(t *testing.T) {
	dir := t.TempDir()
	src := "package mypkg\n\n" +
		"type Level int\n\n" +
		"func (l Level) String() string { return \"level\" }\n\n" +
		"type MyErr struct{}\n\n" +
		"func (e MyErr) Error() string { return \"boom\" }\n"
	if err := os.WriteFile(filepath.Join(dir, "f.go"), []byte(src), 0o640); err != nil {
		t.Fatal(err)
	}
	fc, err := trace.ScanFuncTagCoverage(dir)
	if err != nil {
		t.Fatalf("ScanFuncTagCoverage: %v", err)
	}
	if fc.Total != 0 {
		t.Errorf("Total = %d, want 0 (String/Error excluded as trivial)", fc.Total)
	}
}

// TestScanFuncTagCoverage_ExcludesBoilerplateGetter verifies a zero-parameter
// single "return <field>" getter is excluded as boilerplate.
//
//fusa:test REQ-TRACE009
func TestScanFuncTagCoverage_ExcludesBoilerplateGetter(t *testing.T) {
	dir := t.TempDir()
	src := "package mypkg\n\n" +
		"type Config struct{ name string }\n\n" +
		"func (c Config) Name() string { return c.name }\n\n" +
		"func (c Config) Compute() string { x := c.name + \"!\"; return x }\n"
	if err := os.WriteFile(filepath.Join(dir, "f.go"), []byte(src), 0o640); err != nil {
		t.Fatal(err)
	}
	fc, err := trace.ScanFuncTagCoverage(dir)
	if err != nil {
		t.Fatalf("ScanFuncTagCoverage: %v", err)
	}
	// Name() is a trivial getter (excluded); Compute() has 2 statements so it
	// is not trivial and must still be counted (untagged).
	if fc.Total != 1 {
		t.Errorf("Total = %d, want 1 (trivial getter excluded, Compute() counted)", fc.Total)
	}
	if fc.Covered != 0 {
		t.Errorf("Covered = %d, want 0", fc.Covered)
	}
}

// TestScanFuncTagCoverage_ExcludesInterfaceBoilerplate verifies a
// zero-parameter method whose body is a single "return <constant literal>"
// statement — the classic engine.Rule.ID()/Description() shape — is excluded
// as generated boilerplate.
//
//fusa:test REQ-TRACE009
func TestScanFuncTagCoverage_ExcludesInterfaceBoilerplate(t *testing.T) {
	dir := t.TempDir()
	src := "package mypkg\n\n" +
		"type myRule struct{}\n\n" +
		"func (r *myRule) ID() string { return \"RULE001\" }\n\n" +
		"func (r *myRule) Description() string { return \"does a thing\" }\n"
	if err := os.WriteFile(filepath.Join(dir, "rule.go"), []byte(src), 0o640); err != nil {
		t.Fatal(err)
	}
	fc, err := trace.ScanFuncTagCoverage(dir)
	if err != nil {
		t.Fatalf("ScanFuncTagCoverage: %v", err)
	}
	if fc.Total != 0 {
		t.Errorf("Total = %d, want 0 (constant-returning interface boilerplate excluded)", fc.Total)
	}
}

//fusa:test REQ-TRACE009
func TestScanFuncTagCoverage_IgnoresVendorAndHidden(t *testing.T) {
	dir := t.TempDir()
	for _, sub := range []string{"vendor", "testdata", ".git"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o750); err != nil {
			t.Fatal(err)
		}
		src := "package mypkg\n\nfunc Exported() {}\n"
		if err := os.WriteFile(filepath.Join(dir, sub, "f.go"), []byte(src), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	fc, err := trace.ScanFuncTagCoverage(dir)
	if err != nil {
		t.Fatalf("ScanFuncTagCoverage: %v", err)
	}
	if fc.Total != 0 {
		t.Errorf("Total = %d, want 0 (vendor/testdata/hidden dirs excluded)", fc.Total)
	}
}

// ─── TRACE009 — dangling //fusa:test tag ──────────────────────────────────────

//fusa:test REQ-TRACE010
func TestTRACE009_DanglingTestTag(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	writeReqs(t, dir, []trace.Requirement{{ID: "REQ-001", Title: "Real requirement"}})
	src := "package main\n\n//fusa:test REQ-DOES-NOT-EXIST\nfunc TestFoo() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "foo_test.go"), []byte(src), 0o640); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default("github.com/example/test", "test")
	result, err := engine.Default.Run(context.Background(), dir, cfg)
	if err != nil {
		t.Fatalf("engine.Run: %v", err)
	}
	if !hasRule(result.Findings, "TRACE009") {
		t.Error("TRACE009: expected finding for dangling //fusa:test tag")
	}
	for _, f := range result.Findings {
		if f.RuleID == "TRACE009" && f.Severity != fusa.SeverityWarning {
			t.Errorf("TRACE009: expected WARNING severity, got %s", f.Severity)
		}
	}

	// Category is auto-derived from the ruleId prefix at report-construction
	// time (report.New), same as every other TRACE-prefixed rule.
	rep := report.New(dir, result.Findings)
	for _, f := range rep.Findings {
		if f.RuleID == "TRACE009" && f.Category != fusa.CategoryRequirement {
			t.Errorf("TRACE009: expected category %q, got %q", fusa.CategoryRequirement, f.Category)
		}
	}
}

//fusa:test REQ-TRACE010
func TestTRACE009_NoDanglingTags(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	writeReqs(t, dir, []trace.Requirement{{ID: "REQ-001", Title: "Real requirement"}})
	src := "package main\n\n//fusa:test REQ-001\nfunc TestFoo() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "foo_test.go"), []byte(src), 0o640); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default("github.com/example/test", "test")
	result, err := engine.Default.Run(context.Background(), dir, cfg)
	if err != nil {
		t.Fatalf("engine.Run: %v", err)
	}
	if hasRule(result.Findings, "TRACE009") {
		t.Error("TRACE009: unexpected finding when all //fusa:test tags reference known requirements")
	}
}

//fusa:test REQ-TRACE010
func TestTRACE009_NoReqsFile(t *testing.T) {
	// No .fusa-reqs.json at all — rule should not be applicable (not every
	// dangling tag in an un-configured project is worth flagging).
	dir := testutil.ProjectDir(t, testutil.GoSource("foo_test.go",
		"package main\n\n//fusa:test REQ-ANYTHING\nfunc TestFoo() {}\n"))

	cfg := config.Default("github.com/example/test", "test")
	result, err := engine.Default.Run(context.Background(), dir, cfg)
	if err != nil {
		t.Fatalf("engine.Run: %v", err)
	}
	if hasRule(result.Findings, "TRACE009") {
		t.Error("TRACE009: unexpected finding when .fusa-reqs.json is absent")
	}
}

// ─── IsExcludedDir ──────────────────────────────────────────────────────────

//fusa:test REQ-TRACE012
func TestIsExcludedDir(t *testing.T) {
	// "." also reports true — deliberately: IsExcludedDir is a pure leaf
	// predicate over a directory's own basename, not root-aware. Every
	// caller already guards the walk root separately (a `path == root`
	// check before ever consulting IsExcludedDir), so a project root whose
	// own basename happens to start with "." is never itself skipped.
	excluded := []string{"vendor", "testdata", ".git", ".hidden", "."}
	for _, name := range excluded {
		if !trace.IsExcludedDir(name) {
			t.Errorf("IsExcludedDir(%q) = false, want true", name)
		}
	}
	included := []string{"pkg", "cmd", "internal"}
	for _, name := range included {
		if trace.IsExcludedDir(name) {
			t.Errorf("IsExcludedDir(%q) = true, want false", name)
		}
	}
}
