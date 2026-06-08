package verify_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/config"
	"github.com/SoundMatt/go-FuSa/engine"
	"github.com/SoundMatt/go-FuSa/testutil"
	"github.com/SoundMatt/go-FuSa/verify"
)

// ─── Parse ────────────────────────────────────────────────────────────────────

const sampleJSON = `{"Action":"run","Test":"TestFoo","Package":"example/pkg"}
{"Action":"pass","Test":"TestFoo","Package":"example/pkg","Elapsed":0.001}
{"Action":"run","Test":"TestBar","Package":"example/pkg"}
{"Action":"fail","Test":"TestBar","Package":"example/pkg","Elapsed":0.002}
{"Action":"run","Test":"TestBaz","Package":"example/pkg"}
{"Action":"skip","Test":"TestBaz","Package":"example/pkg","Elapsed":0.000}
{"Action":"pass","Package":"example/pkg","Elapsed":0.003}
`

//fusa:test REQ-VERIFY004
func TestParse_Results(t *testing.T) {
	results, err := verify.Parse(strings.NewReader(sampleJSON))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("Parse: got %d results, want 3", len(results))
	}
	want := []struct {
		name   string
		status verify.TestStatus
	}{
		{"TestFoo", verify.StatusPass},
		{"TestBar", verify.StatusFail},
		{"TestBaz", verify.StatusSkip},
	}
	for i, w := range want {
		if results[i].Name != w.name {
			t.Errorf("[%d] Name = %q, want %q", i, results[i].Name, w.name)
		}
		if results[i].Status != w.status {
			t.Errorf("[%d] Status = %q, want %q", i, results[i].Status, w.status)
		}
	}
}

func TestParse_InvalidJSON(t *testing.T) {
	_, err := verify.Parse(strings.NewReader("not json\n"))
	if err == nil {
		t.Error("Parse: expected error for invalid JSON")
	}
}

func TestParse_Empty(t *testing.T) {
	results, err := verify.Parse(strings.NewReader(""))
	if err != nil {
		t.Fatalf("Parse empty: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("Parse empty: got %d results, want 0", len(results))
	}
}

// ─── Summarise ────────────────────────────────────────────────────────────────

func TestSummarise(t *testing.T) {
	results := []verify.TestResult{
		{Name: "A", Status: verify.StatusPass},
		{Name: "B", Status: verify.StatusFail},
		{Name: "C", Status: verify.StatusSkip},
		{Name: "D", Status: verify.StatusPass},
	}
	s := verify.Summarise(results)
	if s.Total != 4 {
		t.Errorf("Total = %d, want 4", s.Total)
	}
	if s.Passed != 2 {
		t.Errorf("Passed = %d, want 2", s.Passed)
	}
	if s.Failed != 1 {
		t.Errorf("Failed = %d, want 1", s.Failed)
	}
	if s.Skipped != 1 {
		t.Errorf("Skipped = %d, want 1", s.Skipped)
	}
}

// ─── New / Save / Load ────────────────────────────────────────────────────────

//fusa:test REQ-VERIFY003
func TestNewBundle(t *testing.T) {
	results := []verify.TestResult{
		{Name: "TestOne", Package: "pkg", Status: verify.StatusPass, Elapsed: 0.001},
	}
	b := verify.New("/project", results)
	if b.ProjectRoot != "/project" {
		t.Errorf("ProjectRoot = %q, want /project", b.ProjectRoot)
	}
	if b.GoVersion == "" {
		t.Error("GoVersion should be set")
	}
	if b.Summary.Total != 1 || b.Summary.Passed != 1 {
		t.Errorf("Summary = %+v, want Total=1 Passed=1", b.Summary)
	}
}

func TestSaveAndLoad_Roundtrip(t *testing.T) {
	dir := t.TempDir()
	results, err := verify.Parse(strings.NewReader(sampleJSON))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	b := verify.New(dir, results)
	path := filepath.Join(dir, verify.BundleFile)
	err = verify.Save(path, b)
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	loaded, err := verify.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Summary.Total != b.Summary.Total {
		t.Errorf("roundtrip Summary.Total = %d, want %d", loaded.Summary.Total, b.Summary.Total)
	}
	if len(loaded.Results) != len(b.Results) {
		t.Errorf("roundtrip Results len = %d, want %d", len(loaded.Results), len(b.Results))
	}
}

func TestLoad_NotFound(t *testing.T) {
	_, err := verify.Load(filepath.Join(t.TempDir(), "missing.json"))
	if err == nil {
		t.Fatal("Load: expected error for missing file")
	}
}

// ─── Run (integration) ────────────────────────────────────────────────────────

//fusa:test REQ-VERIFY005
func TestRun_PassingTests(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"),
		[]byte("module testmod\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	src := `package testmod

import "testing"

func TestAlwaysPass(t *testing.T) { _ = t }
`
	if err := os.WriteFile(filepath.Join(dir, "pass_test.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	results, err := verify.Run(context.Background(), dir)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(results) == 0 {
		t.Error("Run: expected at least one result")
	}
	for _, r := range results {
		if r.Status != verify.StatusPass {
			t.Errorf("Run: test %q: got status %q, want pass", r.Name, r.Status)
		}
	}
}

// ─── Engine rules ─────────────────────────────────────────────────────────────

func hasRule(findings []fusa.Finding, ruleID string) bool {
	for _, f := range findings {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}

func runVerify(t *testing.T, files map[string]string) []fusa.Finding {
	t.Helper()
	dir := testutil.ProjectDir(t, files)
	cfg := config.Default("github.com/example/test", "test")
	result, err := engine.Default.Run(context.Background(), dir, cfg)
	if err != nil {
		t.Fatalf("engine.Run: %v", err)
	}
	return result.Findings
}

//fusa:test REQ-VERIFY001
func TestVERIFY001_NoBundleFile(t *testing.T) {
	findings := runVerify(t, testutil.MinimalProject())
	if !hasRule(findings, "VERIFY001") {
		t.Error("VERIFY001: expected INFO finding when bundle absent")
	}
}

func TestVERIFY001_BundlePresent(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	b := verify.New(dir, nil)
	if err := verify.Save(filepath.Join(dir, verify.BundleFile), b); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default("github.com/example/test", "test")
	result, err := engine.Default.Run(context.Background(), dir, cfg)
	if err != nil {
		t.Fatalf("engine.Run: %v", err)
	}
	if hasRule(result.Findings, "VERIFY001") {
		t.Error("VERIFY001: unexpected finding when bundle is present")
	}
}

//fusa:test REQ-VERIFY002
func TestVERIFY002_FailedTests(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	results := []verify.TestResult{
		{Name: "TestA", Status: verify.StatusPass},
		{Name: "TestB", Status: verify.StatusFail},
	}
	b := verify.New(dir, results)
	if err := verify.Save(filepath.Join(dir, verify.BundleFile), b); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default("github.com/example/test", "test")
	result, err := engine.Default.Run(context.Background(), dir, cfg)
	if err != nil {
		t.Fatalf("engine.Run: %v", err)
	}
	if !hasRule(result.Findings, "VERIFY002") {
		t.Error("VERIFY002: expected WARNING for failed tests in bundle")
	}
}

// ─── Fuzz ─────────────────────────────────────────────────────────────────────

func FuzzParse(f *testing.F) {
	f.Add(`{"Action":"pass","Test":"TestFoo","Package":"p","Elapsed":0.001}` + "\n")
	f.Add(`{"Action":"fail","Test":"T","Package":"p"}` + "\n")
	f.Add("")
	f.Add("not json\n")
	f.Add(`{}` + "\n")
	f.Fuzz(func(t *testing.T, data string) {
		_, _ = verify.Parse(strings.NewReader(data)) // must not panic
	})
}

func TestVERIFY002_AllTestsPassed(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	results := []verify.TestResult{
		{Name: "TestA", Status: verify.StatusPass},
	}
	b := verify.New(dir, results)
	if err := verify.Save(filepath.Join(dir, verify.BundleFile), b); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default("github.com/example/test", "test")
	result, err := engine.Default.Run(context.Background(), dir, cfg)
	if err != nil {
		t.Fatalf("engine.Run: %v", err)
	}
	if hasRule(result.Findings, "VERIFY002") {
		t.Error("VERIFY002: unexpected finding when all tests passed")
	}
}
