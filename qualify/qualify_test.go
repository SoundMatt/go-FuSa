package qualify_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	// Blank imports populate engine.Default with all built-in rule sets.
	_ "github.com/SoundMatt/go-FuSa/analyze"
	_ "github.com/SoundMatt/go-FuSa/lint"
	_ "github.com/SoundMatt/go-FuSa/release"
	_ "github.com/SoundMatt/go-FuSa/trace"
	_ "github.com/SoundMatt/go-FuSa/verify"

	"github.com/SoundMatt/go-FuSa/engine"
	"github.com/SoundMatt/go-FuSa/qualify"
)

// ─── BuiltinCases ─────────────────────────────────────────────────────────────

func TestBuiltinCases_NonEmpty(t *testing.T) {
	cases := qualify.BuiltinCases()
	if len(cases) == 0 {
		t.Fatal("BuiltinCases: expected non-empty slice")
	}
}

func TestBuiltinCases_EachHasRuleAndName(t *testing.T) {
	for i, c := range qualify.BuiltinCases() {
		if c.Name == "" {
			t.Errorf("[%d] Case.Name is empty", i)
		}
		if c.RuleID == "" {
			t.Errorf("[%d] Case.RuleID is empty", i)
		}
		if c.Description == "" {
			t.Errorf("[%d] Case.Description is empty", i)
		}
		if len(c.Files) == 0 {
			t.Errorf("[%d] %s: Files map is empty", i, c.Name)
		}
	}
}

// ─── Run ──────────────────────────────────────────────────────────────────────

//fusa:test REQ-QUALIFY001
//fusa:test REQ-QUALIFY002
//fusa:test REQ-QUALIFY003
func TestRun_AllBuiltinCases(t *testing.T) {
	cases := qualify.BuiltinCases()
	report, err := qualify.Run(context.Background(), engine.Default, cases)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if report.Total != len(cases) {
		t.Errorf("Total = %d, want %d", report.Total, len(cases))
	}
	if report.HasFailures() {
		t.Errorf("%d/%d case(s) failed:", report.Failed, report.Total)
		for _, r := range report.Results {
			if !r.Passed {
				t.Errorf("  FAIL %s: %s", r.Case.Name, r.Error)
			}
		}
	}
}

//fusa:test REQ-QUALIFY004
func TestRun_HashIsSet(t *testing.T) {
	cases := qualify.BuiltinCases()
	report, err := qualify.Run(context.Background(), engine.Default, cases)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if report.Hash == "" {
		t.Error("Run: Hash field is empty")
	}
	if len(report.Hash) != 64 {
		t.Errorf("Run: Hash length = %d, want 64 (SHA-256 hex)", len(report.Hash))
	}
}

func TestRun_EmptyCases(t *testing.T) {
	report, err := qualify.Run(context.Background(), engine.Default, nil)
	if err != nil {
		t.Fatalf("Run (no cases): %v", err)
	}
	if report.Total != 0 {
		t.Errorf("Total = %d, want 0", report.Total)
	}
	if report.HasFailures() {
		t.Error("HasFailures should be false for empty run")
	}
}

// ─── HasFailures ──────────────────────────────────────────────────────────────

func TestHasFailures(t *testing.T) {
	pass := &qualify.Report{Total: 2, Passed: 2, Failed: 0}
	if pass.HasFailures() {
		t.Error("HasFailures: expected false for all-pass report")
	}
	fail := &qualify.Report{Total: 2, Passed: 1, Failed: 1}
	if !fail.HasFailures() {
		t.Error("HasFailures: expected true for report with failures")
	}
}

// ─── Save / Load ──────────────────────────────────────────────────────────────

func TestSaveAndLoad_Roundtrip(t *testing.T) {
	cases := qualify.BuiltinCases()[:2]
	report, err := qualify.Run(context.Background(), engine.Default, cases)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	path := filepath.Join(t.TempDir(), qualify.ReportFile)
	if saveErr := qualify.Save(path, report); saveErr != nil {
		t.Fatalf("Save: %v", saveErr)
	}
	loaded, err := qualify.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Total != report.Total {
		t.Errorf("roundtrip Total = %d, want %d", loaded.Total, report.Total)
	}
	if loaded.Hash != report.Hash {
		t.Errorf("roundtrip Hash mismatch: got %q, want %q", loaded.Hash, report.Hash)
	}
}

func TestLoad_NotFound(t *testing.T) {
	_, err := qualify.Load(filepath.Join(t.TempDir(), "missing.json"))
	if err == nil {
		t.Fatal("Load: expected error for missing file")
	}
}

func TestLoad_MalformedJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), qualify.ReportFile)
	if err := os.WriteFile(path, []byte("not json"), 0o640); err != nil {
		t.Fatal(err)
	}
	_, err := qualify.Load(path)
	if err == nil {
		t.Fatal("Load: expected error for malformed JSON")
	}
}

// ─── JSON serialisation ───────────────────────────────────────────────────────

func TestReport_JSONRoundtrip(t *testing.T) {
	r := &qualify.Report{
		GoVersion: "go1.22",
		Total:     1,
		Passed:    1,
		Results: []qualify.Result{
			{Case: qualify.Case{Name: "test", RuleID: "X001", Files: map[string]string{"f": "x"}}, Passed: true},
		},
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got qualify.Report
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.GoVersion != r.GoVersion {
		t.Errorf("GoVersion = %q, want %q", got.GoVersion, r.GoVersion)
	}
	if len(got.Results) != 1 {
		t.Errorf("Results len = %d, want 1", len(got.Results))
	}
}

func TestQUALIFY001_Description(t *testing.T) {
	for _, r := range engine.Default.Rules() {
		if r.ID() == "QUALIFY001" {
			if r.Description() == "" {
				t.Error("QUALIFY001 Description() is empty")
			}
			return
		}
	}
	t.Error("QUALIFY001 not registered")
}
