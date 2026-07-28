package qualify_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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

//fusa:test REQ-QUALIFY006
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
	const wantLen = 71 // "sha256:" (7) + 64 hex chars
	if len(report.Hash) != wantLen {
		t.Errorf("Run: Hash length = %d, want %d (\"sha256:<64-hex>\")", len(report.Hash), wantLen)
	}
	if !strings.HasPrefix(report.Hash, "sha256:") {
		t.Errorf("Run: Hash does not start with \"sha256:\": %q", report.Hash)
	}
}

// x-FuSa spec §6 MUST: results[].result is a PASS/FAIL/SKIP/ERROR enum
// string, not just a results[].passed bool. Regression test for #51.
//
//fusa:test REQ-QUALIFY010
func TestRun_ResultsCarrySpecEnumString(t *testing.T) {
	cases := qualify.BuiltinCases()
	report, err := qualify.Run(context.Background(), engine.Default, cases)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(report.Results) == 0 {
		t.Fatal("Run: no results")
	}
	for _, r := range report.Results {
		switch r.Result {
		case qualify.ResultPass, qualify.ResultFail, qualify.ResultSkip, qualify.ResultError:
			// valid
		default:
			t.Errorf("case %s: Result = %q, want one of PASS/FAIL/SKIP/ERROR", r.Case.Name, r.Result)
		}
		if (r.Result == qualify.ResultPass) != r.Passed {
			t.Errorf("case %s: Result = %q inconsistent with Passed = %v", r.Case.Name, r.Result, r.Passed)
		}
	}

	// The field must also round-trip through the JSON the CLI writes.
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var payload struct {
		Results []struct {
			Result string `json:"result"`
		} `json:"results"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(payload.Results) == 0 || payload.Results[0].Result == "" {
		t.Error("marshaled JSON results[0].result is empty")
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

//fusa:test REQ-QUALIFY009
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

//fusa:test REQ-QUALIFY005
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

// ─── Feature 2: Tool qualification display ────────────────────────────────────

//fusa:test REQ-QUALIFY007
func TestReport_QualificationBadge_Independent(t *testing.T) {
	r := &qualify.Report{QualificationMethod: "independent"}
	if badge := r.QualificationBadge(); badge != "independently-qualified" {
		t.Errorf("QualificationBadge = %q, want \"independently-qualified\"", badge)
	}
}

//fusa:test REQ-QUALIFY007
func TestReport_QualificationBadge_Self(t *testing.T) {
	r := &qualify.Report{QualificationMethod: "self"}
	if badge := r.QualificationBadge(); badge != "self-qualified" {
		t.Errorf("QualificationBadge = %q, want \"self-qualified\"", badge)
	}
}

//fusa:test REQ-QUALIFY007
func TestReport_QualificationBadge_Unset(t *testing.T) {
	r := &qualify.Report{}
	if badge := r.QualificationBadge(); badge != "unqualified" {
		t.Errorf("QualificationBadge = %q, want \"unqualified\"", badge)
	}
}

//fusa:test REQ-QUALIFY007
func TestReport_QualificationFields_RoundTrip(t *testing.T) {
	r := &qualify.Report{
		QualificationMethod:    "independent",
		QualificationRecordUri: "https://example.com/dossier",
		QualifierIdentity:      "Acme Safety Labs",
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got qualify.Report
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.QualificationMethod != "independent" {
		t.Errorf("QualificationMethod = %q", got.QualificationMethod)
	}
	if got.QualificationRecordUri != "https://example.com/dossier" {
		t.Errorf("QualificationRecordUri = %q", got.QualificationRecordUri)
	}
	if got.QualifierIdentity != "Acme Safety Labs" {
		t.Errorf("QualifierIdentity = %q", got.QualifierIdentity)
	}
}

// ─── Feature 4: V&V independence ─────────────────────────────────────────────

//fusa:test REQ-QUALIFY008
func TestReport_IndependenceStatus_Independent(t *testing.T) {
	r := &qualify.Report{
		ImplementationAuthor: "Alice",
		IndependentReviewer:  "Bob",
	}
	if status := r.IndependenceStatus(); status != "independent" {
		t.Errorf("IndependenceStatus = %q, want \"independent\"", status)
	}
}

//fusa:test REQ-QUALIFY008
func TestReport_IndependenceStatus_SelfReviewed(t *testing.T) {
	r := &qualify.Report{
		ImplementationAuthor: "Alice",
		IndependentReviewer:  "Alice",
	}
	if status := r.IndependenceStatus(); status != "self-reviewed" {
		t.Errorf("IndependenceStatus = %q, want \"self-reviewed\"", status)
	}
}

//fusa:test REQ-QUALIFY008
func TestReport_IndependenceStatus_Unqualified(t *testing.T) {
	r := &qualify.Report{ImplementationAuthor: "Alice"}
	if status := r.IndependenceStatus(); status != "unqualified" {
		t.Errorf("IndependenceStatus = %q, want \"unqualified\"", status)
	}
}

//fusa:test REQ-QUALIFY008
func TestReport_VVIndependenceFields_RoundTrip(t *testing.T) {
	r := &qualify.Report{
		ImplementationAuthor:    "Alice",
		IndependentReviewer:     "Bob",
		IndependentTestExecutor: "Carol",
		AchievableASIL:          "ASIL-D",
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got qualify.Report
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.ImplementationAuthor != "Alice" {
		t.Errorf("ImplementationAuthor = %q", got.ImplementationAuthor)
	}
	if got.IndependentReviewer != "Bob" {
		t.Errorf("IndependentReviewer = %q", got.IndependentReviewer)
	}
	if got.IndependentTestExecutor != "Carol" {
		t.Errorf("IndependentTestExecutor = %q", got.IndependentTestExecutor)
	}
	if got.AchievableASIL != "ASIL-D" {
		t.Errorf("AchievableASIL = %q", got.AchievableASIL)
	}
}
