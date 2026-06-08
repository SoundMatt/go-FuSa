package engine_test

import (
	"context"
	"errors"
	"testing"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/config"
	"github.com/SoundMatt/go-FuSa/engine"
	"github.com/SoundMatt/go-FuSa/testutil"
)

// stubRule is a test Rule that returns predetermined findings.
type stubRule struct {
	id       string
	findings []fusa.Finding
	err      error
}

func (r *stubRule) ID() string          { return r.id }
func (r *stubRule) Description() string { return "stub rule for testing" }
func (r *stubRule) Run(_ context.Context, _ string, _ *config.Config) ([]fusa.Finding, error) {
	return r.findings, r.err
}

func TestRegistry_Register(t *testing.T) {
	reg := engine.NewRegistry()
	r := &stubRule{id: "TEST001"}
	if err := reg.Register(r); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if got := len(reg.Rules()); got != 1 {
		t.Errorf("Rules(): len = %d, want 1", got)
	}
}

func TestRegistry_Register_Nil(t *testing.T) {
	reg := engine.NewRegistry()
	if err := reg.Register(nil); err == nil {
		t.Error("Register(nil): expected error, got nil")
	}
}

func TestRegistry_Register_Duplicate(t *testing.T) {
	reg := engine.NewRegistry()
	r := &stubRule{id: "TEST001"}
	if err := reg.Register(r); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	if err := reg.Register(r); err == nil {
		t.Error("duplicate Register: expected error, got nil")
	}
}

func TestRegistry_MustRegister_Panics(t *testing.T) {
	reg := engine.NewRegistry()
	r := &stubRule{id: "TEST001"}
	reg.MustRegister(r)
	defer func() {
		if rec := recover(); rec == nil {
			t.Error("MustRegister duplicate: expected panic, got none")
		}
	}()
	reg.MustRegister(r)
}

func TestRegistry_Rules_Sorted(t *testing.T) {
	reg := engine.NewRegistry()
	reg.MustRegister(&stubRule{id: "C"})
	reg.MustRegister(&stubRule{id: "A"})
	reg.MustRegister(&stubRule{id: "B"})
	rules := reg.Rules()
	if rules[0].ID() != "A" || rules[1].ID() != "B" || rules[2].ID() != "C" {
		t.Errorf("Rules() not sorted: %v", ids(rules))
	}
}

func TestRegistry_Run_Findings(t *testing.T) {
	reg := engine.NewRegistry()
	reg.MustRegister(&stubRule{
		id: "TEST001",
		findings: []fusa.Finding{
			{RuleID: "TEST001", Severity: fusa.SeverityError, Message: "boom"},
		},
	})
	cfg := config.Default("github.com/x/y", "y")
	result, err := reg.Run(context.Background(), t.TempDir(), cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Errorf("Findings: len = %d, want 1", len(result.Findings))
	}
	if !result.HasErrors() {
		t.Error("HasErrors: want true")
	}
}

func TestRegistry_Run_Exclude(t *testing.T) {
	reg := engine.NewRegistry()
	reg.MustRegister(&stubRule{id: "SKIP", findings: []fusa.Finding{{RuleID: "SKIP", Severity: fusa.SeverityError}}})
	reg.MustRegister(&stubRule{id: "RUN", findings: []fusa.Finding{{RuleID: "RUN", Severity: fusa.SeverityInfo}}})
	cfg := config.Default("github.com/x/y", "y")
	cfg.Rules.Exclude = []string{"SKIP"}
	result, err := reg.Run(context.Background(), t.TempDir(), cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range result.Findings {
		if f.RuleID == "SKIP" {
			t.Error("excluded rule SKIP still produced findings")
		}
	}
	if result.HasErrors() {
		t.Error("HasErrors: want false after excluding error rule")
	}
}

func TestRegistry_Run_RuleError(t *testing.T) {
	reg := engine.NewRegistry()
	reg.MustRegister(&stubRule{id: "FAIL", err: errors.New("rule internal error")})
	cfg := config.Default("github.com/x/y", "y")
	result, err := reg.Run(context.Background(), t.TempDir(), cfg)
	if err != nil {
		t.Fatalf("Run: unexpected fatal error: %v", err)
	}
	if len(result.Errors) == 0 {
		t.Error("expected rule error collected, got none")
	}
}

func TestRegistry_Run_ContextCancelled(t *testing.T) {
	reg := engine.NewRegistry()
	for _, id := range []string{"A", "B", "C"} {
		reg.MustRegister(&stubRule{
			id:       id,
			findings: []fusa.Finding{{RuleID: id, Severity: fusa.SeverityInfo}},
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately
	cfg := config.Default("github.com/x/y", "y")
	result, err := reg.Run(ctx, t.TempDir(), cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// With a cancelled context, no rules should run.
	if len(result.Findings) != 0 {
		t.Errorf("cancelled context: expected 0 findings, got %d", len(result.Findings))
	}
}

func TestResult_HasErrors_Empty(t *testing.T) {
	r := &engine.Result{}
	if r.HasErrors() {
		t.Error("empty result: HasErrors should be false")
	}
}

// ─── Built-in rules ───────────────────────────────────────────────────────────

func TestBuiltinRules_FullProject(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	cfg := config.Default("github.com/example/test", "test")
	result, err := engine.Default.Run(context.Background(), dir, cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.HasErrors() {
		t.Errorf("full project should have no errors; findings: %v", result.Findings)
	}
}

//fusa:test REQ-FUSA001
func TestBuiltinRule_FUSA001_MissingConfig(t *testing.T) {
	dir := testutil.ProjectDir(t, map[string]string{
		"go.mod": "module github.com/x/y\n\ngo 1.22\n",
	})
	cfg := config.Default("github.com/x/y", "y")
	result, err := engine.Default.Run(context.Background(), dir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !findingExists(result.Findings, "FUSA001", fusa.SeverityError) {
		t.Error("FUSA001: expected ERROR finding for missing .fusa.json")
	}
}

//fusa:test REQ-FUSA002
func TestBuiltinRule_FUSA002_MissingGoMod(t *testing.T) {
	dir := testutil.ProjectDir(t, map[string]string{
		config.ConfigFile: `{"version":"1","project":{"name":"x","module":"github.com/x/y","standard":"generic"},"report":{"format":"text"}}`,
	})
	cfg := config.Default("github.com/x/y", "y")
	result, err := engine.Default.Run(context.Background(), dir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !findingExists(result.Findings, "FUSA002", fusa.SeverityError) {
		t.Error("FUSA002: expected ERROR finding for missing go.mod")
	}
}

//fusa:test REQ-FUSA003
func TestBuiltinRule_FUSA003_MissingLicense(t *testing.T) {
	files := testutil.MinimalProject()
	delete(files, "LICENSE")
	dir := testutil.ProjectDir(t, files)
	cfg := config.Default("github.com/example/test", "test")
	result, err := engine.Default.Run(context.Background(), dir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !findingExists(result.Findings, "FUSA003", fusa.SeverityWarning) {
		t.Error("FUSA003: expected WARNING for missing LICENSE")
	}
}

//fusa:test REQ-FUSA004
func TestBuiltinRule_FUSA004_MissingReadme(t *testing.T) {
	files := testutil.MinimalProject()
	delete(files, "README.md")
	dir := testutil.ProjectDir(t, files)
	cfg := config.Default("github.com/example/test", "test")
	result, err := engine.Default.Run(context.Background(), dir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !findingExists(result.Findings, "FUSA004", fusa.SeverityWarning) {
		t.Error("FUSA004: expected WARNING for missing README")
	}
}

//fusa:test REQ-FUSA005
func TestBuiltinRule_FUSA005_MissingCI(t *testing.T) {
	files := testutil.MinimalProject()
	delete(files, ".github/workflows/ci.yml")
	dir := testutil.ProjectDir(t, files)
	cfg := config.Default("github.com/example/test", "test")
	result, err := engine.Default.Run(context.Background(), dir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !findingExists(result.Findings, "FUSA005", fusa.SeverityWarning) {
		t.Error("FUSA005: expected WARNING for missing CI")
	}
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func findingExists(findings []fusa.Finding, ruleID string, sev fusa.Severity) bool {
	for _, f := range findings {
		if f.RuleID == ruleID && f.Severity == sev {
			return true
		}
	}
	return false
}

func ids(rules []engine.Rule) []string {
	out := make([]string, len(rules))
	for i, r := range rules {
		out[i] = r.ID()
	}
	return out
}
