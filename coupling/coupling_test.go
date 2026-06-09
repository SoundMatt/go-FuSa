package coupling_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SoundMatt/go-FuSa/config"
	"github.com/SoundMatt/go-FuSa/coupling"
	"github.com/SoundMatt/go-FuSa/engine"
)

func loadConfig(t *testing.T, path string) *config.Config {
	t.Helper()
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	return cfg
}

func writeGoFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func runRule(t *testing.T, rule engine.Rule, dir string) []string {
	t.Helper()
	findings, err := rule.Run(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("Run %s: %v", rule.ID(), err)
	}
	var ids []string
	for _, f := range findings {
		ids = append(ids, f.RuleID+":"+f.Message)
	}
	return ids
}

func TestCOUP001_ExportedVar(t *testing.T) {
	dir := t.TempDir()
	writeGoFile(t, dir, "main.go", `package main

var ExportedGlobal = "shared"
var unexported = "private"
`)
	rule := coupling.NewDataCouplingRule()
	findings, err := rule.Run(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	found := false
	for _, f := range findings {
		if strings.Contains(f.Message, "ExportedGlobal") {
			found = true
		}
	}
	if !found {
		t.Error("expected COUP001 finding for ExportedGlobal")
	}
	for _, f := range findings {
		if strings.Contains(f.Message, "unexported") {
			t.Error("unexported var should not trigger COUP001")
		}
	}
}

func TestCOUP001_NoExportedVars(t *testing.T) {
	dir := t.TempDir()
	writeGoFile(t, dir, "main.go", `package main

var privateOnly = 42
const PublicConst = "ok"
`)
	rule := coupling.NewDataCouplingRule()
	findings, err := rule.Run(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %d", len(findings))
	}
}

func TestCOUP002_FuncParam(t *testing.T) {
	dir := t.TempDir()
	writeGoFile(t, dir, "main.go", `package main

func DoWork(fn func() error) error { return fn() }
func helper(s string) {}
`)
	rule := coupling.NewControlCouplingRule()
	findings, err := rule.Run(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	found := false
	for _, f := range findings {
		if strings.Contains(f.Message, "DoWork") {
			found = true
		}
	}
	if !found {
		t.Error("expected COUP002 finding for func parameter")
	}
}

func TestCOUP002_InlineInterfaceParam(t *testing.T) {
	dir := t.TempDir()
	writeGoFile(t, dir, "main.go", `package main

func Execute(action interface{ Do() }) { action.Do() }
`)
	rule := coupling.NewControlCouplingRule()
	findings, err := rule.Run(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) == 0 {
		t.Error("expected COUP002 finding for inline interface parameter")
	}
}

func TestCOUP002_UnexportedFunc(t *testing.T) {
	dir := t.TempDir()
	writeGoFile(t, dir, "main.go", `package main

func unexported(fn func()) { fn() }
`)
	rule := coupling.NewControlCouplingRule()
	findings, err := rule.Run(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings for unexported func, got %d", len(findings))
	}
}

func TestRuleIDs(t *testing.T) {
	if id := coupling.NewDataCouplingRule().ID(); id != "COUP001" {
		t.Errorf("ID = %q", id)
	}
	if id := coupling.NewControlCouplingRule().ID(); id != "COUP002" {
		t.Errorf("ID = %q", id)
	}
}

func TestDescriptions(t *testing.T) {
	if d := coupling.NewDataCouplingRule().Description(); d == "" {
		t.Error("COUP001 Description should not be empty")
	}
	if d := coupling.NewControlCouplingRule().Description(); d == "" {
		t.Error("COUP002 Description should not be empty")
	}
}

func TestTestFileSkipped(t *testing.T) {
	dir := t.TempDir()
	// _test.go files should be skipped
	writeGoFile(t, dir, "foo_test.go", `package main_test

var ExportedInTest = "hi"
`)
	rule := coupling.NewDataCouplingRule()
	findings, err := rule.Run(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("test files should be skipped, got %d findings", len(findings))
	}
}

// Ensure the runRule helper compiles (used in other test functions if needed).
var _ = runRule

// ─── CouplingReport / SaveReport ──────────────────────────────────────────────

func TestSaveReport_WritesValidJSON(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, coupling.CouplingReportFile)
	if err := coupling.SaveReport(outPath, nil, nil, dir); err != nil {
		t.Fatalf("SaveReport: %v", err)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !strings.Contains(string(data), `"generatedAt"`) {
		t.Error("output does not contain generatedAt")
	}
}

func TestSaveReport_WithFindings(t *testing.T) {
	dir := t.TempDir()
	writeGoFile(t, dir, "a.go", `package pkg
import "fmt"
var Exported int = 0
func Fn(cb func()) { fmt.Println(cb) }
`)
	dataRule := coupling.NewDataCouplingRule()
	ctrlRule := coupling.NewControlCouplingRule()
	data, _ := dataRule.Run(context.Background(), dir, nil)
	ctrl, _ := ctrlRule.Run(context.Background(), dir, nil)

	outPath := filepath.Join(dir, coupling.CouplingReportFile)
	if err := coupling.SaveReport(outPath, data, ctrl, dir); err != nil {
		t.Fatalf("SaveReport: %v", err)
	}
	raw, _ := os.ReadFile(outPath)
	if !strings.Contains(string(raw), `"dataCoupling"`) {
		t.Error("report missing dataCoupling field")
	}
	if !strings.Contains(string(raw), `"controlCoupling"`) {
		t.Error("report missing controlCoupling field")
	}
}

// ─── COUP003 ──────────────────────────────────────────────────────────────────

func findRule(t *testing.T, id string) engine.Rule {
	t.Helper()
	for _, r := range engine.Default.Rules() {
		if r.ID() == id {
			return r
		}
	}
	t.Fatalf("%s not registered in engine", id)
	return nil
}

func writeFusaJSON(t *testing.T, dir, standard string) {
	t.Helper()
	content := `{"version":"1","project":{"name":"t","module":"t","standard":"` + standard + `"},"rules":{},"report":{"format":"text"}}`
	if err := os.WriteFile(filepath.Join(dir, ".fusa.json"), []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
}

func TestCOUP003_FiredWhenDO178CAndNoReport(t *testing.T) {
	dir := t.TempDir()
	writeFusaJSON(t, dir, "DO178C")
	cfg := loadConfig(t, filepath.Join(dir, ".fusa.json"))
	rule := findRule(t, "COUP003")
	findings, err := rule.Run(context.Background(), dir, cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) == 0 {
		t.Error("expected COUP003 finding for DO178C project without coupling-report.json")
	}
}

func TestCOUP003_SilentWhenNonDO178C(t *testing.T) {
	dir := t.TempDir()
	rule := findRule(t, "COUP003")
	findings, err := rule.Run(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("COUP003 should not fire for non-DO178C project, got %d findings", len(findings))
	}
}

func TestCOUP003_SilentWhenReportPresent(t *testing.T) {
	dir := t.TempDir()
	writeFusaJSON(t, dir, "DO178C")
	if err := os.WriteFile(filepath.Join(dir, coupling.CouplingReportFile), []byte(`{}`), 0o640); err != nil {
		t.Fatal(err)
	}
	cfg := loadConfig(t, filepath.Join(dir, ".fusa.json"))
	rule := findRule(t, "COUP003")
	findings, err := rule.Run(context.Background(), dir, cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("COUP003 should not fire when report present, got %d findings", len(findings))
	}
}
