package coupling_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/SoundMatt/go-FuSa/coupling"
	"github.com/SoundMatt/go-FuSa/engine"
)

// TestSaveReport_BadPath exercises the write error path.
func TestSaveReport_BadPath(t *testing.T) {
	err := coupling.SaveReport("/nonexistent/dir/coupling.json", nil, nil, "proj")
	if err == nil {
		t.Error("expected error for bad path")
	}
}

// TestSaveReport_NilFindings exercises SaveReport with nil slices.
func TestSaveReport_NilFindings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "coupling.json")
	err := coupling.SaveReport(path, nil, nil, "proj")
	if err != nil {
		t.Errorf("SaveReport nil findings: %v", err)
	}
	if _, statErr := os.Stat(path); statErr != nil {
		t.Error("SaveReport did not create output file")
	}
}

// TestCOUP002_InterfaceParam exercises the interface parameter case.
func TestCOUP002_InterfaceParam(t *testing.T) {
	dir := t.TempDir()
	src := `package main

// ExportedWithInterface accepts an interface param
func ExportedWithInterface(r interface{ Read([]byte) (int, error) }) error {
	return nil
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	rule := coupling.NewControlCouplingRule()
	findings, err := rule.Run(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) == 0 {
		t.Error("COUP002: expected finding for exported function with interface parameter")
	}
}

// TestParseModuleFiles_TestdataDir covers the testdata directory skip.
func TestParseModuleFiles_TestdataDir(t *testing.T) {
	dir := t.TempDir()
	testdataDir := filepath.Join(dir, "testdata")
	if err := os.MkdirAll(testdataDir, 0o750); err != nil {
		t.Fatal(err)
	}
	// File in testdata should be skipped
	src := `package testdata
var ExportedInTestdata = "value"
`
	if err := os.WriteFile(filepath.Join(testdataDir, "data.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	// Main file — no exported vars
	main := `package main
func main() {}
`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(main), 0o644); err != nil {
		t.Fatal(err)
	}
	rule := coupling.NewDataCouplingRule()
	findings, err := rule.Run(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// No findings from testdata; the exported var there should be skipped
	for _, f := range findings {
		if contains(f.Location.File, "testdata") {
			t.Errorf("COUP001: unexpected finding in testdata: %v", f)
		}
	}
}

// TestParseModuleFiles_DotDir covers the dot-prefixed directory skip.
func TestParseModuleFiles_DotDir(t *testing.T) {
	dir := t.TempDir()
	dotDir := filepath.Join(dir, ".hidden")
	if err := os.MkdirAll(dotDir, 0o750); err != nil {
		t.Fatal(err)
	}
	src := `package hidden
var ExportedInDot = "value"
`
	if err := os.WriteFile(filepath.Join(dotDir, "hidden.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	main := `package main
func main() {}
`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(main), 0o644); err != nil {
		t.Fatal(err)
	}
	rule := coupling.NewDataCouplingRule()
	findings, err := rule.Run(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range findings {
		if contains(f.Location.File, ".hidden") {
			t.Errorf("COUP001: unexpected finding in .hidden dir: %v", f)
		}
	}
}

// TestRun_WithVendorDir exercises the vendor directory skip.
func TestRun_WithVendorDir(t *testing.T) {
	dir := t.TempDir()
	vendorDir := filepath.Join(dir, "vendor", "pkg")
	if err := os.MkdirAll(vendorDir, 0o750); err != nil {
		t.Fatal(err)
	}
	// Exported var in vendor — should be skipped
	if err := os.WriteFile(filepath.Join(vendorDir, "vendor.go"), []byte("package pkg\nvar VendorVar = \"val\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rule := coupling.NewDataCouplingRule()
	findings, err := rule.Run(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range findings {
		if contains(f.Location.File, "vendor") {
			t.Errorf("COUP001: unexpected finding in vendor: %v", f)
		}
	}
}

// TestCOUP001_Run_SubdirectorySkipped exercises non-root dirs.
func TestCOUP001_MultiDir(t *testing.T) {
	dir := t.TempDir()
	subDir := filepath.Join(dir, "subpkg")
	if err := os.MkdirAll(subDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "sub.go"), []byte("package subpkg\nvar SubExported = \"x\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\nvar MainExported = \"y\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rule := coupling.NewDataCouplingRule()
	findings, err := rule.Run(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) < 2 {
		t.Errorf("expected >= 2 findings (one per exported var), got %d", len(findings))
	}
}

// TestCOUP002_ExportedFuncNoParams covers exported func with no parameters.
func TestCOUP002_ExportedFuncNoParams(t *testing.T) {
	dir := t.TempDir()
	src := `package main

// Exported but no parameters — no control coupling
func ExportedNoParams() error {
	return nil
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	rule := coupling.NewControlCouplingRule()
	findings, err := rule.Run(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range findings {
		if f.RuleID == "COUP002" {
			t.Errorf("COUP002: unexpected finding for no-param function: %v", f)
		}
	}
}

// TestRuleDescriptions exercises ID/Description methods.
func TestRuleDescriptions(t *testing.T) {
	for _, r := range []engine.Rule{
		coupling.NewDataCouplingRule(),
		coupling.NewControlCouplingRule(),
	} {
		if r.ID() == "" {
			t.Error("rule ID is empty")
		}
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
