package fmea_test

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/config"
	"github.com/SoundMatt/go-FuSa/engine"
	"github.com/SoundMatt/go-FuSa/fmea"
	"github.com/SoundMatt/go-FuSa/testutil"
)

// ─── fixtures ─────────────────────────────────────────────────────────────────

const srcExported = `package mypkg

import "errors"

// DoWork does some work.
//
//fusa:req REQ-TEST001
func DoWork() error {
	return errors.New("fail")
}

// RunLoop starts a background loop.
func RunLoop() {
	go func() {}()
}

// helper is unexported and must be skipped.
func helper() {}
`

const srcNoExports = `package empty
`

const srcSyntaxError = `package bad {{{
`

// ─── Scan ─────────────────────────────────────────────────────────────────────

//fusa:test REQ-FMEA001
func TestScan_DiscoversFunctions(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.GoSource("mypkg/work.go", srcExported))
	r, err := fmea.Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	found := false
	for _, e := range r.Entries {
		if e.Function == "DoWork" {
			found = true
		}
	}
	if !found {
		t.Error("expected DoWork in entries")
	}
}

//fusa:test REQ-FMEA003
func TestScan_ExtractsRequirementIDs(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.GoSource("mypkg/work.go", srcExported))
	r, err := fmea.Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for _, e := range r.Entries {
		if e.Function == "DoWork" {
			if len(e.RequirementIDs) == 0 || e.RequirementIDs[0] != "REQ-TEST001" {
				t.Errorf("DoWork: RequirementIDs = %v, want [REQ-TEST001]", e.RequirementIDs)
			}
			return
		}
	}
	t.Error("DoWork not found")
}

//fusa:test REQ-FMEA002
func TestScan_FailureModes_ErrorReturn(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.GoSource("mypkg/work.go", srcExported))
	r, err := fmea.Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for _, e := range r.Entries {
		if e.Function == "DoWork" {
			foundMode := false
			for _, m := range e.FailureModes {
				if strings.Contains(m, "error") {
					foundMode = true
				}
			}
			if !foundMode {
				t.Errorf("DoWork: expected error failure mode, got %v", e.FailureModes)
			}
			return
		}
	}
	t.Error("DoWork not found")
}

func TestScan_FailureModes_Goroutine(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.GoSource("mypkg/work.go", srcExported))
	r, err := fmea.Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for _, e := range r.Entries {
		if e.Function == "RunLoop" {
			found := false
			for _, m := range e.FailureModes {
				if strings.Contains(strings.ToLower(m), "goroutine") {
					found = true
				}
			}
			if !found {
				t.Errorf("RunLoop: expected goroutine failure mode, got %v", e.FailureModes)
			}
			return
		}
	}
	t.Error("RunLoop not found")
}

func TestScan_SkipsUnexported(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.GoSource("mypkg/work.go", srcExported))
	r, err := fmea.Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for _, e := range r.Entries {
		if e.Function == "helper" {
			t.Error("unexported function 'helper' should not appear in entries")
		}
	}
}

func TestScan_SkipsTestFiles(t *testing.T) {
	files := testutil.GoSource("mypkg/work.go", srcExported)
	files["mypkg/work_test.go"] = `package mypkg_test

func TestExportedFromTestFile() {}
`
	dir := testutil.ProjectDir(t, files)
	r, err := fmea.Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for _, e := range r.Entries {
		if e.Function == "TestExportedFromTestFile" {
			t.Error("functions from _test.go should be skipped")
		}
	}
}

func TestScan_EmptyProject(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	r, err := fmea.Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if r.Module == "" {
		t.Error("Module should be set from go.mod")
	}
}

func TestScan_NoExports(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.GoSource("empty/empty.go", srcNoExports))
	r, err := fmea.Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for _, e := range r.Entries {
		if e.Component == "empty" {
			t.Error("empty package should produce no entries")
		}
	}
}

func TestScan_SkipsSyntaxError(t *testing.T) {
	files := testutil.GoSource("mypkg/work.go", srcExported)
	files["bad/bad.go"] = srcSyntaxError
	dir := testutil.ProjectDir(t, files)
	_, err := fmea.Scan(dir) // must not fail
	if err != nil {
		t.Fatalf("Scan: unexpected error for unparseable file: %v", err)
	}
}

func TestScan_SeverityHigh_WithReq(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.GoSource("mypkg/work.go", srcExported))
	r, err := fmea.Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for _, e := range r.Entries {
		if e.Function == "DoWork" {
			if e.Severity != fmea.SeverityHigh {
				t.Errorf("DoWork: Severity = %q, want high (has //fusa:req)", e.Severity)
			}
			return
		}
	}
	t.Error("DoWork not found")
}

func TestScan_DetectionControl_WithTests(t *testing.T) {
	files := testutil.GoSource("mypkg/work.go", srcExported)
	files["mypkg/work_test.go"] = `package mypkg_test

import "testing"

func TestDoWork(t *testing.T) {}
`
	dir := testutil.ProjectDir(t, files)
	r, err := fmea.Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for _, e := range r.Entries {
		if e.Function == "DoWork" {
			if !strings.Contains(e.DetectionControl, "test") {
				t.Errorf("DoWork: DetectionControl = %q, expected 'test'", e.DetectionControl)
			}
			return
		}
	}
	t.Error("DoWork not found")
}

func TestScan_SkipsVendor(t *testing.T) {
	files := testutil.MinimalProject()
	files["vendor/extpkg/ext.go"] = `package extpkg

func VendorFunc() {}
`
	dir := testutil.ProjectDir(t, files)
	r, err := fmea.Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for _, e := range r.Entries {
		if e.Component == "extpkg" {
			t.Error("vendor directory should be skipped")
		}
	}
}

func TestScan_WriteName(t *testing.T) {
	src := `package storage

func WriteData(data []byte) error { return nil }
`
	dir := testutil.ProjectDir(t, testutil.GoSource("storage/storage.go", src))
	r, err := fmea.Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for _, e := range r.Entries {
		if e.Function == "WriteData" {
			found := false
			for _, m := range e.FailureModes {
				if strings.Contains(strings.ToLower(m), "write") || strings.Contains(strings.ToLower(m), "corruption") {
					found = true
				}
			}
			if !found {
				t.Errorf("WriteData: expected write/corruption failure mode, got %v", e.FailureModes)
			}
			return
		}
	}
	t.Error("WriteData not found")
}

// ─── Render ───────────────────────────────────────────────────────────────────

//fusa:test REQ-FMEA004
func TestRender_JSON(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.GoSource("mypkg/work.go", srcExported))
	r, err := fmea.Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	var buf bytes.Buffer
	if err := fmea.Render(&buf, r, "json"); err != nil {
		t.Fatalf("Render json: %v", err)
	}
	var parsed fmea.Report
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("Render json: invalid JSON: %v", err)
	}
	if parsed.Format == "" {
		t.Error("Render json: expected Format field")
	}
}

func TestRender_JSONDefault(t *testing.T) {
	r := &fmea.Report{Format: "go-FuSa dFMEA v1"}
	var buf bytes.Buffer
	if err := fmea.Render(&buf, r, ""); err != nil {
		t.Fatalf("Render default: %v", err)
	}
	if !strings.Contains(buf.String(), `"format"`) {
		t.Error("Render default: expected JSON output")
	}
}

//fusa:test REQ-FMEA004
func TestRender_CSV(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.GoSource("mypkg/work.go", srcExported))
	r, scanErr := fmea.Scan(dir)
	if scanErr != nil {
		t.Fatalf("Scan: %v", scanErr)
	}
	var buf bytes.Buffer
	if renderErr := fmea.Render(&buf, r, "csv"); renderErr != nil {
		t.Fatalf("Render csv: %v", renderErr)
	}
	rows, csvErr := csv.NewReader(&buf).ReadAll()
	if csvErr != nil {
		t.Fatalf("Render csv: invalid CSV: %v", csvErr)
	}
	if len(rows) < 2 {
		t.Errorf("Render csv: expected header + data rows, got %d rows", len(rows))
	}
	if rows[0][0] != "Component" {
		t.Errorf("Render csv: expected header Component, got %q", rows[0][0])
	}
}

func TestRender_UnknownFormat(t *testing.T) {
	r := &fmea.Report{}
	var buf bytes.Buffer
	if err := fmea.Render(&buf, r, "xml"); err == nil {
		t.Error("Render: expected error for unknown format")
	}
}

// ─── engine rule ─────────────────────────────────────────────────────────────

func runEngine(t *testing.T, files map[string]string) []fusa.Finding {
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

//fusa:test REQ-FMEA005
func TestFMEA001_Absent(t *testing.T) {
	findings := runEngine(t, testutil.MinimalProject())
	if !hasRule(findings, "FMEA001") {
		t.Error("FMEA001: expected INFO finding when fmea.json absent")
	}
}

func TestFMEA001_Present(t *testing.T) {
	files := testutil.MinimalProject()
	files[fmea.FMEAFile] = `{"format":"go-FuSa dFMEA v1","entries":[]}`
	findings := runEngine(t, files)
	if hasRule(findings, "FMEA001") {
		t.Error("FMEA001: unexpected finding when fmea.json present")
	}
}

func TestFMEA001_Description(t *testing.T) {
	for _, r := range engine.Default.Rules() {
		if r.ID() == "FMEA001" {
			if r.Description() == "" {
				t.Error("FMEA001: empty description")
			}
			return
		}
	}
	t.Error("FMEA001 not registered")
}

func TestScan_RunName(t *testing.T) {
	src := `package svc

func RunService() {}
`
	dir := testutil.ProjectDir(t, testutil.GoSource("svc/svc.go", src))
	r, err := fmea.Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for _, e := range r.Entries {
		if e.Function == "RunService" {
			found := false
			for _, m := range e.FailureModes {
				if strings.Contains(strings.ToLower(m), "execution") || strings.Contains(strings.ToLower(m), "output") {
					found = true
				}
			}
			if !found {
				t.Errorf("RunService: unexpected failure modes: %v", e.FailureModes)
			}
			return
		}
	}
	t.Error("RunService not found")
}

func TestScan_MainPkg(t *testing.T) {
	src := `package main

func MainFunc() {}
`
	dir := testutil.ProjectDir(t, testutil.GoSource("cmd/main.go", src))
	r, err := fmea.Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for _, e := range r.Entries {
		if e.Function == "MainFunc" {
			if e.Component != "main" {
				t.Errorf("main package: Component = %q, want 'main'", e.Component)
			}
			return
		}
	}
	t.Error("MainFunc not found")
}

func TestScan_NonErrorReturn(t *testing.T) {
	src := `package mypkg

func GetValue() int { return 42 }
`
	dir := testutil.ProjectDir(t, testutil.GoSource("mypkg/get.go", src))
	r, err := fmea.Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for _, e := range r.Entries {
		if e.Function == "GetValue" {
			if e.Severity != fmea.SeverityLow {
				t.Errorf("GetValue: Severity = %q, want low", e.Severity)
			}
			return
		}
	}
	t.Error("GetValue not found")
}

// ─── EnrichWithCyber ──────────────────────────────────────────────────────────

//fusa:test REQ-FMEA006
func TestEnrichWithCyber_Basic(t *testing.T) {
	src := `package mypkg

func Process() error { return nil }
`
	dir := testutil.ProjectDir(t, testutil.GoSource("mypkg/proc.go", src))
	report, err := fmea.Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	// Set a File path on one entry to enable cross-referencing.
	for i := range report.Entries {
		if report.Entries[i].Function == "Process" {
			report.Entries[i].File = "mypkg/proc.go"
		}
	}

	cyberFindings := []fusa.Finding{
		{
			RuleID:   "CYBER006",
			Severity: fusa.SeverityError,
			Message:  "hardcoded credential",
			Location: fusa.Location{File: "mypkg/proc.go", Line: 3},
		},
		{
			RuleID:   "CYBER003",
			Severity: fusa.SeverityWarning,
			Message:  "insecure random",
			Location: fusa.Location{File: "other/file.go", Line: 10},
		},
	}
	fmea.EnrichWithCyber(report, cyberFindings)

	for _, e := range report.Entries {
		if e.Function == "Process" {
			if len(e.CyberRisks) == 0 {
				t.Error("EnrichWithCyber: expected CyberRisks for Process")
			}
			if e.Severity != fmea.SeverityHigh {
				t.Errorf("EnrichWithCyber: Severity = %q, want high (ERROR finding)", e.Severity)
			}
			return
		}
	}
	t.Log("Process function not found — skipping (no exported func in scan)")
}

func TestEnrichWithCyber_NoFindings(t *testing.T) {
	src := `package mypkg
func Noop() {}
`
	dir := testutil.ProjectDir(t, testutil.GoSource("mypkg/noop.go", src))
	report, err := fmea.Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	before := len(report.Entries)
	fmea.EnrichWithCyber(report, nil)
	if len(report.Entries) != before {
		t.Error("EnrichWithCyber with nil findings should not change entry count")
	}
}

// ─── Fuzz ─────────────────────────────────────────────────────────────────────

func FuzzScan(f *testing.F) {
	f.Add("package mypkg\nfunc ExportedFunc() error { return nil }\n")
	f.Add("package bad {{{\n")
	f.Add("")
	f.Fuzz(func(t *testing.T, src string) {
		dir := t.TempDir()
		_ = os.WriteFile(filepath.Join(dir, "f.go"), []byte(src), 0o644)
		_, _ = fmea.Scan(dir) // must not panic
	})
}
