package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/trace"
)

// ─── runTraceHLRLLR (P0: REQ-TRACE008) ───────────────────────────────────────

// buildHLRLLRMatrix constructs a trace.Matrix for a project directory.
func buildHLRLLRMatrix(t *testing.T, dir string) *trace.Matrix {
	t.Helper()
	m, err := trace.Build(dir)
	if err != nil {
		t.Fatalf("trace.Build: %v", err)
	}
	return m
}

//fusa:test REQ-TRACE008
func TestRunTraceHLRLLR_NoViolations_ExitOK(t *testing.T) {
	// A well-formed HLR/LLR project: one HLR with one valid LLR child.
	dir := t.TempDir()
	reqs := []trace.Requirement{
		{ID: "REQ-HLR-001", Title: "High-level requirement", Level: "HLR"},
		{ID: "REQ-LLR-001", Title: "Low-level requirement", Level: "LLR", ParentID: "REQ-HLR-001"},
	}
	if err := trace.SaveRequirements(dir, reqs); err != nil {
		t.Fatalf("SaveRequirements: %v", err)
	}
	m := buildHLRLLRMatrix(t, dir)

	var out, errOut bytes.Buffer
	code := runTraceHLRLLR(m, &out, &errOut)
	if code != fusa.ExitOK {
		t.Errorf("expected ExitOK (%d), got %d\nstdout: %s\nstderr: %s",
			fusa.ExitOK, code, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "HLR/LLR Decomposition") {
		t.Errorf("stdout should contain decomposition header; got: %s", out.String())
	}
}

//fusa:test REQ-TRACE008
func TestRunTraceHLRLLR_OrphanedLLR_ExitGateFail(t *testing.T) {
	// LLR with a parentId that does not match any HLR → orphaned.
	dir := t.TempDir()
	reqs := []trace.Requirement{
		{ID: "REQ-HLR-001", Title: "High-level requirement", Level: "HLR"},
		{ID: "REQ-LLR-001", Title: "Low-level requirement", Level: "LLR", ParentID: "REQ-HLR-MISSING"},
	}
	if err := trace.SaveRequirements(dir, reqs); err != nil {
		t.Fatalf("SaveRequirements: %v", err)
	}
	m := buildHLRLLRMatrix(t, dir)

	var out, errOut bytes.Buffer
	code := runTraceHLRLLR(m, &out, &errOut)
	if code != fusa.ExitGateFail {
		t.Errorf("expected ExitGateFail (%d), got %d\nstdout: %s\nstderr: %s",
			fusa.ExitGateFail, code, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "ORPHANED LLR") {
		t.Errorf("stdout should mention orphaned LLR; got: %s", out.String())
	}
}

//fusa:test REQ-TRACE008
func TestRunTraceHLRLLR_UncoveredHLR_ExitGateFail(t *testing.T) {
	// HLR with no LLR children → uncovered.
	dir := t.TempDir()
	reqs := []trace.Requirement{
		{ID: "REQ-HLR-001", Title: "High-level requirement, no children", Level: "HLR"},
	}
	if err := trace.SaveRequirements(dir, reqs); err != nil {
		t.Fatalf("SaveRequirements: %v", err)
	}
	m := buildHLRLLRMatrix(t, dir)

	var out, errOut bytes.Buffer
	code := runTraceHLRLLR(m, &out, &errOut)
	if code != fusa.ExitGateFail {
		t.Errorf("expected ExitGateFail (%d), got %d\nstdout: %s\nstderr: %s",
			fusa.ExitGateFail, code, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "UNCOVERED HLR") {
		t.Errorf("stdout should mention uncovered HLR; got: %s", out.String())
	}
}

//fusa:test REQ-TRACE008
func TestRunTraceHLRLLR_NoHierarchicalReqs_ExitOK(t *testing.T) {
	// No HLR/LLR levels → HLRLLRSummary is nil → exit OK.
	dir := t.TempDir()
	reqs := []trace.Requirement{
		{ID: "REQ-001", Title: "Flat requirement (no Level)"},
	}
	if err := trace.SaveRequirements(dir, reqs); err != nil {
		t.Fatalf("SaveRequirements: %v", err)
	}
	m := buildHLRLLRMatrix(t, dir)

	var out, errOut bytes.Buffer
	code := runTraceHLRLLR(m, &out, &errOut)
	if code != fusa.ExitOK {
		t.Errorf("expected ExitOK (%d) for flat reqs, got %d\nstdout: %s\nstderr: %s",
			fusa.ExitOK, code, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "no hierarchical requirements") {
		t.Errorf("stdout should note absence of hierarchical requirements; got: %s", out.String())
	}
}

//fusa:test REQ-TRACE008
func TestRun_Trace_StrictHLRLLR_GateFail(t *testing.T) {
	// CLI integration: --strict-hlr-llr flag with an uncovered HLR exits 1.
	dir := t.TempDir()
	reqs := []trace.Requirement{
		{ID: "REQ-HLR-001", Title: "Uncovered HLR", Level: "HLR"},
	}
	if err := trace.SaveRequirements(dir, reqs); err != nil {
		t.Fatalf("SaveRequirements: %v", err)
	}
	var out, errOut bytes.Buffer
	code := run([]string{"trace", "--dir", dir, "--strict-hlr-llr"}, &out, &errOut)
	if code != fusa.ExitGateFail {
		t.Errorf("trace --strict-hlr-llr with uncovered HLR: expected ExitGateFail (%d), got %d\nstdout: %s\nstderr: %s",
			fusa.ExitGateFail, code, out.String(), errOut.String())
	}
}

//fusa:test REQ-TRACE008
func TestRun_Trace_StrictHLRLLR_Pass(t *testing.T) {
	// CLI integration: --strict-hlr-llr flag with a fully covered HLR/LLR tree exits 0.
	dir := t.TempDir()
	reqs := []trace.Requirement{
		{ID: "REQ-HLR-001", Title: "Covered HLR", Level: "HLR"},
		{ID: "REQ-LLR-001", Title: "Valid LLR", Level: "LLR", ParentID: "REQ-HLR-001"},
	}
	if err := trace.SaveRequirements(dir, reqs); err != nil {
		t.Fatalf("SaveRequirements: %v", err)
	}
	var out, errOut bytes.Buffer
	code := run([]string{"trace", "--dir", dir, "--strict-hlr-llr"}, &out, &errOut)
	if code != fusa.ExitOK {
		t.Errorf("trace --strict-hlr-llr with valid tree: expected ExitOK (%d), got %d\nstdout: %s\nstderr: %s",
			fusa.ExitOK, code, out.String(), errOut.String())
	}
}

// ─── runCoverage --mcdc (P2: REQ-COV015) ─────────────────────────────────────

//fusa:test REQ-COV015
func TestRunCoverage_MCDC_MissingFile_ExitUsage(t *testing.T) {
	// --mcdc without --mcdc-file must fail with ExitUsage.
	dir := t.TempDir()
	// Write a minimal coverage profile so the main coverage path succeeds.
	profilePath := filepath.Join(dir, "coverage.out")
	profileContent := "mode: set\ngithub.com/example/foo/bar.go:1.30,2.2 1 1\n"
	if err := os.WriteFile(profilePath, []byte(profileContent), 0o640); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := runCoverage([]string{"--mcdc", profilePath}, &out, &errOut)
	if code != fusa.ExitUsage {
		t.Errorf("--mcdc without --mcdc-file: expected ExitUsage (%d), got %d\nstderr: %s",
			fusa.ExitUsage, code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "--mcdc-file") {
		t.Errorf("stderr should mention --mcdc-file; got: %s", errOut.String())
	}
}

//fusa:test REQ-COV015
func TestRunCoverage_MCDC_BelowThreshold_ExitGateFail(t *testing.T) {
	// --mcdc with a valid LLVM JSON file where coverage is below threshold → ExitGateFail.
	dir := t.TempDir()

	// Write a minimal Go coverage profile.
	profilePath := filepath.Join(dir, "coverage.out")
	profileContent := "mode: set\ngithub.com/example/foo/bar.go:1.30,2.2 1 1\n"
	if err := os.WriteFile(profilePath, []byte(profileContent), 0o640); err != nil {
		t.Fatal(err)
	}

	// Write a synthetic LLVM coverage JSON with one condition that has covered_true_count=0
	// (uncovered), so coverage is below the default 100% threshold.
	mcdcJSON := map[string]interface{}{
		"data": []map[string]interface{}{
			{
				"functions": []map[string]interface{}{
					{
						"name": "doThing",
						"mcdc_records": []map[string]interface{}{
							{
								"conditions": []map[string]interface{}{
									{
										"covered_true_count":  0,
										"covered_false_count": 1,
									},
								},
							},
						},
					},
				},
			},
		},
	}
	mcdcData, err := json.Marshal(mcdcJSON)
	if err != nil {
		t.Fatalf("marshal mcdc json: %v", err)
	}
	mcdcPath := filepath.Join(dir, "mcdc.json")
	if err := os.WriteFile(mcdcPath, mcdcData, 0o640); err != nil {
		t.Fatal(err)
	}

	var out, errOut bytes.Buffer
	code := runCoverage([]string{"--mcdc", "--mcdc-file", mcdcPath, "--mcdc-threshold", "100", profilePath}, &out, &errOut)
	if code != fusa.ExitGateFail {
		t.Errorf("--mcdc below threshold: expected ExitGateFail (%d), got %d\nstdout: %s\nstderr: %s",
			fusa.ExitGateFail, code, out.String(), errOut.String())
	}
}

//fusa:test REQ-COV015
func TestRunCoverage_MCDC_FullyCovered_ExitOK(t *testing.T) {
	// --mcdc with a valid LLVM JSON file where all conditions are covered → ExitOK.
	dir := t.TempDir()

	profilePath := filepath.Join(dir, "coverage.out")
	profileContent := "mode: set\ngithub.com/example/foo/bar.go:1.30,2.2 1 1\n"
	if err := os.WriteFile(profilePath, []byte(profileContent), 0o640); err != nil {
		t.Fatal(err)
	}

	// All conditions covered: covered_true_count>0 AND covered_false_count>0.
	mcdcJSON := map[string]interface{}{
		"data": []map[string]interface{}{
			{
				"functions": []map[string]interface{}{
					{
						"name": "doThing",
						"mcdc_records": []map[string]interface{}{
							{
								"conditions": []map[string]interface{}{
									{
										"covered_true_count":  2,
										"covered_false_count": 3,
									},
								},
							},
						},
					},
				},
			},
		},
	}
	mcdcData, err := json.Marshal(mcdcJSON)
	if err != nil {
		t.Fatalf("marshal mcdc json: %v", err)
	}
	mcdcPath := filepath.Join(dir, "mcdc.json")
	if err := os.WriteFile(mcdcPath, mcdcData, 0o640); err != nil {
		t.Fatal(err)
	}

	var out, errOut bytes.Buffer
	code := runCoverage([]string{"--mcdc", "--mcdc-file", mcdcPath, "--mcdc-threshold", "100", profilePath}, &out, &errOut)
	if code != fusa.ExitOK {
		t.Errorf("--mcdc fully covered: expected ExitOK (%d), got %d\nstdout: %s\nstderr: %s",
			fusa.ExitOK, code, out.String(), errOut.String())
	}
}

// ─── runQualify new flags (P2: REQ-QUALIFY007, REQ-QUALIFY008) ────────────────

//fusa:test REQ-QUALIFY007
//fusa:test REQ-QUALIFY008
func TestRunQualify_NewFlags_PopulateReport(t *testing.T) {
	// --qualification-method, --qualifier, --record-uri, --independent-reviewer,
	// --independent-test-executor, --achievable-asil should all appear in the
	// saved qualification report.
	outDir := t.TempDir()
	reportPath := filepath.Join(outDir, "qualify-report.json")

	var out, errOut bytes.Buffer
	code := runQualify([]string{
		"--output", reportPath,
		"--qualification-method", "independent",
		"--qualifier", "SafetyLabs Inc.",
		"--record-uri", "https://example.com/dossier",
		"--independent-reviewer", "Eve",
		"--independent-test-executor", "Frank",
		"--achievable-asil", "ASIL-D",
	}, &out, &errOut)
	if code != fusa.ExitOK {
		t.Fatalf("runQualify with flags: exit %d\nstdout: %s\nstderr: %s",
			code, out.String(), errOut.String())
	}

	data, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}

	type minReport struct {
		QualificationMethod     string `json:"qualificationMethod"`
		QualifierIdentity       string `json:"qualifierIdentity"`
		QualificationRecordUri  string `json:"qualificationRecordUri"`
		IndependentReviewer     string `json:"independentReviewer"`
		IndependentTestExecutor string `json:"independentTestExecutor"`
		AchievableASIL          string `json:"achievableAsil"`
	}
	var rep minReport
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	if rep.QualificationMethod != "independent" {
		t.Errorf("QualificationMethod = %q, want \"independent\"", rep.QualificationMethod)
	}
	if rep.QualifierIdentity != "SafetyLabs Inc." {
		t.Errorf("QualifierIdentity = %q, want \"SafetyLabs Inc.\"", rep.QualifierIdentity)
	}
	if rep.QualificationRecordUri != "https://example.com/dossier" {
		t.Errorf("QualificationRecordUri = %q, want \"https://example.com/dossier\"", rep.QualificationRecordUri)
	}
	if rep.IndependentReviewer != "Eve" {
		t.Errorf("IndependentReviewer = %q, want \"Eve\"", rep.IndependentReviewer)
	}
	if rep.IndependentTestExecutor != "Frank" {
		t.Errorf("IndependentTestExecutor = %q, want \"Frank\"", rep.IndependentTestExecutor)
	}
	if rep.AchievableASIL != "ASIL-D" {
		t.Errorf("AchievableASIL = %q, want \"ASIL-D\"", rep.AchievableASIL)
	}

	// Verify badge and independence status appear in stdout.
	outStr := out.String()
	if !strings.Contains(outStr, "independently-qualified") {
		t.Errorf("stdout should contain 'independently-qualified' badge; got: %s", outStr)
	}
	if !strings.Contains(outStr, "independent") {
		t.Errorf("stdout should contain independence status; got: %s", outStr)
	}
}

//fusa:test REQ-QUALIFY007
//fusa:test REQ-QUALIFY008
func TestRunQualify_NoFlags_DefaultsPopulateStdout(t *testing.T) {
	// Without new flags, badge should be "unqualified" and independence "unqualified".
	outDir := t.TempDir()
	reportPath := filepath.Join(outDir, "qualify-report.json")

	var out, errOut bytes.Buffer
	code := runQualify([]string{"--output", reportPath}, &out, &errOut)
	if code != fusa.ExitOK {
		t.Fatalf("runQualify no flags: exit %d\nstdout: %s\nstderr: %s",
			code, out.String(), errOut.String())
	}
	outStr := out.String()
	if !strings.Contains(outStr, "unqualified") {
		t.Errorf("stdout should show 'unqualified' badge when no flags set; got: %s", outStr)
	}
}
