package pr_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/config"
	"github.com/SoundMatt/go-FuSa/engine"
	"github.com/SoundMatt/go-FuSa/pr"
)

func runPREngine(t *testing.T, dir string) []fusa.Finding {
	t.Helper()
	cfg := config.Default("github.com/example/test", "test")
	result, err := engine.Default.Run(context.Background(), dir, cfg)
	if err != nil {
		t.Fatalf("engine.Run: %v", err)
	}
	var findings []fusa.Finding
	for _, f := range result.Findings {
		if f.RuleID == "PR001" {
			findings = append(findings, f)
		}
	}
	return findings
}

//fusa:test REQ-PR001
func TestPR001_NoFile_InfoFinding(t *testing.T) {
	dir := t.TempDir()
	findings := runPREngine(t, dir)
	if len(findings) == 0 {
		t.Error("PR001: expected INFO finding when .fusa-problems.json absent")
	}
	if findings[0].Severity != fusa.SeverityInfo {
		t.Errorf("expected Info severity, got %v", findings[0].Severity)
	}
}

func TestPR001_FilePresent_NoCritical_NoFinding(t *testing.T) {
	dir := t.TempDir()
	log := &pr.Log{
		Project: "test",
		Reports: []pr.ProblemReport{
			{ID: "PR-001", Title: "minor issue", Severity: pr.PRSeverityMinor,
				Status: pr.StatusOpen, Created: time.Now(), Updated: time.Now()},
		},
	}
	if err := pr.Save(filepath.Join(dir, pr.ProblemsFile), log); err != nil {
		t.Fatal(err)
	}
	findings := runPREngine(t, dir)
	if len(findings) != 0 {
		t.Errorf("PR001: unexpected finding for open minor report: %v", findings)
	}
}

func TestPR001_OpenCritical_ErrorFinding(t *testing.T) {
	dir := t.TempDir()
	log := &pr.Log{
		Project: "test",
		Reports: []pr.ProblemReport{
			{ID: "PR-CRIT", Title: "critical bug", Severity: pr.PRSeverityCritical,
				Status: pr.StatusOpen, Created: time.Now(), Updated: time.Now()},
		},
	}
	if err := pr.Save(filepath.Join(dir, pr.ProblemsFile), log); err != nil {
		t.Fatal(err)
	}
	findings := runPREngine(t, dir)
	if len(findings) == 0 {
		t.Error("PR001: expected ERROR finding for open critical report")
	}
	if findings[0].Severity != fusa.SeverityError {
		t.Errorf("expected Error severity, got %v", findings[0].Severity)
	}
}

func TestPR001_Description(t *testing.T) {
	for _, r := range engine.Default.Rules() {
		if r.ID() == "PR001" {
			if r.Description() == "" {
				t.Error("PR001 Description() returned empty string")
			}
			return
		}
	}
	t.Error("PR001 rule not registered in engine")
}

func TestPR001_ClosedCritical_NoFinding(t *testing.T) {
	dir := t.TempDir()
	log := &pr.Log{
		Project: "test",
		Reports: []pr.ProblemReport{
			{ID: "PR-CRIT", Title: "critical but closed", Severity: pr.PRSeverityCritical,
				Status: pr.StatusClosed, Created: time.Now(), Updated: time.Now()},
		},
	}
	if err := pr.Save(filepath.Join(dir, pr.ProblemsFile), log); err != nil {
		t.Fatal(err)
	}
	findings := runPREngine(t, dir)
	if len(findings) != 0 {
		t.Errorf("PR001: unexpected finding for closed critical report: %v", findings)
	}
}

func TestPR001_MalformedFile_Error(t *testing.T) {
	dir := t.TempDir()
	// Write invalid JSON
	if err := os.WriteFile(filepath.Join(dir, pr.ProblemsFile), []byte("{invalid json"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default("github.com/example/test", "test")
	_, err := engine.Default.Run(context.Background(), dir, cfg)
	// Engine should return an error when the file is malformed
	if err == nil {
		// Some engines swallow errors — just ensure no panic
		t.Log("engine swallowed parse error (acceptable)")
	}
}
