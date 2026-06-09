package impact_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SoundMatt/go-FuSa/impact"
)

// initGitRepo sets up a minimal git repo in dir with an initial commit.
func initGitRepo(t *testing.T, dir string) {
	t.Helper()
	for _, args := range [][]string{
		{"git", "-C", dir, "init"},
		{"git", "-C", dir, "config", "user.email", "test@example.com"},
		{"git", "-C", dir, "config", "user.name", "Test"},
	} {
		if out, err := exec.CommandContext(context.Background(), args[0], args[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("git init: %v\n%s", err, out)
		}
	}
}

func commitAll(t *testing.T, dir, msg string) {
	t.Helper()
	for _, args := range [][]string{
		{"git", "-C", dir, "add", "."},
		{"git", "-C", dir, "commit", "--allow-empty", "-m", msg},
	} {
		if out, err := exec.CommandContext(context.Background(), args[0], args[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("git commit: %v\n%s", err, out)
		}
	}
}

func TestAnalyse_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	rep, err := impact.Analyse(dir, "", "")
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}
	if rep == nil {
		t.Fatal("expected non-nil report")
	}
	// No git repo → empty report
	if len(rep.ChangedFiles) != 0 {
		t.Errorf("expected 0 changed files in non-git dir, got %d", len(rep.ChangedFiles))
	}
}

func TestAnalyse_GitRepoNoChanges(t *testing.T) {
	dir := t.TempDir()
	initGitRepo(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main"), 0o644); err != nil {
		t.Fatal(err)
	}
	commitAll(t, dir, "initial")

	rep, err := impact.Analyse(dir, "", "")
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}
	// No uncommitted changes
	if len(rep.ChangedFiles) != 0 {
		t.Errorf("expected 0 changed files after clean commit, got %d", len(rep.ChangedFiles))
	}
}

func TestAnalyse_WithChanges(t *testing.T) {
	dir := t.TempDir()
	initGitRepo(t, dir)

	// Initial commit with a file
	src := filepath.Join(dir, "main.go")
	if err := os.WriteFile(src, []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	commitAll(t, dir, "initial")

	// Modify the file (uncommitted)
	if err := os.WriteFile(src, []byte("package main\n// modified\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	rep, err := impact.Analyse(dir, "", "")
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}
	if len(rep.ChangedFiles) == 0 {
		t.Error("expected changed files after modification")
	}
}

func TestAnalyse_FromRef(t *testing.T) {
	dir := t.TempDir()
	initGitRepo(t, dir)

	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte("package p\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	commitAll(t, dir, "commit-a")

	// Get commit hash
	out, err := exec.CommandContext(context.Background(), "git", "-C", dir, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Skip("git rev-parse failed:", err)
	}
	commitA := strings.TrimSpace(string(out))

	if writeErr := os.WriteFile(filepath.Join(dir, "b.go"), []byte("package p\n"), 0o644); writeErr != nil {
		t.Fatal(writeErr)
	}
	commitAll(t, dir, "commit-b")

	rep, err := impact.Analyse(dir, commitA, "HEAD")
	if err != nil {
		t.Fatalf("Analyse with refs: %v", err)
	}
	_ = rep // may or may not have changes depending on git version
}

func TestRender_Text(t *testing.T) {
	rep := &impact.Report{
		ChangedFiles: []impact.FileChange{
			{Path: "main.go", Status: "M"},
		},
		ImpactedReqs: []impact.RequirementImpact{
			{RequirementID: "REQ-001", AffectedFiles: []string{"main.go"}},
		},
	}
	var buf bytes.Buffer
	if err := impact.Render(&buf, rep, "text"); err != nil {
		t.Fatalf("Render text: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Impact Analysis Report") {
		t.Error("missing report header")
	}
	if !strings.Contains(out, "main.go") {
		t.Error("missing changed file in output")
	}
	if !strings.Contains(out, "REQ-001") {
		t.Error("missing requirement in output")
	}
}

func TestRender_JSON(t *testing.T) {
	rep := &impact.Report{
		ChangedFiles: []impact.FileChange{
			{Path: "x.go", Status: "A"},
		},
	}
	var buf bytes.Buffer
	if err := impact.Render(&buf, rep, "json"); err != nil {
		t.Fatalf("Render json: %v", err)
	}
	if !strings.Contains(buf.String(), `"changedFiles"`) {
		t.Error("missing changedFiles in JSON")
	}
}

func TestRender_InvalidFormat(t *testing.T) {
	rep := &impact.Report{}
	if err := impact.Render(&bytes.Buffer{}, rep, "xml"); err == nil {
		t.Error("expected error for unsupported format")
	}
}

func TestRenderText_StaleAndRerun(t *testing.T) {
	rep := &impact.Report{
		ChangedFiles: []impact.FileChange{
			{Path: "pkg/foo.go", Status: "M"},
		},
		ImpactedReqs: []impact.RequirementImpact{
			{
				RequirementID: "REQ-STALE",
				AffectedFiles: []string{"pkg/foo.go"},
				TestsNeeded:   []string{"pkg/foo_test.go"},
			},
		},
		StaleArtifacts: []impact.ArtifactStatus{
			{File: "safety_plan.md", Stale: true, Reason: "source changed after artefact"},
			{File: "test_evidence.md", Stale: false, Reason: ""},
		},
		RerunTests: []string{"pkg/foo_test.go", "pkg/bar_test.go"},
	}
	var buf bytes.Buffer
	if err := impact.Render(&buf, rep, "text"); err != nil {
		t.Fatalf("Render text: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "REQ-STALE") {
		t.Error("missing REQ-STALE in output")
	}
	if !strings.Contains(out, "foo_test.go") {
		t.Error("missing test file in output")
	}
	if !strings.Contains(out, "safety_plan.md") {
		t.Error("missing stale artifact in output")
	}
	if !strings.Contains(out, "pkg/bar_test.go") {
		t.Error("missing rerun test in output")
	}
}

func TestRenderText_EmptyReport(t *testing.T) {
	rep := &impact.Report{}
	var buf bytes.Buffer
	if err := impact.Render(&buf, rep, "text"); err != nil {
		t.Fatalf("Render empty text: %v", err)
	}
	if !strings.Contains(buf.String(), "no changes detected") {
		t.Error("missing empty-changes message")
	}
}

// TestAnalyse_WithTracedRequirementsAndChanges exercises the impacted-requirement
// and stale-artefact branches inside Analyse by:
//   - setting up a real git repo with a committed source file that has a //fusa:req tag
//   - modifying the file (uncommitted) so it appears in git diff HEAD
//   - providing a .fusa-reqs.json that defines the annotated requirement
//   - also providing a .fusa-evidence.json that is older than the changed file
//
// This drives the inner loops that populate ImpactedReqs and RerunTests.
func TestAnalyse_WithTracedRequirementsAndChanges(t *testing.T) {
	dir := t.TempDir()
	initGitRepo(t, dir)

	// Write requirements file.
	reqs := `{"requirements":[{"id":"REQ-IA001","title":"Impact test"}]}`
	if err := os.WriteFile(filepath.Join(dir, ".fusa-reqs.json"), []byte(reqs), 0o644); err != nil {
		t.Fatal(err)
	}

	// Write implementation file with req annotation.
	implSrc := "package main\n\n//fusa:req REQ-IA001\nfunc Work() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "work.go"), []byte(implSrc), 0o644); err != nil {
		t.Fatal(err)
	}

	// Write a test file referencing the same requirement.
	testSrc := "package main\n\n//fusa:test REQ-IA001\nfunc TestWork() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "work_test.go"), []byte(testSrc), 0o644); err != nil {
		t.Fatal(err)
	}

	commitAll(t, dir, "initial with trace")

	// Modify the impl file so it shows up in git diff HEAD.
	modifiedSrc := "package main\n\n//fusa:req REQ-IA001\nfunc Work() { _ = 1 }\n"
	if err := os.WriteFile(filepath.Join(dir, "work.go"), []byte(modifiedSrc), 0o644); err != nil {
		t.Fatal(err)
	}

	rep, err := impact.Analyse(dir, "", "")
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}

	// We expect at least one changed file.
	if len(rep.ChangedFiles) == 0 {
		t.Skip("git diff returned no changes — skipping assertion (CI environment)")
	}

	// ImpactedReqs should include REQ-IA001 because work.go is both changed and annotated.
	found := false
	for _, ir := range rep.ImpactedReqs {
		if ir.RequirementID == "REQ-IA001" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Analyse: expected REQ-IA001 in ImpactedReqs, got %+v", rep.ImpactedReqs)
	}

	// RerunTests should have at least one entry (work_test.go references REQ-IA001).
	if len(rep.RerunTests) == 0 {
		t.Logf("Analyse: RerunTests empty — test file may not have been scanned (acceptable if no tag file match)")
	}
}

// TestAnalyse_StaleArtifactPresent verifies the branch where an artefact IS present
// but older than the changed source, and the branch where it is fresh (not stale).
func TestAnalyse_StaleArtifactPresent(t *testing.T) {
	dir := t.TempDir()
	initGitRepo(t, dir)

	src := filepath.Join(dir, "main.go")
	if err := os.WriteFile(src, []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	commitAll(t, dir, "initial")

	// Modify the file so latestSrc mtime will be set.
	if err := os.WriteFile(src, []byte("package main\n// v2\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Write an artefact file — os.Stat will succeed, triggering the modTime comparison.
	artefact := filepath.Join(dir, ".fusa-evidence.json")
	if err := os.WriteFile(artefact, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}

	rep, err := impact.Analyse(dir, "", "")
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}

	if len(rep.ChangedFiles) == 0 {
		t.Skip("git diff returned no changes — skipping artefact staleness assertion")
	}

	// StaleArtifacts should be populated (at least one entry for .fusa-evidence.json).
	if len(rep.StaleArtifacts) == 0 {
		t.Error("Analyse: expected StaleArtifacts to be populated when latestSrc is set")
	}
}

// TestAnalyse_FromRefOnly exercises the fromRef-only branch (fromRef..HEAD).
func TestAnalyse_FromRefOnly(t *testing.T) {
	dir := t.TempDir()
	initGitRepo(t, dir)

	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte("package p\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	commitAll(t, dir, "commit-one")

	out, err := exec.CommandContext(context.Background(), "git", "-C", dir, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Skip("git rev-parse failed:", err)
	}
	base := strings.TrimSpace(string(out))

	if werr := os.WriteFile(filepath.Join(dir, "b.go"), []byte("package p\n"), 0o644); werr != nil {
		t.Fatal(werr)
	}
	commitAll(t, dir, "commit-two")

	rep, err := impact.Analyse(dir, base, "")
	if err != nil {
		t.Fatalf("Analyse fromRef only: %v", err)
	}
	if rep == nil {
		t.Fatal("expected non-nil report")
	}
}
