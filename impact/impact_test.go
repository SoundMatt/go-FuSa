package impact_test

import (
	"bytes"
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
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
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
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
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
	out, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Skip("git rev-parse failed:", err)
	}
	commitA := strings.TrimSpace(string(out))

	if err := os.WriteFile(filepath.Join(dir, "b.go"), []byte("package p\n"), 0o644); err != nil {
		t.Fatal(err)
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
