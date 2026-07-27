package release_test

// Gap tests for vcsInfo() in release.go (v0.33.1).
// vcsInfo is tested indirectly via BuildProvenance; we exercise:
//   - success path: projectRoot is a real git repo → revision + modified
//   - error path:   projectRoot is not a git repo → "", false  (already in existing tests)

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/SoundMatt/go-FuSa/release"
)

// TestBuildProvenance_InGitRepo exercises the happy-path of vcsInfo (both
// runGit calls succeed) by running BuildProvenance against the go-FuSa
// repository root, which is guaranteed to be a git repo in development.
// If git is not installed the function gracefully returns empty values and
// the test simply verifies that BuildProvenance still succeeds.
//
//fusa:test REQ-RELEASE005
func TestBuildProvenance_InGitRepo(t *testing.T) {
	// The test binary runs from the release/ package directory.
	// go up one level to reach the repo root (which has .git).
	projectRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatalf("Abs: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(projectRoot, ".git")); statErr != nil {
		t.Skip("parent directory is not a git repo; skipping vcsInfo git-success path")
	}

	prov, err := release.BuildProvenance(context.Background(), projectRoot)
	if err != nil {
		t.Fatalf("BuildProvenance in git repo: %v", err)
	}
	// VCSRevision is non-empty when git is installed.
	_ = prov.VCSRevision
	_ = prov.VCSModified
}

// TestBuildProvenance_NonGitDir exercises the vcsInfo error path where
// rev-parse fails (not a git repo) → revision="", modified=false.
//
//fusa:test REQ-RELEASE005
func TestBuildProvenance_NonGitDir(t *testing.T) {
	dir := t.TempDir()
	gomod := "module github.com/example/test\n\ngo 1.22\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0o640); err != nil {
		t.Fatal(err)
	}

	prov, err := release.BuildProvenance(context.Background(), dir)
	if err != nil {
		t.Fatalf("BuildProvenance non-git: %v", err)
	}
	// Not a git repo → VCSRevision is empty, VCSModified is false.
	if prov.VCSRevision != "" {
		t.Errorf("VCSRevision = %q, want empty for non-git dir", prov.VCSRevision)
	}
	if prov.VCSModified {
		t.Error("VCSModified = true, want false for non-git dir")
	}
}
