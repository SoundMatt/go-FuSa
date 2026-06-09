// Package vuln — internal tests for private helpers.
// These run inside `package vuln` to access unexported functions directly.
package vuln

import (
	"os"
	"path/filepath"
	"testing"
)

// ─── countModDeps ─────────────────────────────────────────────────────────────

// TestCountModDeps_WithRequires verifies that require lines are counted.
func TestCountModDeps_WithRequires(t *testing.T) {
	dir := t.TempDir()
	gomod := `module github.com/example/test

go 1.22

require (
	github.com/foo/bar v1.2.3
	github.com/baz/qux v0.9.0
)

require github.com/single/dep v0.1.0
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0o640); err != nil {
		t.Fatal(err)
	}
	n := countModDeps(dir)
	if n == 0 {
		t.Error("countModDeps: expected >0 for go.mod with require lines")
	}
}

// TestCountModDeps_MissingGoMod verifies that a missing go.mod returns 0.
func TestCountModDeps_MissingGoMod(t *testing.T) {
	dir := t.TempDir() // no go.mod written
	n := countModDeps(dir)
	if n != 0 {
		t.Errorf("countModDeps: expected 0 for missing go.mod, got %d", n)
	}
}

// TestCountModDeps_NoDeps verifies that a go.mod with no require lines returns 0.
func TestCountModDeps_NoDeps(t *testing.T) {
	dir := t.TempDir()
	gomod := "module github.com/example/test\n\ngo 1.22\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0o640); err != nil {
		t.Fatal(err)
	}
	n := countModDeps(dir)
	if n != 0 {
		t.Errorf("countModDeps: expected 0 for no-dep go.mod, got %d", n)
	}
}

// ─── moduleFromRoot ───────────────────────────────────────────────────────────

// TestModuleFromRoot_Valid verifies that the module path is extracted from go.mod.
func TestModuleFromRoot_Valid(t *testing.T) {
	dir := t.TempDir()
	gomod := "module github.com/example/myproject\n\ngo 1.22\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0o640); err != nil {
		t.Fatal(err)
	}
	got := moduleFromRoot(dir)
	if got != "github.com/example/myproject" {
		t.Errorf("moduleFromRoot: expected 'github.com/example/myproject', got %q", got)
	}
}

// TestModuleFromRoot_MissingGoMod verifies that a missing go.mod returns the root path.
func TestModuleFromRoot_MissingGoMod(t *testing.T) {
	dir := t.TempDir() // no go.mod written
	got := moduleFromRoot(dir)
	if got != dir {
		t.Errorf("moduleFromRoot: expected root path %q, got %q", dir, got)
	}
}

// TestModuleFromRoot_NoModuleLine verifies fallback when go.mod has no module directive.
func TestModuleFromRoot_NoModuleLine(t *testing.T) {
	dir := t.TempDir()
	gomod := "go 1.22\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0o640); err != nil {
		t.Fatal(err)
	}
	got := moduleFromRoot(dir)
	// No "module …" line → returns the root directory.
	if got != dir {
		t.Errorf("moduleFromRoot: expected root %q when no module line, got %q", dir, got)
	}
}

// ─── runGovulncheck ───────────────────────────────────────────────────────────
//
// runGovulncheck is intentionally not unit-tested here because it shells out to
// an external binary (`govulncheck`) that is not guaranteed to be installed in
// all environments. Its integration is exercised indirectly by
// TestScanWithGovulncheck_FallbackNoDeps in vuln_test.go, which calls
// ScanWithGovulncheck and verifies that it falls back gracefully when the binary
// is absent, or runs successfully when it is present. A full call-graph test
// would require a controlled vulnerable module, which is out of scope for unit tests.
