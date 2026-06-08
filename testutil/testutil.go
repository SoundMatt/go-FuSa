// Package testutil provides helpers for go-FuSa unit tests.
package testutil

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/SoundMatt/go-FuSa/config"
)

// ProjectDir creates files under t.TempDir() and returns the directory path.
// files maps relative path → content.
func ProjectDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatalf("testutil: mkdir %s: %v", filepath.Dir(path), err)
		}
		if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
			t.Fatalf("testutil: write %s: %v", path, err)
		}
	}
	return dir
}

// MinimalProject returns a file map that satisfies all built-in FUSA rules.
func MinimalProject() map[string]string {
	cfg := `{
  "version": "1",
  "project": {
    "name": "test-project",
    "module": "github.com/example/test",
    "standard": "generic"
  },
  "rules": {},
  "report": {
    "format": "text"
  }
}
`
	return map[string]string{
		config.ConfigFile:          cfg,
		"go.mod":                   "module github.com/example/test\n\ngo 1.22\n",
		"LICENSE":                  "Mozilla Public License 2.0\n",
		"README.md":                "# Test Project\n",
		".github/workflows/ci.yml": "name: CI\non:\n  push:\n    branches: [main]\n",
	}
}

// GoSource returns a map with a single Go source file at the given path.
func GoSource(relPath, content string) map[string]string {
	files := MinimalProject()
	files[relPath] = content
	return files
}
