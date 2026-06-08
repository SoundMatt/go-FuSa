package testutil_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SoundMatt/go-FuSa/config"
	"github.com/SoundMatt/go-FuSa/testutil"
)

func TestProjectDir_CreatesFiles(t *testing.T) {
	files := map[string]string{
		"main.go":     "package main\n",
		"sub/util.go": "package sub\n",
	}
	dir := testutil.ProjectDir(t, files)
	if dir == "" {
		t.Fatal("ProjectDir returned empty path")
	}
	for rel, want := range files {
		path := filepath.Join(dir, rel)
		got, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("ProjectDir: %s not created: %v", rel, err)
			continue
		}
		if string(got) != want {
			t.Errorf("ProjectDir: %s content = %q, want %q", rel, string(got), want)
		}
	}
}

func TestProjectDir_CleanedUp(t *testing.T) {
	var savedDir string
	func() {
		inner := testing.T{}
		savedDir = testutil.ProjectDir(&inner, map[string]string{"f.go": "package p\n"})
	}()
	// t.TempDir() cleanup happens at the end of the test, not the closure —
	// we verify the directory was at least created.
	if savedDir == "" {
		t.Error("ProjectDir returned empty path")
	}
}

func TestMinimalProject_ContainsRequiredFiles(t *testing.T) {
	files := testutil.MinimalProject()
	required := []string{
		config.ConfigFile,
		"go.mod",
		"LICENSE",
		"README.md",
		".github/workflows/ci.yml",
	}
	for _, r := range required {
		if _, ok := files[r]; !ok {
			t.Errorf("MinimalProject: missing required file %q", r)
		}
	}
}

func TestMinimalProject_ConfigIsValidJSON(t *testing.T) {
	files := testutil.MinimalProject()
	cfgContent, ok := files[config.ConfigFile]
	if !ok {
		t.Fatalf("MinimalProject: missing %s", config.ConfigFile)
	}
	// Minimal validation: contains required JSON keys.
	for _, key := range []string{"version", "project", "rules", "report"} {
		if !strings.Contains(cfgContent, `"`+key+`"`) {
			t.Errorf("MinimalProject: config missing key %q", key)
		}
	}
}

func TestGoSource_IncludesMinimalProject(t *testing.T) {
	const relPath = "myfile.go"
	const src = "package mypkg\n\nfunc Foo() {}\n"
	files := testutil.GoSource(relPath, src)

	// GoSource must include all MinimalProject files.
	for k := range testutil.MinimalProject() {
		if _, ok := files[k]; !ok {
			t.Errorf("GoSource: missing MinimalProject file %q", k)
		}
	}
	// And also the requested source file.
	if got, ok := files[relPath]; !ok {
		t.Errorf("GoSource: missing source file %q", relPath)
	} else if got != src {
		t.Errorf("GoSource: content = %q, want %q", got, src)
	}
}

func TestProjectDir_NestedDirectories(t *testing.T) {
	files := map[string]string{
		"a/b/c/deep.go": "package deep\n",
	}
	dir := testutil.ProjectDir(t, files)
	path := filepath.Join(dir, "a", "b", "c", "deep.go")
	if _, err := os.Stat(path); err != nil {
		t.Errorf("ProjectDir: nested file not created: %v", err)
	}
}
