package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

//fusa:test REQ-E2E001
func TestPipeline_EndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping end-to-end pipeline test in short mode")
	}

	dir := t.TempDir()

	// Minimal Go project: real module, real test, all structural files present.
	// No .fusa.json — gofusa init will create it in stage 1.
	files := map[string]string{
		"go.mod":                   "module example.com/e2e\n\ngo 1.22\n",
		"LICENSE":                  "MIT License\n\nCopyright (c) 2024 Example\n",
		"README.md":                "# e2e\n",
		".github/workflows/ci.yml": "name: CI\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: go test ./...\n",
		"compute.go":               "package e2e\n\n// Add returns the sum of a and b.\nfunc Add(a, b int) int { return a + b }\n",
		"compute_test.go":          "package e2e\n\nimport \"testing\"\n\nfunc TestAdd(t *testing.T) {\n\tif got := Add(1, 2); got != 3 {\n\t\tt.Errorf(\"Add(1,2) = %d, want 3\", got)\n\t}\n}\n",
	}
	for rel, content := range files {
		full := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(full), err)
		}
		if err := os.WriteFile(full, []byte(content), 0o640); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}

	stage := func(name string, args ...string) {
		t.Helper()
		var out, errOut bytes.Buffer
		code := run(args, &out, &errOut)
		if code != 0 {
			t.Errorf("stage %q: exit %d\nstdout:\n%s\nstderr:\n%s",
				name, code, out.String(), errOut.String())
		}
	}

	// 1. init — creates .fusa.json
	stage("init", "init", "--dir", dir)
	if _, err := os.Stat(filepath.Join(dir, ".fusa.json")); err != nil {
		t.Fatalf("init: .fusa.json not created: %v", err)
	}

	// 2. check — must pass with all project files in place
	stage("check", "check", "--dir", dir)

	// 3. trace — no .fusa-reqs.json yet; emits TRACE001 INFO, still exits 0
	stage("trace", "trace", "--dir", dir)

	// 4. verify — runs go test on the synthetic project
	stage("verify", "verify", "--dir", dir)
	if _, err := os.Stat(filepath.Join(dir, ".fusa-evidence.json")); err != nil {
		t.Errorf("verify: .fusa-evidence.json not created: %v", err)
	}

	// 5. release — generates sbom.json and provenance.json
	stage("release", "release", "--dir", dir)
	for _, f := range []string{"sbom.json", "provenance.json"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("release: %s not created: %v", f, err)
		}
	}

	// 6. qualify — runs the 44-case built-in suite
	qualifyOut := filepath.Join(dir, "qualify-report.json")
	stage("qualify", "qualify", "--output", qualifyOut)
	if _, err := os.Stat(qualifyOut); err != nil {
		t.Errorf("qualify: qualify-report.json not created: %v", err)
	}
}
