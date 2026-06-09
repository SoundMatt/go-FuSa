// Package verify provides test evidence collection for go-FuSa projects (v0.5).
//
// Use Run to execute the project's test suite and capture structured results,
// then New to build an evidence bundle and Save to persist it. The bundle
// provides an auditable record of test execution for safety evidence packages.
//
// Activate the engine rules by importing this package for its side effects:
//
//	import _ "github.com/SoundMatt/go-FuSa/verify"
package verify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"time"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/config"
	"github.com/SoundMatt/go-FuSa/engine"
)

// BundleFile is the default filename for the evidence bundle.
const BundleFile = ".fusa-evidence.json"

// TestStatus is the outcome of a single test run.
type TestStatus string

const (
	StatusPass TestStatus = "pass"
	StatusFail TestStatus = "fail"
	StatusSkip TestStatus = "skip"
)

// TestResult holds the result of a single test function.
type TestResult struct {
	Name    string     `json:"name"`
	Package string     `json:"package"`
	Status  TestStatus `json:"status"`
	Elapsed float64    `json:"elapsedSeconds"`
}

// Summary holds aggregate test result counts.
type Summary struct {
	Total   int `json:"total"`
	Passed  int `json:"passed"`
	Failed  int `json:"failed"`
	Skipped int `json:"skipped"`
}

// Bundle is the verification evidence bundle persisted to BundleFile.
type Bundle struct {
	GeneratedAt time.Time    `json:"generatedAt"`
	ProjectRoot string       `json:"projectRoot"`
	GoVersion   string       `json:"goVersion"`
	Results     []TestResult `json:"results"`
	Summary     Summary      `json:"summary"`
}

// testEvent is one line of go test -json output.
type testEvent struct {
	Action  string  `json:"Action"`
	Test    string  `json:"Test"`
	Package string  `json:"Package"`
	Elapsed float64 `json:"Elapsed"`
}

// Parse reads go test -json output from r and returns per-test results.
// Package-level events (no Test field) are ignored.
//
//fusa:req REQ-VERIFY004
func Parse(r io.Reader) ([]TestResult, error) {
	dec := json.NewDecoder(r)
	var results []TestResult
	for {
		var ev testEvent
		if err := dec.Decode(&ev); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("verify: parse: %w", err)
		}
		if ev.Test == "" {
			continue // package-level event
		}
		switch ev.Action {
		case "pass":
			results = append(results, TestResult{Name: ev.Test, Package: ev.Package, Status: StatusPass, Elapsed: ev.Elapsed})
		case "fail":
			results = append(results, TestResult{Name: ev.Test, Package: ev.Package, Status: StatusFail, Elapsed: ev.Elapsed})
		case "skip":
			results = append(results, TestResult{Name: ev.Test, Package: ev.Package, Status: StatusSkip, Elapsed: ev.Elapsed})
		}
	}
	return results, nil
}

// Summarise computes aggregate counts from a slice of TestResults.
//
//fusa:req REQ-VERIFY004
func Summarise(results []TestResult) Summary {
	s := Summary{Total: len(results)}
	for _, r := range results {
		switch r.Status {
		case StatusPass:
			s.Passed++
		case StatusFail:
			s.Failed++
		case StatusSkip:
			s.Skipped++
		}
	}
	return s
}

// New builds a Bundle from test results for the given project root.
//
//fusa:req REQ-VERIFY003
func New(projectRoot string, results []TestResult) *Bundle {
	return &Bundle{
		GeneratedAt: time.Now().UTC(),
		ProjectRoot: projectRoot,
		GoVersion:   runtime.Version(),
		Results:     results,
		Summary:     Summarise(results),
	}
}

// Run executes go test -json -count=1 ./... in dir and returns parsed results.
// A test-failure exit code is not an error; the results will contain StatusFail
// entries. Other execution errors (go not found, no module) are returned as errors.
//
//fusa:req REQ-VERIFY005
func Run(ctx context.Context, dir string) ([]TestResult, error) {
	cmd := exec.CommandContext(ctx, "go", "test", "-json", "-count=1", "./...")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			return nil, fmt.Errorf("verify: run: %w", err)
		}
		// Non-zero exit means test failures; still parse whatever was written.
	}
	return Parse(bytes.NewReader(out))
}

// Save writes the evidence bundle to path as indented JSON.
//
//fusa:req REQ-VERIFY006
func Save(path string, b *Bundle) error {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return fmt.Errorf("verify: marshal bundle: %w", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o640); err != nil {
		return fmt.Errorf("verify: write %s: %w", path, err)
	}
	return nil
}

// Load reads an evidence bundle from path.
//
//fusa:req REQ-VERIFY007
func Load(path string) (*Bundle, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fusa.ErrNoConfig
		}
		return nil, fmt.Errorf("verify: read %s: %w", path, err)
	}
	var b Bundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("%w: %s: %s", fusa.ErrInvalidConfig, path, err)
	}
	return &b, nil
}

// ─── Engine rules ──────────────────────────────────────────────────────────────

func init() {
	engine.Default.MustRegister(&ruleEvidencePresent{})
	engine.Default.MustRegister(&ruleNoTestFailures{})
}

// VERIFY001 — .fusa-evidence.json should be present.
type ruleEvidencePresent struct{}

func (r *ruleEvidencePresent) ID() string { return "VERIFY001" }
func (r *ruleEvidencePresent) Description() string {
	return "Project should have a .fusa-evidence.json test evidence bundle."
}

//fusa:req REQ-VERIFY001
func (r *ruleEvidencePresent) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	path := projectRoot + "/" + BundleFile
	if _, err := os.Stat(path); err == nil {
		return nil, nil
	}
	return []fusa.Finding{{
		RuleID:      r.ID(),
		Severity:    fusa.SeverityInfo,
		Message:     "no .fusa-evidence.json test evidence bundle found",
		Location:    fusa.Location{File: BundleFile},
		Remediation: "run 'gofusa verify' to generate the test evidence bundle",
	}}, nil
}

// VERIFY002 — evidence bundle must show no test failures.
type ruleNoTestFailures struct{}

func (r *ruleNoTestFailures) ID() string { return "VERIFY002" }
func (r *ruleNoTestFailures) Description() string {
	return "Test evidence bundle must contain no failed tests."
}

//fusa:req REQ-VERIFY002
func (r *ruleNoTestFailures) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	b, err := Load(projectRoot + "/" + BundleFile)
	if err != nil {
		if errors.Is(err, fusa.ErrNoConfig) {
			return nil, nil // VERIFY001 handles missing bundle
		}
		return nil, err
	}
	if b.Summary.Failed == 0 {
		return nil, nil
	}
	return []fusa.Finding{{
		RuleID:   r.ID(),
		Severity: fusa.SeverityWarning,
		Message: fmt.Sprintf("evidence bundle reports %d failed test(s) out of %d total",
			b.Summary.Failed, b.Summary.Total),
		Location:    fusa.Location{File: BundleFile},
		Remediation: "fix failing tests and regenerate the evidence bundle with 'gofusa verify'",
	}}, nil
}
