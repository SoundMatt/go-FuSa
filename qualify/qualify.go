// Package qualify implements the go-FuSa tool qualification suite (v0.9).
//
// It runs a built-in set of test cases — one positive and one negative for
// every registered engine rule — against synthetic isolated project
// directories.  The output is a machine-readable [Report] suitable for use
// as tool qualification evidence in regulated environments
// (ISO 26262 Part 8, IEC 61508 Part 6 tool confidence requirements).
//
// Basic usage:
//
//	report, err := qualify.Run(ctx, engine.Default, qualify.BuiltinCases())
//	if err != nil {
//	    log.Fatal(err)
//	}
//	qualify.Save("qualify-report.json", report)
package qualify

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"time"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/config"
	"github.com/SoundMatt/go-FuSa/engine"
)

// ReportFile is the default filename for a qualification report.
const ReportFile = "qualify-report.json"

// Case is a single qualification test case.
type Case struct {
	// Name is a short human-readable identifier.
	Name string `json:"name"`
	// RuleID is the engine rule being exercised.
	RuleID string `json:"ruleId"`
	// Description describes the scenario under test.
	Description string `json:"description"`
	// Files maps project-relative paths to file content for the synthetic project.
	Files map[string]string `json:"files"`
	// ExpectFinding is true when the case expects at least one finding with RuleID.
	ExpectFinding bool `json:"expectFinding"`
}

// Result status enum values (§6 MUST): every Result.Result is one of these.
const (
	ResultPass  = "PASS"
	ResultFail  = "FAIL"
	ResultSkip  = "SKIP"
	ResultError = "ERROR"
)

// Result is the outcome of a single qualification test case.
//
// Result is the spec-mandated PASS/FAIL/SKIP/ERROR status string (§6 MUST).
// Passed is kept for back-compat with existing callers/CLI output and is
// always exactly (Result == ResultPass).
type Result struct {
	Case   Case   `json:"case"`
	Result string `json:"result"`
	Passed bool   `json:"passed"`
	Error  string `json:"error,omitempty"`
}

// Report is the output of a full qualification run.
//
//fusa:req REQ-QUALIFY002
//fusa:req REQ-QUALIFY007
//fusa:req REQ-QUALIFY008
type Report struct {
	SchemaVersion string    `json:"schemaVersion"`
	Kind          string    `json:"kind"`
	Tool          string    `json:"tool"`
	ToolVersion   string    `json:"toolVersion"`
	Language      string    `json:"language"`
	GeneratedAt   time.Time `json:"generatedAt"`
	GoVersion     string    `json:"goVersion"`
	Module        string    `json:"module"`
	Total         int       `json:"total"`
	Passed        int       `json:"passed"`
	Failed        int       `json:"failed"`
	Results       []Result  `json:"results"`
	// Hash is a SHA-256 integrity hash in "sha256:<hex>" format (§6).
	Hash string `json:"hash"`

	// Tool qualification metadata (Feature 2 — §ISO 26262-8 / IEC 61508-6).
	//fusa:req REQ-QUALIFY007
	QualificationMethod    string `json:"qualificationMethod,omitempty"`    // "self" or "independent"
	QualificationRecordUri string `json:"qualificationRecordUri,omitempty"` // URI to qualification dossier
	QualifierIdentity      string `json:"qualifierIdentity,omitempty"`      // name/org performing qualification

	// V&V independence metadata (Feature 4 — DO-178C §6.4.2 / ISO 26262-8 §9).
	//fusa:req REQ-QUALIFY008
	ImplementationAuthor    string `json:"implementationAuthor,omitempty"`
	IndependentReviewer     string `json:"independentReviewer,omitempty"`
	IndependentTestExecutor string `json:"independentTestExecutor,omitempty"`
	AchievableASIL          string `json:"achievableAsil,omitempty"`
}

// IndependenceStatus returns the V&V independence status for the report.
// Returns "independent" when IndependentReviewer is non-empty and differs from ImplementationAuthor.
// Returns "self-reviewed" when they are the same. Returns "unqualified" when no reviewer is set.
//
//fusa:req REQ-QUALIFY008
func (r *Report) IndependenceStatus() string {
	if r.IndependentReviewer == "" {
		return "unqualified"
	}
	if r.ImplementationAuthor != "" && r.IndependentReviewer == r.ImplementationAuthor {
		return "self-reviewed"
	}
	return "independent"
}

// QualificationBadge returns a human-readable qualification badge string.
//
//fusa:req REQ-QUALIFY007
func (r *Report) QualificationBadge() string {
	switch r.QualificationMethod {
	case "independent":
		return "independently-qualified"
	case "self":
		return "self-qualified"
	default:
		return "unqualified"
	}
}

// HasFailures reports whether any test case in the report failed.
//
//fusa:req REQ-QUALIFY009
func (r *Report) HasFailures() bool { return r.Failed > 0 }

// Run executes cases against reg and returns a Report.
// Each case runs in its own isolated temporary directory and is cleaned up on completion.
// The returned Report includes a SHA-256 integrity hash.
//
//fusa:req REQ-QUALIFY001
func Run(ctx context.Context, reg *engine.Registry, cases []Case) (*Report, error) {
	report := &Report{
		SchemaVersion: fusa.SpecVersion,
		Kind:          "qualification",
		Tool:          "go-FuSa",
		ToolVersion:   fusa.Version,
		Language:      "go",
		GeneratedAt:   time.Now().UTC(),
		GoVersion:     runtime.Version(),
		Module:        "github.com/SoundMatt/go-FuSa",
		Results:       make([]Result, 0, len(cases)),
	}

	for _, c := range cases {
		r := runCase(ctx, reg, c)
		report.Results = append(report.Results, r)
		report.Total++
		if r.Passed {
			report.Passed++
		} else {
			report.Failed++
		}
	}

	hash, err := computeHash(report)
	if err != nil {
		return nil, fmt.Errorf("qualify: hash report: %w", err)
	}
	report.Hash = hash
	return report, nil
}

// Save writes the report as indented JSON to path.
//
//fusa:req REQ-QUALIFY004
func Save(path string, r *Report) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("qualify: marshal report: %w", err)
	}
	return os.WriteFile(path, data, 0o640)
}

// Load reads a qualification report from path.
// Returns [fusa.ErrNoConfig] if path does not exist.
//
//fusa:req REQ-QUALIFY005
func Load(path string) (*Report, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", fusa.ErrNoConfig, path)
		}
		return nil, err
	}
	var r Report
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("%w: qualify report: %v", fusa.ErrInvalidConfig, err)
	}
	return &r, nil
}

// BuiltinCases returns the built-in qualification test cases, covering all
// engine rules with one positive case (expects finding) and one negative case
// (expects no finding) each.
//
//fusa:req REQ-QUALIFY006
func BuiltinCases() []Case { return builtinCases }

// runCase executes a single qualification test case. Infrastructure failures
// (unable to set up or run the synthetic case) report ResultError; a case
// that runs to completion but doesn't match its expectation reports
// ResultFail; a matching case reports ResultPass (§6).
//
//fusa:req REQ-QUALIFY010
func runCase(ctx context.Context, reg *engine.Registry, c Case) Result {
	//fusa:req REQ-QUALIFY003
	dir, err := os.MkdirTemp("", "fusa-qualify-*")
	if err != nil {
		return Result{Case: c, Result: ResultError, Error: fmt.Sprintf("mktemp: %v", err)}
	}
	defer func() { _ = os.RemoveAll(dir) }()

	for rel, content := range c.Files {
		path := filepath.Join(dir, rel)
		if mkErr := os.MkdirAll(filepath.Dir(path), 0o750); mkErr != nil {
			return Result{Case: c, Result: ResultError, Error: fmt.Sprintf("mkdir %s: %v", rel, mkErr)}
		}
		if wErr := os.WriteFile(path, []byte(content), 0o640); wErr != nil {
			return Result{Case: c, Result: ResultError, Error: fmt.Sprintf("write %s: %v", rel, wErr)}
		}
	}

	cfg := config.Default("github.com/fusa-qualify/test", "qualify")
	result, err := reg.Run(ctx, dir, cfg)
	if err != nil {
		return Result{Case: c, Result: ResultError, Error: fmt.Sprintf("engine.Run: %v", err)}
	}

	found := hasFinding(result.Findings, c.RuleID)
	if found == c.ExpectFinding {
		return Result{Case: c, Result: ResultPass, Passed: true}
	}
	if c.ExpectFinding {
		return Result{Case: c, Result: ResultFail, Passed: false,
			Error: fmt.Sprintf("expected finding %s but none was produced", c.RuleID)}
	}
	return Result{Case: c, Result: ResultFail, Passed: false,
		Error: fmt.Sprintf("unexpected finding %s was produced", c.RuleID)}
}

func hasFinding(findings []fusa.Finding, ruleID string) bool {
	for _, f := range findings {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}

// computeHash returns a "sha256:<hex>" integrity hash of the report content
// (excluding the Hash field and §3.1 common-header metadata such as
// generatedAt) per §6. The content is canonicalized with
// [fusa.CanonicalizeJSON] — not Go struct field order — so the hash is
// reproducible across x-FuSa tools (MUST-145/146), and results[] is sorted by
// case name before hashing so ordering never perturbs the digest (MUST-148).
//
//fusa:req REQ-QUALIFY004
func computeHash(r *Report) (string, error) {
	type hashable struct {
		GoVersion string   `json:"goVersion"`
		Module    string   `json:"module"`
		Total     int      `json:"total"`
		Passed    int      `json:"passed"`
		Failed    int      `json:"failed"`
		Results   []Result `json:"results"`
	}
	results := make([]Result, len(r.Results))
	copy(results, r.Results)
	sort.Slice(results, func(i, j int) bool {
		return results[i].Case.Name < results[j].Case.Name
	})
	h := hashable{
		GoVersion: r.GoVersion,
		Module:    r.Module,
		Total:     r.Total,
		Passed:    r.Passed,
		Failed:    r.Failed,
		Results:   results,
	}
	data, err := json.Marshal(h)
	if err != nil {
		return "", err
	}
	canon, err := fusa.CanonicalizeJSON(data)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canon)
	return fmt.Sprintf("sha256:%x", sum), nil
}

// ruleQualifyReport implements engine.Rule for QUALIFY001.
type ruleQualifyReport struct{}

func (r *ruleQualifyReport) ID() string { return "QUALIFY001" }
func (r *ruleQualifyReport) Description() string {
	return "qualify-report.json was not found. A qualification report is required evidence in regulated environments."
}

//fusa:req REQ-QUALIFY001
func (r *ruleQualifyReport) Run(_ context.Context, dir string, _ *config.Config) ([]fusa.Finding, error) {
	if _, err := os.Stat(filepath.Join(dir, ReportFile)); err == nil {
		return nil, nil
	}
	return []fusa.Finding{{
		RuleID:      "QUALIFY001",
		Severity:    fusa.SeverityInfo,
		Message:     "qualify-report.json not found",
		Location:    fusa.Location{File: dir},
		Remediation: "Run 'gofusa qualify' to generate tool qualification evidence.",
	}}, nil
}

func init() {
	engine.Default.MustRegister(&ruleQualifyReport{})
}
