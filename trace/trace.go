// Package trace provides requirements traceability for go-FuSa projects (v0.4).
//
// A project records its requirements in .fusa-reqs.json. Source files are
// annotated with //fusa:req <ID> comments for implementation references and
// //fusa:test <ID> comments for test references. Build constructs the full
// traceability matrix linking requirements to their code and test locations.
//
// Activate the engine rules by importing this package for its side effects:
//
//	import _ "github.com/SoundMatt/go-FuSa/trace"
package trace

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/config"
	"github.com/SoundMatt/go-FuSa/engine"
)

// ReqsFile is the default requirements manifest filename.
const ReqsFile = ".fusa-reqs.json"

// TagKind distinguishes implementation references from test references.
type TagKind string

const (
	// KindImpl marks a source location that implements a requirement.
	KindImpl TagKind = "impl"
	// KindTest marks a source location that tests a requirement.
	KindTest TagKind = "test"
	// KindSecTest marks a security-test that verifies a CYBER/security requirement.
	// Used with //fusa:sec-test <REQ-ID> annotations.
	KindSecTest TagKind = "sec-test"
)

// Requirement is a traceable safety requirement.
type Requirement struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Text     string `json:"text,omitempty"`
	Standard string `json:"standard,omitempty"`
	Level    string `json:"level,omitempty"`
}

// Tag links a source location to a requirement.
type Tag struct {
	RequirementID string  `json:"requirementId"`
	File          string  `json:"file"`
	Line          int     `json:"line"`
	Kind          TagKind `json:"kind"`
}

// Coverage holds traceability coverage metrics.
type Coverage struct {
	TotalRequirements     int `json:"totalRequirements"`
	TracedRequirements    int `json:"tracedRequirements"`
	TestedRequirements    int `json:"testedRequirements"`
	SecTestedRequirements int `json:"secTestedRequirements"` // //fusa:sec-test tags
}

// FuncCoverage reports exported-function annotation density.
type FuncCoverage struct {
	Total     int      `json:"total"`
	Covered   int      `json:"covered"`
	Pct       float64  `json:"pct"`
	Uncovered []string `json:"uncovered,omitempty"`
}

const (
	// DefaultReqCoverageThreshold is the minimum requirement-to-source coverage % for TRACE006.
	DefaultReqCoverageThreshold = 80
	// DefaultFuncAnnotationThreshold is the minimum exported-function annotation density % for TRACE007.
	DefaultFuncAnnotationThreshold = 80
)

// Matrix is the full traceability matrix for a project.
type Matrix struct {
	Requirements []Requirement `json:"requirements"`
	Tags         []Tag         `json:"tags"`
	Coverage     Coverage      `json:"coverage"`
}

// LoadRequirements reads requirements from .fusa-reqs.json in dir.
// Returns fusa.ErrNoConfig if the file is absent.
//
//fusa:req REQ-TRACE001
func LoadRequirements(dir string) ([]Requirement, error) {
	path := filepath.Join(dir, ReqsFile)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fusa.ErrNoConfig
		}
		return nil, fmt.Errorf("trace: read %s: %w", ReqsFile, err)
	}
	var payload struct {
		Requirements []Requirement `json:"requirements"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, fmt.Errorf("%w: %s: %s", fusa.ErrInvalidConfig, ReqsFile, err)
	}
	return payload.Requirements, nil
}

// SaveRequirements writes reqs as .fusa-reqs.json in dir.
//
//fusa:req REQ-TRACE001
func SaveRequirements(dir string, reqs []Requirement) error {
	payload := struct {
		Requirements []Requirement `json:"requirements"`
	}{Requirements: reqs}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("trace: marshal requirements: %w", err)
	}
	path := filepath.Join(dir, ReqsFile)
	if err := os.WriteFile(path, append(data, '\n'), 0o640); err != nil {
		return fmt.Errorf("trace: write %s: %w", ReqsFile, err)
	}
	return nil
}

// ScanTags walks Go source files under root and returns all //fusa:req and
// //fusa:test annotation tags found in comments.
func ScanTags(root string) ([]Tag, error) {
	var tags []Tag
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if path == root {
				return nil // never skip the root itself
			}
			name := d.Name()
			//fusa:req REQ-TRACE005
			if name == "vendor" || name == "testdata" || strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") {
			return nil
		}
		fileTags, ferr := scanFile(path)
		if ferr != nil {
			return ferr
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		for i := range fileTags {
			fileTags[i].File = rel
		}
		tags = append(tags, fileTags...)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("trace: scan: %w", err)
	}
	return tags, nil
}

// scanFile extracts trace tags from a single file by line scanning.
func scanFile(path string) ([]Tag, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("trace: open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	var tags []Tag
	sc := bufio.NewScanner(f)
	lineNum := 0
	for sc.Scan() {
		lineNum++
		text := strings.TrimSpace(sc.Text())
		for _, pair := range []struct {
			prefix string
			kind   TagKind
		}{
			{"//fusa:req ", KindImpl},
			{"//fusa:test ", KindTest},
			{"//fusa:sec-test ", KindSecTest},
		} {
			if !strings.HasPrefix(text, pair.prefix) {
				continue
			}
			//fusa:req REQ-TRACE007
			//fusa:req REQ-TRACE005
			reqID := strings.TrimSpace(text[len(pair.prefix):])
			if reqID == "" {
				continue
			}
			tags = append(tags, Tag{
				RequirementID: reqID,
				Line:          lineNum,
				Kind:          pair.kind,
			})
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("trace: scan %s: %w", path, err)
	}
	return tags, nil
}

// Build constructs the full traceability Matrix for the project at root.
// If no .fusa-reqs.json exists, the matrix will have an empty requirements list
// but will still include any tags found in source files.
//
//fusa:req REQ-TRACE002
func Build(root string) (*Matrix, error) {
	reqs, err := LoadRequirements(root)
	if err != nil && !errors.Is(err, fusa.ErrNoConfig) {
		return nil, err
	}

	tags, err := ScanTags(root)
	if err != nil {
		return nil, err
	}

	sort.Slice(reqs, func(i, j int) bool { return reqs[i].ID < reqs[j].ID })
	sort.Slice(tags, func(i, j int) bool {
		if tags[i].RequirementID != tags[j].RequirementID {
			return tags[i].RequirementID < tags[j].RequirementID
		}
		if tags[i].File != tags[j].File {
			return tags[i].File < tags[j].File
		}
		return tags[i].Line < tags[j].Line
	})

	traced := make(map[string]bool)
	tested := make(map[string]bool)
	secTested := make(map[string]bool)
	for _, t := range tags {
		switch t.Kind {
		case KindImpl:
			traced[t.RequirementID] = true
		case KindTest:
			tested[t.RequirementID] = true
		case KindSecTest:
			secTested[t.RequirementID] = true
		}
	}

	cov := Coverage{TotalRequirements: len(reqs)}
	for _, req := range reqs {
		//fusa:req REQ-TRACE003
		if traced[req.ID] {
			cov.TracedRequirements++
		}
		//fusa:req REQ-TRACE004
		if tested[req.ID] {
			cov.TestedRequirements++
		}
		//fusa:req REQ-TRACE005
		if secTested[req.ID] {
			cov.SecTestedRequirements++
		}
	}

	return &Matrix{
		Requirements: reqs,
		Tags:         tags,
		Coverage:     cov,
	}, nil
}

// ScanFuncCoverage counts exported functions and how many live in files that
// contain at least one //fusa:req annotation. tags must be the ScanTags result
// for the same root. Test files (_test.go) are excluded.
//
//fusa:req REQ-TRACE007
func ScanFuncCoverage(root string, tags []Tag) (*FuncCoverage, error) {
	annotated := make(map[string]bool)
	for _, t := range tags {
		if t.Kind == KindImpl {
			annotated[t.File] = true
		}
	}

	fset := token.NewFileSet()
	fc := &FuncCoverage{}

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if path == root {
				return nil
			}
			name := d.Name()
			if name == "vendor" || name == "testdata" || strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return nil // skip unparseable files
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name == nil || !ast.IsExported(fn.Name.Name) {
				continue
			}
			fc.Total++
			if annotated[rel] {
				fc.Covered++
			} else {
				fc.Uncovered = append(fc.Uncovered, rel+":"+fn.Name.Name)
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("trace: scan func coverage: %w", err)
	}
	if fc.Total > 0 {
		fc.Pct = float64(fc.Covered) * 100 / float64(fc.Total)
	}
	return fc, nil
}

// Render writes the traceability matrix to w in the given format.
// Supported formats: "text" (default), "json".
//
//fusa:req REQ-TRACE006
func Render(w io.Writer, m *Matrix, format string) error {
	switch format {
	case "", "text":
		return renderText(w, m)
	case "json":
		return renderJSON(w, m)
	default:
		return fmt.Errorf("trace: unsupported format %q", format)
	}
}

func renderText(w io.Writer, m *Matrix) error {
	lines := []string{
		"Requirements Traceability Matrix",
		fmt.Sprintf("Requirements: %d  Traced: %d  Tested: %d  Sec-Tested: %d",
			m.Coverage.TotalRequirements,
			m.Coverage.TracedRequirements,
			m.Coverage.TestedRequirements,
			m.Coverage.SecTestedRequirements),
		"",
	}
	for _, l := range lines {
		if _, err := fmt.Fprintln(w, l); err != nil {
			return err
		}
	}

	if len(m.Requirements) == 0 {
		if _, err := fmt.Fprintf(w, "No requirements defined. Add requirements to %s.\n", ReqsFile); err != nil {
			return err
		}
	}

	byReq := make(map[string][]Tag)
	for _, t := range m.Tags {
		byReq[t.RequirementID] = append(byReq[t.RequirementID], t)
	}

	for _, req := range m.Requirements {
		entries := byReq[req.ID]
		hasImpl := false
		hasTest := false
		for _, e := range entries {
			if e.Kind == KindImpl {
				hasImpl = true
			}
			if e.Kind == KindTest {
				hasTest = true
			}
		}
		var status string
		switch {
		case hasImpl && hasTest:
			status = "[traced+tested]"
		case hasImpl:
			status = "[traced]      "
		default:
			status = "[untraced]    "
		}
		if _, err := fmt.Fprintf(w, "%s  %s  %s\n", status, req.ID, req.Title); err != nil {
			return err
		}
		for _, e := range entries {
			if _, err := fmt.Fprintf(w, "               %s  %s:%d\n", e.Kind, e.File, e.Line); err != nil {
				return err
			}
		}
	}

	knownReqs := make(map[string]bool)
	for _, req := range m.Requirements {
		knownReqs[req.ID] = true
	}
	var orphans []Tag
	for _, t := range m.Tags {
		if !knownReqs[t.RequirementID] {
			orphans = append(orphans, t)
		}
	}
	if len(orphans) > 0 {
		if _, err := fmt.Fprintln(w, "\nOrphan tags (no matching requirement in "+ReqsFile+"):"); err != nil {
			return err
		}
		for _, t := range orphans {
			if _, err := fmt.Fprintf(w, "  %s  %s:%d  (%s)\n", t.RequirementID, t.File, t.Line, t.Kind); err != nil {
				return err
			}
		}
	}
	return nil
}

func renderJSON(w io.Writer, m *Matrix) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(m); err != nil {
		return fmt.Errorf("trace: json encode: %w", err)
	}
	return nil
}

// ─── Engine rules ──────────────────────────────────────────────────────────────

func init() {
	engine.Default.MustRegister(&ruleReqsPresent{})
	engine.Default.MustRegister(&ruleAllReqsTraced{})
	engine.Default.MustRegister(&ruleUntestedReqs{})
	engine.Default.MustRegister(&ruleReqMissingText{})
	engine.Default.MustRegister(&ruleVerificationIndependence{})
	engine.Default.MustRegister(&ruleReqCoverage{})
	engine.Default.MustRegister(&ruleFuncAnnotationDensity{})
}

// TRACE001 — .fusa-reqs.json should be present.
type ruleReqsPresent struct{}

func (r *ruleReqsPresent) ID() string { return "TRACE001" }
func (r *ruleReqsPresent) Description() string {
	return "Project should have a .fusa-reqs.json requirements manifest for traceability."
}

//fusa:req REQ-TRACE001
func (r *ruleReqsPresent) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	_, err := os.Stat(filepath.Join(projectRoot, ReqsFile))
	if err == nil {
		return nil, nil
	}
	if os.IsNotExist(err) {
		return []fusa.Finding{{
			RuleID:      r.ID(),
			Severity:    fusa.SeverityInfo,
			Message:     "no .fusa-reqs.json requirements manifest found",
			Location:    fusa.Location{File: ReqsFile},
			Remediation: "create " + ReqsFile + " to enable requirements traceability",
		}}, nil
	}
	return nil, err
}

// TRACE002 — all requirements must have at least one //fusa:req implementation tag.
//
//fusa:req REQ-REQQ001
type ruleAllReqsTraced struct{}

func (r *ruleAllReqsTraced) ID() string { return "TRACE002" }
func (r *ruleAllReqsTraced) Description() string {
	return "Every requirement in .fusa-reqs.json must have at least one //fusa:req implementation tag."
}

//fusa:req REQ-TRACE002
func (r *ruleAllReqsTraced) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	matrix, err := Build(projectRoot)
	if err != nil {
		return nil, err
	}
	if len(matrix.Requirements) == 0 {
		return nil, nil
	}

	traced := make(map[string]bool)
	for _, t := range matrix.Tags {
		if t.Kind == KindImpl {
			traced[t.RequirementID] = true
		}
	}

	var findings []fusa.Finding
	for _, req := range matrix.Requirements {
		if !traced[req.ID] {
			findings = append(findings, fusa.Finding{
				RuleID:      r.ID(),
				Severity:    fusa.SeverityWarning,
				Message:     fmt.Sprintf("requirement %s (%q) has no //fusa:req implementation tag", req.ID, req.Title),
				Location:    fusa.Location{File: ReqsFile},
				Remediation: "add //fusa:req " + req.ID + " comment in the implementing source file",
			})
		}
	}
	return findings, nil
}

// TRACE003 — requirements with no //fusa:test tag are a test gap.
type ruleUntestedReqs struct{}

func (r *ruleUntestedReqs) ID() string { return "TRACE003" }
func (r *ruleUntestedReqs) Description() string {
	return "Requirements in .fusa-reqs.json with no //fusa:test tag have no automated test evidence."
}

//fusa:req REQ-REQQ002
func (r *ruleUntestedReqs) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	matrix, err := Build(projectRoot)
	if err != nil {
		return nil, err
	}
	if len(matrix.Requirements) == 0 {
		return nil, nil
	}

	tested := make(map[string]bool)
	for _, t := range matrix.Tags {
		if t.Kind == KindTest {
			tested[t.RequirementID] = true
		}
	}

	var findings []fusa.Finding
	for _, req := range matrix.Requirements {
		if !tested[req.ID] {
			findings = append(findings, fusa.Finding{
				RuleID:      r.ID(),
				Severity:    fusa.SeverityInfo,
				Message:     fmt.Sprintf("requirement %s (%q) has no //fusa:test tag — test coverage gap", req.ID, req.Title),
				Location:    fusa.Location{File: ReqsFile},
				Remediation: "add //fusa:test " + req.ID + " in a _test.go file",
			})
		}
	}
	return findings, nil
}

// TRACE004 — requirements missing the text field lack formal specification.
type ruleReqMissingText struct{}

func (r *ruleReqMissingText) ID() string { return "TRACE004" }
func (r *ruleReqMissingText) Description() string {
	return "Requirements without a text field lack a formal specification statement."
}

//fusa:req REQ-REQQ003
func (r *ruleReqMissingText) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	reqs, err := LoadRequirements(projectRoot)
	if err != nil {
		if errors.Is(err, fusa.ErrNoConfig) {
			return nil, nil
		}
		return nil, err
	}

	var findings []fusa.Finding
	for _, req := range reqs {
		if strings.TrimSpace(req.Text) == "" {
			findings = append(findings, fusa.Finding{
				RuleID:      r.ID(),
				Severity:    fusa.SeverityWarning,
				Message:     fmt.Sprintf("requirement %s (%q) is missing its text field", req.ID, req.Title),
				Location:    fusa.Location{File: ReqsFile},
				Remediation: "add a \"text\" field to " + req.ID + " with a complete requirement statement",
			})
		}
	}
	return findings, nil
}

// TRACE005 — verification independence: same file has both //fusa:req and //fusa:test
// for the same requirement, suggesting the developer also wrote the test.
// DO-178C §6.4.2 requires independence at DAL-A/B.
type ruleVerificationIndependence struct{}

func (r *ruleVerificationIndependence) ID() string { return "TRACE005" }
func (r *ruleVerificationIndependence) Description() string {
	return "Same file has both //fusa:req and //fusa:test for the same requirement — verification independence risk (DO-178C §6.4.2)."
}

//fusa:req REQ-TRACE005
func (r *ruleVerificationIndependence) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	matrix, err := Build(projectRoot)
	if err != nil {
		return nil, err
	}
	if len(matrix.Requirements) == 0 {
		return nil, nil
	}

	implFiles := make(map[string]map[string]bool)
	testFiles := make(map[string]map[string]bool)
	for _, t := range matrix.Tags {
		switch t.Kind {
		case KindImpl:
			if implFiles[t.RequirementID] == nil {
				implFiles[t.RequirementID] = make(map[string]bool)
			}
			implFiles[t.RequirementID][t.File] = true
		case KindTest:
			if testFiles[t.RequirementID] == nil {
				testFiles[t.RequirementID] = make(map[string]bool)
			}
			testFiles[t.RequirementID][t.File] = true
		}
	}

	var findings []fusa.Finding
	for reqID, impls := range implFiles {
		tests, ok := testFiles[reqID]
		if !ok {
			continue
		}
		for file := range impls {
			if tests[file] {
				findings = append(findings, fusa.Finding{
					RuleID:   r.ID(),
					Severity: fusa.SeverityInfo,
					Message: fmt.Sprintf(
						"requirement %s: file %q contains both //fusa:req and //fusa:test — consider independent verifier (DO-178C §6.4.2)",
						reqID, file,
					),
					Location:    fusa.Location{File: file},
					Remediation: "have a different engineer or file provide the //fusa:test annotation for independence evidence",
				})
				break
			}
		}
	}
	return findings, nil
}

// TRACE006 — aggregate requirement-to-source traceability below threshold.
// Fires when fewer than DefaultReqCoverageThreshold% of requirements have a
// //fusa:req implementation annotation (DO-178C §6.4.4).
type ruleReqCoverage struct{}

func (r *ruleReqCoverage) ID() string { return "TRACE006" }
func (r *ruleReqCoverage) Description() string {
	return "Aggregate requirement-to-source traceability below threshold (DO-178C §6.4.4)."
}

//fusa:req REQ-TRACE006
func (r *ruleReqCoverage) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	matrix, err := Build(projectRoot)
	if err != nil {
		return nil, err
	}
	if matrix.Coverage.TotalRequirements == 0 {
		return nil, nil
	}
	pct := matrix.Coverage.TracedRequirements * 100 / matrix.Coverage.TotalRequirements
	if pct >= DefaultReqCoverageThreshold {
		return nil, nil
	}
	return []fusa.Finding{{
		RuleID:   r.ID(),
		Severity: fusa.SeverityWarning,
		Message: fmt.Sprintf(
			"requirement coverage %d%% (%d/%d requirements have //fusa:req annotations) is below the %d%% threshold",
			pct, matrix.Coverage.TracedRequirements, matrix.Coverage.TotalRequirements, DefaultReqCoverageThreshold,
		),
		Location:    fusa.Location{File: ReqsFile},
		Remediation: "add //fusa:req <ID> annotations to source files implementing each untraced requirement",
	}}, nil
}

// TRACE007 — exported-function annotation density below threshold.
// Fires when fewer than DefaultFuncAnnotationThreshold% of exported functions
// are in files with //fusa:req annotations.
type ruleFuncAnnotationDensity struct{}

func (r *ruleFuncAnnotationDensity) ID() string { return "TRACE007" }
func (r *ruleFuncAnnotationDensity) Description() string {
	return "Exported function annotation density below threshold — many functions lack //fusa:req traceability."
}

//fusa:req REQ-TRACE007
func (r *ruleFuncAnnotationDensity) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	tags, err := ScanTags(projectRoot)
	if err != nil {
		return nil, err
	}
	fc, err := ScanFuncCoverage(projectRoot, tags)
	if err != nil {
		return nil, err
	}
	if fc.Total == 0 {
		return nil, nil
	}
	if fc.Pct >= float64(DefaultFuncAnnotationThreshold) {
		return nil, nil
	}
	return []fusa.Finding{{
		RuleID:   r.ID(),
		Severity: fusa.SeverityInfo,
		Message: fmt.Sprintf(
			"function annotation density %.0f%% (%d/%d exported functions in annotated files) is below the %d%% threshold",
			fc.Pct, fc.Covered, fc.Total, DefaultFuncAnnotationThreshold,
		),
		Location:    fusa.Location{File: "."},
		Remediation: "add //fusa:req annotations to source files containing exported functions",
	}}, nil
}
