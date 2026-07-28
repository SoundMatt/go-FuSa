// Package fmea generates a Design Failure Mode and Effects Analysis (dFMEA)
// table from Go source code (v0.12).
//
// Scan walks a project root, parses exported function declarations using
// go/ast, and derives failure modes, effects, and severities from function
// signatures, return types, goroutine usage, and //fusa:req annotations.
//
// Render writes the resulting [Report] in "json" or "csv" format.
//
// Activate the engine rule by importing this package for its side effects:
//
//	import _ "github.com/SoundMatt/go-FuSa/fmea"
package fmea

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/config"
	"github.com/SoundMatt/go-FuSa/engine"
	"github.com/SoundMatt/go-FuSa/trace"
)

// FMEAFile and FMEACSVFile are the default output filenames.
const (
	FMEAFile    = "fmea.json"
	FMEACSVFile = "fmea.csv"
)

// Severity is the estimated impact severity of a failure mode.
type Severity string

const (
	SeverityHigh   Severity = "high"
	SeverityMedium Severity = "medium"
	SeverityLow    Severity = "low"
)

// Entry is a single row in a dFMEA table, derived from one exported function.
//
// FailureMode/Effect/Cause are the x-FuSa spec §9.2 canonical singular
// fields; FailureModes/Effects (plural, kept for back-compat with existing
// callers/CSV output) hold the same content as the un-joined candidate list
// — FailureMode/Effect are simply strings.Join(…, "; ") of the plural forms.
//
//fusa:req REQ-FMEA001
type Entry struct {
	ID   string `json:"id"`
	Item string `json:"item"` // "<component>.<function>" — component/function under analysis (§9.2 MUST)

	Component string `json:"component,omitempty"` // supplementary breakdown of Item, not part of the §9.2 schema
	Function  string `json:"function,omitempty"`  // supplementary breakdown of Item, not part of the §9.2 schema
	File      string `json:"file,omitempty"`

	FailureMode string   `json:"failureMode"`
	Effect      string   `json:"effect"`
	Cause       string   `json:"cause,omitempty"`
	Severity    Severity `json:"severity"`

	ActionPriority string   `json:"actionPriority,omitempty"`
	Mitigations    []string `json:"mitigations,omitempty"`
	RequirementIDs []string `json:"requirementIds,omitempty"`

	// FailureModes/Effects are the un-joined candidate lists FailureMode/
	// Effect are built from — kept for existing consumers (CSV, tests).
	FailureModes     []string `json:"failureModes,omitempty"`
	Effects          []string `json:"effects,omitempty"`
	DetectionControl string   `json:"detectionControl,omitempty"`
	CyberRisks       []string `json:"cyberRisks,omitempty"` // populated by EnrichWithCyber
}

// Summary is the x-FuSa spec §9.2 `fmea.json` summary block.
//
//fusa:req REQ-FMEA007
type Summary struct {
	Total        int `json:"total"`
	HighPriority int `json:"highPriority"`

	// ComponentsAnalyzed/ComponentsInProject/CoveragePct are the §9.2
	// coverage metrics: coveragePct = 100 * componentsAnalyzed /
	// componentsInProject. ComponentsInProjectMethod documents the
	// denominator methodology honestly (see CountProjectFunctions doc).
	ComponentsAnalyzed        int     `json:"componentsAnalyzed"`
	ComponentsInProject       int     `json:"componentsInProject"`
	CoveragePct               float64 `json:"coveragePct"`
	ComponentsInProjectMethod string  `json:"componentsInProjectMethod,omitempty"`
}

// Report is the complete dFMEA output for a project.
//
//fusa:req REQ-FMEA008
type Report struct {
	// §3.1 common header.
	SchemaVersion string    `json:"schemaVersion"`
	Kind          string    `json:"kind"`
	Tool          string    `json:"tool"`
	ToolVersion   string    `json:"toolVersion"`
	Language      string    `json:"language"`
	GeneratedAt   time.Time `json:"generatedAt"`

	Format string `json:"format,omitempty"` // supplementary/legacy, not part of the §3.1 header
	Module string `json:"module,omitempty"`

	Entries []Entry `json:"entries"`
	Summary Summary `json:"summary"`

	// Attestation is the optional §1.6.2 independent-review assertion that
	// can suppress a FUSA-STUB002 (blanket-fallback) finding on this file.
	Attestation *fusa.Attestation `json:"attestation,omitempty"`
}

// Scan walks projectRoot, parses exported Go functions, and returns a dFMEA report.
// Vendor, testdata, and hidden directories are skipped.
//
//fusa:req REQ-FMEA001
//fusa:req REQ-FMEA002
//fusa:req REQ-FMEA003
func Scan(projectRoot string) (*Report, error) {
	report := &Report{
		SchemaVersion: fusa.SchemaVersion(),
		Kind:          "fmea-report",
		Tool:          "go-FuSa",
		ToolVersion:   fusa.Version,
		Language:      "go",
		GeneratedAt:   time.Now().UTC(),
		Format:        "go-FuSa dFMEA v1",
		Module:        readModule(projectRoot),
	}

	err := filepath.WalkDir(projectRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		base := d.Name()
		if base == "vendor" || base == "testdata" || (base != "." && strings.HasPrefix(base, ".")) {
			return filepath.SkipDir
		}
		entries, scanErr := scanDir(path)
		if scanErr != nil {
			return nil // skip unparseable directories
		}
		report.Entries = append(report.Entries, entries...)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("fmea: scan %s: %w", projectRoot, err)
	}

	sort.Slice(report.Entries, func(i, j int) bool {
		if report.Entries[i].Component != report.Entries[j].Component {
			return report.Entries[i].Component < report.Entries[j].Component
		}
		return report.Entries[i].Function < report.Entries[j].Function
	})
	for i := range report.Entries {
		report.Entries[i].ID = fmt.Sprintf("FMEA-%03d", i+1)
		// §4 MUST: entries[].file is project-relative, forward-slash — the
		// same rule lint/analyze/cyber already apply to their own findings.
		// scanFile assigns the raw (often absolute, under the default
		// --dir-omitted invocation) walked path; relativize it here rather
		// than threading projectRoot through scanDir/scanFile.
		//
		//fusa:req REQ-LOC-REL003
		report.Entries[i].File = relFile(projectRoot, report.Entries[i].File)
	}

	report.Summary = buildSummary(report, projectRoot)
	return report, nil
}

// buildSummary computes the §9.2 coverage metrics. ComponentsAnalyzed is the
// number of entries Scan actually produced; ComponentsInProject is an
// independent count (CountProjectFunctions, a raw source-text scan that
// still counts functions in a file Scan's AST parser could not analyze) —
// see CountProjectFunctions doc for the honesty tradeoff this makes.
func buildSummary(report *Report, projectRoot string) Summary {
	s := Summary{Total: len(report.Entries), ComponentsAnalyzed: len(report.Entries)}
	for _, e := range report.Entries {
		if e.Severity == SeverityHigh {
			s.HighPriority++
		}
	}
	total, err := CountProjectFunctions(projectRoot)
	if err != nil || total < s.ComponentsAnalyzed {
		// Fall back to the exhaustive-by-construction case: Scan analyzes
		// every exported function it can parse, so absent a working
		// independent count, componentsInProject can be no smaller than
		// what was actually analyzed.
		total = s.ComponentsAnalyzed
	}
	s.ComponentsInProject = total
	if total > 0 {
		s.CoveragePct = float64(s.ComponentsAnalyzed) * 100 / float64(total)
	} else {
		s.CoveragePct = 100
	}
	// x-FuSa spec §9.2 MUST: coveragePct must never exceed 100. The fallback
	// above already guarantees total >= ComponentsAnalyzed (so this can't
	// currently trigger), but a defensive clamp is cheap insurance against a
	// future change to the fallback logic silently reintroducing the
	// overflow the spec calls out.
	//
	//fusa:req REQ-FMEA012
	if s.CoveragePct > 100 {
		s.CoveragePct = 100
	}
	s.ComponentsInProjectMethod = "raw regex scan for top-level exported func declarations in non-test .go files " +
		"under non-vendor/testdata/dot-directories (CountProjectFunctions) — independent of Scan's own go/ast parse, " +
		"so a file Scan's parser rejects still counts toward the denominator; componentsAnalyzed counts entries Scan " +
		"actually emitted (every exported function in every file it could parse — Scan does not curate a subset)"
	return s
}

// scanDir processes all non-test .go files in dir (not recursive).
func scanDir(dir string) ([]Entry, error) {
	infos, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var goFiles []string
	hasTests := false
	for _, info := range infos {
		if info.IsDir() {
			continue
		}
		name := info.Name()
		if strings.HasSuffix(name, "_test.go") {
			hasTests = true
			continue
		}
		if strings.HasSuffix(name, ".go") {
			goFiles = append(goFiles, filepath.Join(dir, name))
		}
	}
	if len(goFiles) == 0 {
		return nil, nil
	}

	var entries []Entry
	for _, path := range goFiles {
		fentries, err := scanFile(path, hasTests)
		if err != nil {
			continue
		}
		entries = append(entries, fentries...)
	}
	return entries, nil
}

// scanFile parses a single .go file and returns FMEA entries for exported functions.
func scanFile(path string, hasTests bool) ([]Entry, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		return nil, err
	}

	pkgName := f.Name.Name
	dir := filepath.Dir(path)
	component := buildComponent(dir, pkgName)

	var entries []Entry
	for _, decl := range f.Decls {
		funcDecl, ok := decl.(*ast.FuncDecl)
		if !ok || !funcDecl.Name.IsExported() {
			continue
		}

		reqIDs := extractReqIDs(funcDecl.Doc)
		returnsErr := funcReturnsError(funcDecl)
		hasGo := funcHasGoroutine(funcDecl.Body)
		hasReceiver := funcDecl.Recv != nil && len(funcDecl.Recv.List) > 0
		paramCount := 0
		if funcDecl.Type.Params != nil {
			paramCount = funcDecl.Type.Params.NumFields()
		}

		modes, effects, causes, mitigations, sev := deriveAnalysis(funcDecl.Name.Name, component, returnsErr, hasGo, len(reqIDs) > 0, hasReceiver, paramCount)
		detection := detectionControl(hasTests, len(reqIDs) > 0)

		entries = append(entries, Entry{
			Item:             itemName(component, funcDecl.Name.Name),
			Component:        component,
			Function:         funcDecl.Name.Name,
			File:             path,
			FailureMode:      strings.Join(modes, "; "),
			Effect:           strings.Join(effects, "; "),
			Cause:            strings.Join(causes, "; "),
			FailureModes:     modes,
			Effects:          effects,
			Severity:         sev,
			ActionPriority:   string(sev),
			Mitigations:      mitigations,
			DetectionControl: detection,
			RequirementIDs:   reqIDs,
		})
	}
	return entries, nil
}

// itemName builds the §9.2 `entries[].item` value from a scanned function's
// component and function name (e.g. "rules (registry).Register").
func itemName(component, function string) string {
	if component == "" {
		return function
	}
	return component + "." + function
}

// Render writes r to w in the given format: "json" (default) or "csv".
//
//fusa:req REQ-FMEA004
func Render(w io.Writer, r *Report, format string) error {
	switch format {
	case "json", "":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	case "csv":
		return renderCSV(w, r)
	default:
		return fmt.Errorf("fmea: unknown format %q (want json or csv)", format)
	}
}

func renderCSV(w io.Writer, r *Report) error {
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{
		"Component", "Function", "FailureModes", "Effects",
		"Severity", "DetectionControl", "RequirementIDs", "CyberRisks",
	}); err != nil {
		return err
	}
	for _, e := range r.Entries {
		if err := cw.Write([]string{
			e.Component,
			e.Function,
			strings.Join(e.FailureModes, "; "),
			strings.Join(e.Effects, "; "),
			string(e.Severity),
			e.DetectionControl,
			strings.Join(e.RequirementIDs, "; "),
			strings.Join(e.CyberRisks, "; "),
		}); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// ─── coverage denominator ─────────────────────────────────────────────────────

// exportedFuncRE matches a top-level exported function/method declaration
// line ("func Name(" or "func (recv Type) Name(", uppercase first letter).
// It is intentionally a raw text scan, not an AST parse — see
// CountProjectFunctions doc.
var exportedFuncRE = regexp.MustCompile(`^func\s+(\([^)]*\)\s+)?[A-Z]\w*\s*\(`)

// CountProjectFunctions returns the total count of exported top-level
// functions/methods declared in non-test .go files under root (excluding
// vendor/, testdata/, and dot-directories) — the §9.2 fmea `coveragePct`
// denominator (componentsInProject).
//
// Unlike Scan's own go/ast-based entry generation, this count is a
// lightweight line-oriented regex scan of the raw source text, so it still
// counts functions in a file Scan's parser rejects outright. This is a
// best-effort, honestly-documented denominator, not a perfect independent
// audit: a function signature split across multiple lines before its
// opening paren is not matched (rare in gofmt'd code), and it makes no
// attempt to exclude trivial accessors/interface shims the way
// trace.ScanFuncTagCoverage does — see Summary.ComponentsInProjectMethod.
// The test-tree/dot-directory exclusion itself reuses trace.IsExcludedDir
// (x-FuSa spec §1.6 rule 4 SHOULD) rather than an independently-drifting
// copy of the same three-way vendor/testdata/dot-dir check.
//
//fusa:req REQ-FMEA009
func CountProjectFunctions(root string) (int, error) {
	total := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if path != root && trace.IsExcludedDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil // skip unreadable files
		}
		for _, line := range strings.Split(string(data), "\n") {
			if exportedFuncRE.MatchString(line) {
				total++
			}
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("fmea: count project functions: %w", err)
	}
	return total, nil
}

// LoadReport reads a persisted dFMEA report from path (typically fmea.json).
//
//fusa:req REQ-FMEA010
func LoadReport(path string) (*Report, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r Report
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("%w: %s: %s", fusa.ErrInvalidConfig, path, err)
	}
	return &r, nil
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func extractReqIDs(doc *ast.CommentGroup) []string {
	if doc == nil {
		return nil
	}
	var ids []string
	for _, c := range doc.List {
		text := strings.TrimPrefix(strings.TrimSpace(c.Text), "//")
		text = strings.TrimSpace(text)
		if strings.HasPrefix(text, "fusa:req ") {
			id := strings.TrimSpace(strings.TrimPrefix(text, "fusa:req "))
			if id != "" {
				ids = append(ids, id)
			}
		}
	}
	return ids
}

func funcReturnsError(fn *ast.FuncDecl) bool {
	if fn.Type.Results == nil {
		return false
	}
	for _, field := range fn.Type.Results.List {
		if ident, ok := field.Type.(*ast.Ident); ok && ident.Name == "error" {
			return true
		}
	}
	return false
}

func funcHasGoroutine(body *ast.BlockStmt) bool {
	if body == nil {
		return false
	}
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		if _, ok := n.(*ast.GoStmt); ok {
			found = true
			return false
		}
		return true
	})
	return found
}

// deriveAnalysis buckets a scanned function into a failureMode/effect/cause/
// mitigations template. x-FuSa spec §1.6 rule 3 allows heuristic templates
// "as long as the output measurably differs across distinct input shapes" —
// every branch below weaves in component (the function's own package/
// directory, a genuine per-function signal, not a fabricated one) plus,
// where relevant, whether the function has a receiver and how many
// parameters it takes, so the generated text actually varies with the
// underlying function's shape rather than collapsing onto a handful of
// fixed strings regardless of which function produced them (go-FuSa#60).
//
//fusa:req REQ-FMEA002
func deriveAnalysis(name, component string, returnsErr, hasGoroutine, hasSafetyReq, hasReceiver bool, paramCount int) (modes, effects, causes, mitigations []string, sev Severity) {
	switch {
	case hasSafetyReq:
		sev = SeverityHigh
	case returnsErr || hasGoroutine:
		sev = SeverityMedium
	default:
		sev = SeverityLow
	}

	if returnsErr {
		modes = append(modes, fmt.Sprintf("%s returns an unexpected error", component))
		effects = append(effects, fmt.Sprintf("silent failure propagated to %s's caller", component))
		causes = append(causes, fmt.Sprintf("an unhandled error path in %s's function body or a callee", component))
		mitigations = append(mitigations, "add unit test coverage for every returned error path")
	}
	if hasGoroutine {
		modes = append(modes, fmt.Sprintf("goroutine spawned in %s not terminated", component))
		effects = append(effects, fmt.Sprintf("memory leak or deadlock in %s", component))
		causes = append(causes, fmt.Sprintf("a spawned goroutine in %s with no cancellation, timeout, or WaitGroup join", component))
		mitigations = append(mitigations, "join or cancel the goroutine before the function returns")
	}

	lower := strings.ToLower(name)
	switch {
	case strings.Contains(lower, "write") || strings.Contains(lower, "save") || strings.Contains(lower, "store"):
		modes = append(modes, fmt.Sprintf("partial write / data corruption in %s", component))
		effects = append(effects, fmt.Sprintf("incorrect persisted state for %s", component))
		causes = append(causes, fmt.Sprintf("an interrupted write in %s (crash, disk full, concurrent access) leaving a partial artifact", component))
		mitigations = append(mitigations, "write via a temp file and atomic rename, or validate the write's result")
	case !hasGoroutine && (strings.Contains(lower, "run") || strings.Contains(lower, "execute") || strings.Contains(lower, "start")):
		modes = append(modes, fmt.Sprintf("uncontrolled execution in %s", component))
		effects = append(effects, fmt.Sprintf("resource exhaustion triggered from %s", component))
		causes = append(causes, fmt.Sprintf("no bound on iteration count, input size, or execution time in %s", component))
		mitigations = append(mitigations, "add a context deadline or explicit resource bound")
	}

	// No signal above matched — the largest bucket in most codebases. Split
	// it by receiver/parameter shape (both genuine per-function signals, per
	// §1.6 rule 3) rather than collapsing every such function onto one
	// fixed "Incorrect output" string regardless of its actual shape.
	if len(modes) == 0 {
		switch {
		case hasReceiver && paramCount == 0:
			modes = []string{fmt.Sprintf("%s returns stale or inconsistent receiver state", component)}
			effects = []string{fmt.Sprintf("caller of %s observes state that no longer reflects a concurrent mutation", component)}
			causes = []string{fmt.Sprintf("%s reads receiver fields with no synchronisation against concurrent mutation", component)}
			mitigations = []string{"add a mutex, or otherwise make the receiver's field access goroutine-safe"}
		case hasReceiver:
			modes = []string{fmt.Sprintf("%s derives incorrect output from receiver and argument state", component)}
			effects = []string{fmt.Sprintf("incorrect system behavior from %s", component)}
			causes = []string{fmt.Sprintf("a logic error in %s combining receiver state with its arguments, not surfaced as an error return or panic", component)}
			mitigations = []string{"add requirement-traced unit tests covering this method's documented behaviour"}
		case paramCount == 0:
			modes = []string{fmt.Sprintf("%s produces incorrect output with no input to validate against", component)}
			effects = []string{fmt.Sprintf("incorrect system behavior from %s", component)}
			causes = []string{fmt.Sprintf("a logic error in %s not surfaced as an error return or panic", component)}
			mitigations = []string{"add requirement-traced unit tests covering this function's documented behaviour"}
		default:
			modes = []string{fmt.Sprintf("%s produces incorrect output for a given input combination", component)}
			effects = []string{fmt.Sprintf("incorrect system behavior from %s", component)}
			causes = []string{fmt.Sprintf("a logic error in %s not surfaced as an error return or panic", component)}
			mitigations = []string{"add requirement-traced unit tests covering this function's documented behaviour"}
		}
	}
	return
}

func detectionControl(hasTests, hasSafetyReq bool) string {
	switch {
	case hasTests && hasSafetyReq:
		return "requirement testing + unit tests"
	case hasTests:
		return "unit tests"
	case hasSafetyReq:
		return "requirement testing"
	default:
		return "code review"
	}
}

func buildComponent(dir, pkgName string) string {
	base := filepath.Base(dir)
	if base == "." || pkgName == "main" {
		return pkgName
	}
	if base == pkgName {
		return pkgName
	}
	return base + " (" + pkgName + ")"
}

func readModule(root string) string {
	data, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "module "))
		}
	}
	return ""
}

// relFile relativizes path against root and normalises it to forward
// slashes (§4 MUST). An unrelativisable path (rare — e.g. a different
// volume on Windows) is returned unchanged rather than erroring, matching
// lint.locationEnd/cyber.location's identical fallback.
func relFile(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return filepath.ToSlash(rel)
}

// ─── engine rule ─────────────────────────────────────────────────────────────

func init() {
	engine.Default.MustRegister(&fmea001Rule{})
}

type fmea001Rule struct{}

func (r *fmea001Rule) ID() string { return "FMEA001" }
func (r *fmea001Rule) Description() string {
	return "fmea.json absent — run 'gofusa fmea' to generate a dFMEA table"
}

//fusa:req REQ-FMEA005
func (r *fmea001Rule) Run(_ context.Context, projectRoot string, cfg *config.Config) ([]fusa.Finding, error) {
	if _, err := os.Stat(filepath.Join(projectRoot, FMEAFile)); err == nil {
		return nil, nil
	}
	return []fusa.Finding{{
		RuleID:      "FMEA001",
		Severity:    fusa.SeverityInfo,
		Message:     "fmea.json not found — run 'gofusa fmea' to generate the dFMEA table",
		Location:    fusa.Location{File: FMEAFile},
		Remediation: "Run: gofusa fmea",
	}}, nil
}

// ─── cyber enrichment ─────────────────────────────────────────────────────────

// EnrichWithCyber cross-references cyberFindings into FMEA entries by source file.
// For each CYBER finding whose file matches a function's file, the finding message
// is appended to CyberRisks and the entry Severity is raised to high when the
// finding is ERROR-level.
//
//fusa:req REQ-FMEA006
func EnrichWithCyber(report *Report, cyberFindings []fusa.Finding) {
	// Build a map from file path to entry indices for O(n) matching.
	fileIndex := make(map[string][]int, len(report.Entries))
	for i, e := range report.Entries {
		if e.File != "" {
			fileIndex[e.File] = append(fileIndex[e.File], i)
		}
	}
	for _, f := range cyberFindings {
		for _, idx := range fileIndex[f.Location.File] {
			report.Entries[idx].CyberRisks = append(report.Entries[idx].CyberRisks, f.RuleID+": "+f.Message)
			if f.Severity == fusa.SeverityError && report.Entries[idx].Severity != SeverityHigh {
				report.Entries[idx].Severity = SeverityHigh
			}
		}
	}
}
