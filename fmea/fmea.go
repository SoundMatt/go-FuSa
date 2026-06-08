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
	"sort"
	"strings"
	"time"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/config"
	"github.com/SoundMatt/go-FuSa/engine"
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
//fusa:req REQ-FMEA001
type Entry struct {
	Component        string   `json:"component"`
	Function         string   `json:"function"`
	FailureModes     []string `json:"failure_modes"`
	Effects          []string `json:"effects"`
	Severity         Severity `json:"severity"`
	DetectionControl string   `json:"detection_control"`
	RequirementIDs   []string `json:"requirement_ids,omitempty"`
}

// Report is the complete dFMEA output for a project.
type Report struct {
	Format      string    `json:"format"`
	GeneratedAt time.Time `json:"generated_at"`
	Module      string    `json:"module"`
	Entries     []Entry   `json:"entries"`
}

// Scan walks projectRoot, parses exported Go functions, and returns a dFMEA report.
// Vendor, testdata, and hidden directories are skipped.
//
//fusa:req REQ-FMEA001
//fusa:req REQ-FMEA002
//fusa:req REQ-FMEA003
func Scan(projectRoot string) (*Report, error) {
	report := &Report{
		Format:      "go-FuSa dFMEA v1",
		GeneratedAt: time.Now().UTC(),
		Module:      readModule(projectRoot),
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

	return report, nil
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

		modes, effects, sev := deriveAnalysis(funcDecl.Name.Name, returnsErr, hasGo, len(reqIDs) > 0)
		detection := detectionControl(hasTests, len(reqIDs) > 0)

		entries = append(entries, Entry{
			Component:        component,
			Function:         funcDecl.Name.Name,
			FailureModes:     modes,
			Effects:          effects,
			Severity:         sev,
			DetectionControl: detection,
			RequirementIDs:   reqIDs,
		})
	}
	return entries, nil
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
		"Severity", "DetectionControl", "RequirementIDs",
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
		}); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
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

//fusa:req REQ-FMEA002
func deriveAnalysis(name string, returnsErr, hasGoroutine, hasSafetyReq bool) (modes, effects []string, sev Severity) {
	switch {
	case hasSafetyReq:
		sev = SeverityHigh
	case returnsErr || hasGoroutine:
		sev = SeverityMedium
	default:
		sev = SeverityLow
	}

	if returnsErr {
		modes = append(modes, "Returns unexpected error")
		effects = append(effects, "Silent failure propagated to caller")
	}
	if hasGoroutine {
		modes = append(modes, "Goroutine not terminated")
		effects = append(effects, "Memory leak or deadlock")
	}

	lower := strings.ToLower(name)
	if strings.Contains(lower, "write") || strings.Contains(lower, "save") || strings.Contains(lower, "store") {
		modes = append(modes, "Partial write / data corruption")
		effects = append(effects, "Incorrect system state")
	} else if !hasGoroutine && (strings.Contains(lower, "run") || strings.Contains(lower, "execute") || strings.Contains(lower, "start")) {
		modes = append(modes, "Uncontrolled execution")
		effects = append(effects, "Resource exhaustion")
	}

	if len(modes) == 0 {
		modes = []string{"Incorrect output"}
		effects = []string{"Incorrect system behavior"}
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
