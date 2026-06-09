// Package coupling detects data and control coupling between packages
// (DO-178C §6.4.4.3).
//
// Data coupling: two packages share mutable state via exported package-level
// variables. Control coupling: one package calls into another via a function
// parameter that directly controls flow (function/interface values).
//
// Activate engine rules by importing this package for its side effects:
//
//	import _ "github.com/SoundMatt/go-FuSa/coupling"
package coupling

import (
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"time"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/config"
	"github.com/SoundMatt/go-FuSa/engine"
)

// CouplingReportFile is the default output filename for coupling analysis.
const CouplingReportFile = "coupling-report.json"

// CouplingReport is the persisted coupling analysis evidence artifact.
// It satisfies DO-178C §6.4.4.3 (data and control coupling characterisation).
//
//fusa:req REQ-COUPLING003
type CouplingReport struct {
	GeneratedAt     time.Time      `json:"generatedAt"`
	ProjectRoot     string         `json:"projectRoot"`
	DataCoupling    []fusa.Finding `json:"dataCoupling"`
	ControlCoupling []fusa.Finding `json:"controlCoupling"`
}

// SaveReport writes a CouplingReport as indented JSON to path.
//
//fusa:req REQ-COUPLING003
func SaveReport(path string, data, ctrl []fusa.Finding, projectRoot string) error {
	rep := &CouplingReport{
		GeneratedAt:     time.Now().UTC(),
		ProjectRoot:     projectRoot,
		DataCoupling:    data,
		ControlCoupling: ctrl,
	}
	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return fmt.Errorf("coupling: marshal report: %w", err)
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o640); err != nil {
		return fmt.Errorf("coupling: write %s: %w", path, err)
	}
	return nil
}

func init() {
	engine.Default.MustRegister(&ruleDataCoupling{})
	engine.Default.MustRegister(&ruleControlCoupling{})
	engine.Default.MustRegister(&ruleCouplingReportPresent{})
}

// NewDataCouplingRule returns a COUP001 rule instance for testing.
//
//fusa:req REQ-COUPLING001
func NewDataCouplingRule() engine.Rule { return &ruleDataCoupling{} }

// NewControlCouplingRule returns a COUP002 rule instance for testing.
//
//fusa:req REQ-COUPLING002
func NewControlCouplingRule() engine.Rule { return &ruleControlCoupling{} }

// ─── COUP001: exported mutable package-level variables ────────────────────────

// ruleDataCoupling flags exported package-level variables (non-const) which
// represent uncontrolled data coupling between packages. DO-178C §6.4.4.3.
type ruleDataCoupling struct{}

func (r *ruleDataCoupling) ID() string { return "COUP001" }
func (r *ruleDataCoupling) Description() string {
	return "Exported mutable package-level variable creates uncontrolled data coupling (DO-178C §6.4.4.3)."
}

//fusa:req REQ-COUP001
func (r *ruleDataCoupling) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	pfs, err := parseModuleFiles(projectRoot)
	if err != nil {
		return nil, err
	}
	var findings []fusa.Finding
	for _, pf := range pfs {
		for _, decl := range pf.file.Decls {
			genDecl, ok := decl.(*ast.GenDecl)
			if !ok || genDecl.Tok != token.VAR {
				continue
			}
			for _, spec := range genDecl.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for _, name := range vs.Names {
					if !ast.IsExported(name.Name) {
						continue
					}
					pos := pf.fset.Position(name.Pos())
					findings = append(findings, fusa.Finding{
						RuleID:   r.ID(),
						Severity: fusa.SeverityInfo,
						Message: fmt.Sprintf(
							"exported var %q creates data coupling — callers can read/write shared state directly",
							name.Name,
						),
						Location:    fusa.Location{File: pos.Filename, Line: pos.Line},
						Remediation: "replace exported vars with accessor functions or encapsulate in a struct to control coupling",
					})
				}
			}
		}
	}
	return findings, nil
}

// ─── COUP002: function/interface parameters as control coupling ───────────────

// ruleControlCoupling flags exported functions that accept func or interface
// parameters. Such parameters introduce control coupling: the caller controls
// the flow of the callee. DO-178C §6.4.4.3.
type ruleControlCoupling struct{}

func (r *ruleControlCoupling) ID() string { return "COUP002" }
func (r *ruleControlCoupling) Description() string {
	return "Exported function accepts func/interface parameter — control coupling (DO-178C §6.4.4.3)."
}

//fusa:req REQ-COUP002
func (r *ruleControlCoupling) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	pfs, err := parseModuleFiles(projectRoot)
	if err != nil {
		return nil, err
	}
	var findings []fusa.Finding
	for _, pf := range pfs {
		for _, decl := range pf.file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name == nil || !ast.IsExported(fn.Name.Name) {
				continue
			}
			if fn.Type.Params == nil {
				continue
			}
			for _, field := range fn.Type.Params.List {
				if isFuncOrInterface(field.Type) {
					pos := pf.fset.Position(fn.Pos())
					findings = append(findings, fusa.Finding{
						RuleID:   r.ID(),
						Severity: fusa.SeverityInfo,
						Message: fmt.Sprintf(
							"exported function %q accepts func/interface parameter — documents control coupling",
							fn.Name.Name,
						),
						Location:    fusa.Location{File: pos.Filename, Line: pos.Line},
						Remediation: "document coupling in requirements traceability and verify all injected implementations",
					})
					break
				}
			}
		}
	}
	return findings, nil
}

func isFuncOrInterface(expr ast.Expr) bool {
	switch expr.(type) {
	case *ast.FuncType:
		return true
	case *ast.InterfaceType:
		return true
	}
	return false
}

// ─── helpers ──────────────────────────────────────────────────────────────────

type parsedFile struct {
	file *ast.File
	fset *token.FileSet
}

func parseModuleFiles(projectRoot string) ([]parsedFile, error) {
	fset := token.NewFileSet()
	var results []parsedFile
	err := filepath.WalkDir(projectRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path == projectRoot {
				return nil
			}
			name := d.Name()
			if name == "vendor" || name == "testdata" || strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, parseErr := parser.ParseFile(fset, path, nil, 0)
		if parseErr != nil {
			return nil
		}
		results = append(results, parsedFile{file: f, fset: fset})
		return nil
	})
	return results, err
}

// COUP003 — coupling-report.json not present.
type ruleCouplingReportPresent struct{}

func (r *ruleCouplingReportPresent) ID() string { return "COUP003" }
func (r *ruleCouplingReportPresent) Description() string {
	return "coupling-report.json not found — coupling characterisation evidence required by DO-178C §6.4.4.3."
}

//fusa:req REQ-COUPLING003
func (r *ruleCouplingReportPresent) Run(_ context.Context, projectRoot string, cfg *config.Config) ([]fusa.Finding, error) {
	path := filepath.Join(projectRoot, CouplingReportFile)
	if _, err := os.Stat(path); err == nil {
		return nil, nil
	}
	if cfg == nil || cfg.Project.Standard != "DO178C" {
		return nil, nil // only surface when project is explicitly DO-178C
	}
	return []fusa.Finding{{
		RuleID:      r.ID(),
		Severity:    fusa.SeverityInfo,
		Message:     CouplingReportFile + " not found — coupling characterisation evidence absent",
		Location:    fusa.Location{File: CouplingReportFile},
		Remediation: "run 'gofusa coupling' to generate the coupling evidence report",
	}}, nil
}
