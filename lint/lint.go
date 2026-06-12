// Package lint provides go-FuSa coding-standard checks (v0.2).
//
// Rules are registered with engine.Default on package import via init.
// Activate by importing this package for its side effects:
//
//	import _ "github.com/SoundMatt/go-FuSa/lint"
//
// Rules in this package use go/ast and go/parser from the standard library
// and require no external dependencies.
package lint

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/config"
	"github.com/SoundMatt/go-FuSa/engine"
)

func init() {
	engine.Default.MustRegister(&ruleNoDiscardedErrors{})
	engine.Default.MustRegister(&rulePanicDetect{})
	engine.Default.MustRegister(&ruleRecoverInventory{})
	engine.Default.MustRegister(&ruleUnsafeInventory{})
	engine.Default.MustRegister(&ruleReflectInventory{})
	engine.Default.MustRegister(&ruleGlobalMutableState{})
}

// ParsedFile holds a parsed AST file together with its file set.
type ParsedFile struct {
	File *ast.File
	Fset *token.FileSet
}

// parseProject walks projectRoot and returns parsed .go files.
// Files that fail to parse are silently skipped (parse errors in foreign
// code must not abort the safety check run).
func parseProject(projectRoot string) ([]ParsedFile, error) {
	fset := token.NewFileSet()
	var results []ParsedFile

	err := filepath.WalkDir(projectRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if name == "vendor" || name == "testdata" || strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		f, parseErr := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if parseErr != nil {
			return nil // skip unparseable files
		}
		results = append(results, ParsedFile{File: f, Fset: fset})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return results, nil
}

func locationEnd(fset *token.FileSet, pos, end token.Pos, projectRoot string) fusa.Location {
	p := fset.Position(pos)
	e := fset.Position(end)
	rel, err := filepath.Rel(projectRoot, p.Filename)
	if err != nil {
		rel = p.Filename
	}
	return fusa.Location{File: filepath.ToSlash(rel), Line: p.Line, Column: p.Column, EndLine: e.Line, EndColumn: e.Column}
}

// ─── LINT001: no discarded error returns ─────────────────────────────────────

// ruleNoDiscardedErrors flags assignment statements where the blank identifier
// _ appears on the left-hand side of a multi-value assignment whose RHS is a
// single call expression. This pattern is the most common way error returns
// are silently discarded in Go code.
type ruleNoDiscardedErrors struct{}

func (r *ruleNoDiscardedErrors) ID() string { return "LINT001" }
func (r *ruleNoDiscardedErrors) Description() string {
	return "Blank identifier must not discard a return value in a call assignment."
}

//fusa:req REQ-LINT001
func (r *ruleNoDiscardedErrors) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	pfs, err := parseProject(projectRoot)
	if err != nil {
		return nil, err
	}
	var findings []fusa.Finding
	for _, pf := range pfs {
		ast.Inspect(pf.File, func(n ast.Node) bool {
			assign, ok := n.(*ast.AssignStmt)
			if !ok || len(assign.Rhs) != 1 {
				return true
			}
			if _, isCall := assign.Rhs[0].(*ast.CallExpr); !isCall {
				return true
			}
			if len(assign.Lhs) < 2 {
				return true // single return: discard is always intentional
			}
			for _, lhs := range assign.Lhs {
				ident, ok := lhs.(*ast.Ident)
				if ok && ident.Name == "_" {
					findings = append(findings, fusa.Finding{
						RuleID:      r.ID(),
						Severity:    fusa.SeverityWarning,
						Message:     "return value discarded with blank identifier in multi-value call",
						Location:    locationEnd(pf.Fset, assign.Pos(), assign.End(), projectRoot),
						Remediation: "assign all return values to named variables and handle each explicitly",
					})
					return true
				}
			}
			return true
		})
	}
	return findings, nil
}

// ─── LINT002: panic detection ─────────────────────────────────────────────────

type rulePanicDetect struct{}

func (r *rulePanicDetect) ID() string { return "LINT002" }
func (r *rulePanicDetect) Description() string {
	return "panic() calls must be explicitly reviewed and justified in safety-critical code."
}

//fusa:req REQ-LINT002
func (r *rulePanicDetect) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	pfs, err := parseProject(projectRoot)
	if err != nil {
		return nil, err
	}
	var findings []fusa.Finding
	for _, pf := range pfs {
		ast.Inspect(pf.File, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			ident, ok := call.Fun.(*ast.Ident)
			if !ok || ident.Name != "panic" {
				return true
			}
			findings = append(findings, fusa.Finding{
				RuleID:      r.ID(),
				Severity:    fusa.SeverityWarning,
				Message:     "panic() call detected",
				Location:    locationEnd(pf.Fset, call.Pos(), call.End(), projectRoot),
				Remediation: "replace panic with an explicit error return; document any remaining panic usage",
			})
			return true
		})
	}
	return findings, nil
}

// ─── LINT003: recover inventory ───────────────────────────────────────────────

type ruleRecoverInventory struct{}

func (r *ruleRecoverInventory) ID() string { return "LINT003" }
func (r *ruleRecoverInventory) Description() string {
	return "recover() calls are inventoried to verify correct usage within deferred functions."
}

//fusa:req REQ-LINT003
func (r *ruleRecoverInventory) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	pfs, err := parseProject(projectRoot)
	if err != nil {
		return nil, err
	}
	var findings []fusa.Finding
	for _, pf := range pfs {
		ast.Inspect(pf.File, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			ident, ok := call.Fun.(*ast.Ident)
			if !ok || ident.Name != "recover" {
				return true
			}
			findings = append(findings, fusa.Finding{
				RuleID:      r.ID(),
				Severity:    fusa.SeverityInfo,
				Message:     "recover() call inventoried — verify it is inside a deferred function",
				Location:    locationEnd(pf.Fset, call.Pos(), call.End(), projectRoot),
				Remediation: "ensure recover() is called only inside a function passed to defer",
			})
			return true
		})
	}
	return findings, nil
}

// ─── LINT004: unsafe package inventory ───────────────────────────────────────

type ruleUnsafeInventory struct{}

func (r *ruleUnsafeInventory) ID() string { return "LINT004" }
func (r *ruleUnsafeInventory) Description() string {
	return `Import of "unsafe" is inventoried and must be justified.`
}

//fusa:req REQ-LINT004
func (r *ruleUnsafeInventory) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	pfs, err := parseProject(projectRoot)
	if err != nil {
		return nil, err
	}
	var findings []fusa.Finding
	for _, pf := range pfs {
		for _, imp := range pf.File.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			if path == "unsafe" {
				findings = append(findings, fusa.Finding{
					RuleID:      r.ID(),
					Severity:    fusa.SeverityWarning,
					Message:     `import of "unsafe" package detected`,
					Location:    locationEnd(pf.Fset, imp.Pos(), imp.End(), projectRoot),
					Remediation: "document justification for unsafe usage; avoid in safety-critical code paths",
				})
			}
		}
	}
	return findings, nil
}

// ─── LINT005: reflect inventory ───────────────────────────────────────────────

type ruleReflectInventory struct{}

func (r *ruleReflectInventory) ID() string { return "LINT005" }
func (r *ruleReflectInventory) Description() string {
	return `Import of "reflect" is inventoried; reflection reduces code auditability.`
}

//fusa:req REQ-LINT005
func (r *ruleReflectInventory) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	pfs, err := parseProject(projectRoot)
	if err != nil {
		return nil, err
	}
	var findings []fusa.Finding
	for _, pf := range pfs {
		for _, imp := range pf.File.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			if path == "reflect" {
				findings = append(findings, fusa.Finding{
					RuleID:      r.ID(),
					Severity:    fusa.SeverityInfo,
					Message:     `import of "reflect" package inventoried`,
					Location:    locationEnd(pf.Fset, imp.Pos(), imp.End(), projectRoot),
					Remediation: "prefer explicit type handling over reflection in safety-critical code",
				})
			}
		}
	}
	return findings, nil
}

// ─── LINT006: global mutable state ───────────────────────────────────────────

type ruleGlobalMutableState struct{}

func (r *ruleGlobalMutableState) ID() string { return "LINT006" }
func (r *ruleGlobalMutableState) Description() string {
	return "Package-level var declarations introduce global mutable state; each must be justified."
}

//fusa:req REQ-LINT006
func (r *ruleGlobalMutableState) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	pfs, err := parseProject(projectRoot)
	if err != nil {
		return nil, err
	}
	var findings []fusa.Finding
	for _, pf := range pfs {
		for _, decl := range pf.File.Decls {
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
					if name.Name == "_" {
						continue
					}
					findings = append(findings, fusa.Finding{
						RuleID:   r.ID(),
						Severity: fusa.SeverityInfo,
						Message:  "package-level var " + name.Name + " introduces global mutable state",
						Location: locationEnd(pf.Fset, vs.Pos(), vs.End(), projectRoot),
						Remediation: "prefer passing state explicitly; document justification for " +
							"any global variable (registries, once-initialised singletons are acceptable)",
					})
				}
			}
		}
	}
	return findings, nil
}
