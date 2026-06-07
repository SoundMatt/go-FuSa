// Package analyze provides go-FuSa static analysis rules (v0.3).
//
// Rules detect safety-relevant patterns using Go's AST: goroutine lifecycle
// issues, race-prone constructs, blocking calls in goroutines, and resource
// lifecycle problems.
//
// Activate by importing this package for its side effects:
//
//	import _ "github.com/SoundMatt/go-FuSa/analyze"
package analyze

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
	engine.Default.MustRegister(&ruleGoroutineWithoutSignal{})
	engine.Default.MustRegister(&ruleGoroutineInLoop{})
	engine.Default.MustRegister(&ruleBlockingInGoroutine{})
	engine.Default.MustRegister(&ruleDeferInLoop{})
}

// parsedFile holds a parsed AST together with its file set.
type parsedFile struct {
	file *ast.File
	fset *token.FileSet
}

func parseProject(projectRoot string) ([]parsedFile, error) {
	fset := token.NewFileSet()
	var results []parsedFile
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
		f, parseErr := parser.ParseFile(fset, path, nil, 0)
		if parseErr != nil {
			return nil
		}
		results = append(results, parsedFile{file: f, fset: fset})
		return nil
	})
	return results, err
}

func location(fset *token.FileSet, pos token.Pos) fusa.Location {
	p := fset.Position(pos)
	return fusa.Location{File: p.Filename, Line: p.Line, Column: p.Column}
}

// isIdent reports whether expr is an identifier with the given name.
func isIdent(expr ast.Expr, name string) bool {
	id, ok := expr.(*ast.Ident)
	return ok && id.Name == name
}

// isSelectorCall reports whether a CallExpr is pkg.Func.
func isSelectorCall(call *ast.CallExpr, pkg, fn string) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	return ok && isIdent(sel.X, pkg) && sel.Sel.Name == fn
}

// ─── ANA001: goroutine without termination signal ─────────────────────────────

// ruleGoroutineWithoutSignal flags "go func() { ... }()" literals that accept
// no parameters (capturing from closure only) and contain no select statement.
// Such goroutines have no visible mechanism to receive a cancellation signal.
type ruleGoroutineWithoutSignal struct{}

func (r *ruleGoroutineWithoutSignal) ID() string { return "ANA001" }
func (r *ruleGoroutineWithoutSignal) Description() string {
	return "Goroutine function literals without parameters or select may lack a termination signal."
}

func (r *ruleGoroutineWithoutSignal) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	pfs, err := parseProject(projectRoot)
	if err != nil {
		return nil, err
	}
	var findings []fusa.Finding
	for _, pf := range pfs {
		ast.Inspect(pf.file, func(n ast.Node) bool {
			goStmt, ok := n.(*ast.GoStmt)
			if !ok {
				return true
			}
			call, ok := goStmt.Call.Fun.(*ast.FuncLit)
			if !ok {
				return true
			}
			// Flag only zero-parameter func literals.
			if call.Type.Params.NumFields() != 0 {
				return true
			}
			// If the body contains a select statement, we assume it handles signals.
			if bodyContainsSelect(call.Body) {
				return true
			}
			// If the body references "ctx" or a done channel, suppress.
			if bodyReferencesSignal(call.Body) {
				return true
			}
			findings = append(findings, fusa.Finding{
				RuleID:      r.ID(),
				Severity:    fusa.SeverityWarning,
				Message:     "goroutine launched without visible termination signal",
				Location:    location(pf.fset, goStmt.Pos()),
				Remediation: "pass a context.Context or done <-chan struct{} parameter to allow cancellation",
			})
			return true
		})
	}
	return findings, nil
}

func bodyContainsSelect(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if _, ok := n.(*ast.SelectStmt); ok {
			found = true
			return false
		}
		return true
	})
	return found
}

func bodyReferencesSignal(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		ident, ok := n.(*ast.Ident)
		if !ok {
			return true
		}
		if ident.Name == "ctx" || ident.Name == "done" || ident.Name == "stop" || ident.Name == "quit" {
			found = true
			return false
		}
		return true
	})
	return found
}

// ─── ANA002: goroutine spawned inside a loop ──────────────────────────────────

// ruleGoroutineInLoop flags "go" statements that appear directly inside a
// for-loop body without a limiting mechanism. This pattern is a common source
// of goroutine leaks when the number of iterations is unbounded.
type ruleGoroutineInLoop struct{}

func (r *ruleGoroutineInLoop) ID() string { return "ANA002" }
func (r *ruleGoroutineInLoop) Description() string {
	return "Goroutine spawned inside a loop without an explicit concurrency bound may cause leaks."
}

func (r *ruleGoroutineInLoop) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	pfs, err := parseProject(projectRoot)
	if err != nil {
		return nil, err
	}
	var findings []fusa.Finding
	for _, pf := range pfs {
		ast.Inspect(pf.file, func(n ast.Node) bool {
			forStmt, ok := n.(*ast.ForStmt)
			if !ok {
				if _, ok2 := n.(*ast.RangeStmt); ok2 {
					// Range loops are covered separately below.
					return true
				}
				return true
			}
			if hasGoInBlock(forStmt.Body) {
				findings = append(findings, fusa.Finding{
					RuleID:      r.ID(),
					Severity:    fusa.SeverityWarning,
					Message:     "goroutine spawned inside for loop — potential unbounded goroutine creation",
					Location:    location(pf.fset, forStmt.Pos()),
					Remediation: "use a semaphore, worker pool, or errgroup to bound concurrency",
				})
			}
			return true
		})
		// Also check range loops.
		ast.Inspect(pf.file, func(n ast.Node) bool {
			rangeStmt, ok := n.(*ast.RangeStmt)
			if !ok {
				return true
			}
			if hasGoInBlock(rangeStmt.Body) {
				findings = append(findings, fusa.Finding{
					RuleID:      r.ID(),
					Severity:    fusa.SeverityWarning,
					Message:     "goroutine spawned inside range loop — potential unbounded goroutine creation",
					Location:    location(pf.fset, rangeStmt.Pos()),
					Remediation: "use a semaphore, worker pool, or errgroup to bound concurrency",
				})
			}
			return true
		})
	}
	return findings, nil
}

// hasGoInBlock reports whether block directly contains a GoStmt (not nested
// inside a function literal, which would be a separate goroutine scope).
func hasGoInBlock(block *ast.BlockStmt) bool {
	for _, stmt := range block.List {
		if _, ok := stmt.(*ast.GoStmt); ok {
			return true
		}
	}
	return false
}

// ─── ANA003: blocking call inside goroutine ───────────────────────────────────

// ruleBlockingInGoroutine flags time.Sleep calls inside goroutine function
// literals. In safety-critical code, goroutines should use select with context
// or done channels rather than unconditional sleeps that cannot be interrupted.
type ruleBlockingInGoroutine struct{}

func (r *ruleBlockingInGoroutine) ID() string { return "ANA003" }
func (r *ruleBlockingInGoroutine) Description() string {
	return "time.Sleep inside a goroutine cannot be interrupted; use select with context or done channel."
}

func (r *ruleBlockingInGoroutine) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	pfs, err := parseProject(projectRoot)
	if err != nil {
		return nil, err
	}
	var findings []fusa.Finding
	for _, pf := range pfs {
		ast.Inspect(pf.file, func(n ast.Node) bool {
			goStmt, ok := n.(*ast.GoStmt)
			if !ok {
				return true
			}
			lit, ok := goStmt.Call.Fun.(*ast.FuncLit)
			if !ok {
				return true
			}
			ast.Inspect(lit.Body, func(inner ast.Node) bool {
				call, ok := inner.(*ast.CallExpr)
				if !ok {
					return true
				}
				if isSelectorCall(call, "time", "Sleep") {
					findings = append(findings, fusa.Finding{
						RuleID:      r.ID(),
						Severity:    fusa.SeverityWarning,
						Message:     "time.Sleep inside goroutine cannot be interrupted",
						Location:    location(pf.fset, call.Pos()),
						Remediation: "replace time.Sleep with select { case <-time.After(d): ... case <-ctx.Done(): ... }",
					})
				}
				return true
			})
			return true
		})
	}
	return findings, nil
}

// ─── ANA004: defer inside loop ────────────────────────────────────────────────

// ruleDeferInLoop flags defer statements appearing directly inside loop bodies.
// Deferred calls execute when the surrounding function returns, not when the
// loop iteration ends, so resources are not released until the function exits.
// This is a common resource-leak pattern in safety-critical code.
type ruleDeferInLoop struct{}

func (r *ruleDeferInLoop) ID() string { return "ANA004" }
func (r *ruleDeferInLoop) Description() string {
	return "defer inside a loop delays resource release until function return, not loop iteration."
}

func (r *ruleDeferInLoop) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	pfs, err := parseProject(projectRoot)
	if err != nil {
		return nil, err
	}
	var findings []fusa.Finding
	for _, pf := range pfs {
		ast.Inspect(pf.file, func(n ast.Node) bool {
			var body *ast.BlockStmt
			var pos token.Pos
			switch stmt := n.(type) {
			case *ast.ForStmt:
				body, pos = stmt.Body, stmt.Pos()
			case *ast.RangeStmt:
				body, pos = stmt.Body, stmt.Pos()
			default:
				return true
			}
			for _, s := range body.List {
				if _, ok := s.(*ast.DeferStmt); ok {
					findings = append(findings, fusa.Finding{
						RuleID:      r.ID(),
						Severity:    fusa.SeverityWarning,
						Message:     "defer inside loop delays resource release until function returns",
						Location:    location(pf.fset, pos),
						Remediation: "extract loop body into a helper function so defer runs each iteration",
					})
					break
				}
			}
			return true
		})
	}
	return findings, nil
}
