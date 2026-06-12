package analyze

import (
	"context"
	"fmt"
	"go/ast"
	"go/token"
	"strings"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/config"
	"github.com/SoundMatt/go-FuSa/engine"
)

func init() {
	engine.Default.MustRegister(&ruleContextDropped{})
	engine.Default.MustRegister(&ruleErrorNotWrapped{})
	engine.Default.MustRegister(&ruleNilDerefRisk{})
	engine.Default.MustRegister(&ruleGoroutineSharedVar{})
}

// ─── ANA005: context dropped ──────────────────────────────────────────────────

// ruleContextDropped flags functions that accept a context.Context parameter
// but create a new background/TODO context inside rather than propagating it.
type ruleContextDropped struct{}

func (r *ruleContextDropped) ID() string { return "ANA005" }
func (r *ruleContextDropped) Description() string {
	return "context.Background()/TODO() called inside a function that already has a context parameter — context is dropped."
}

//fusa:req REQ-ANA005
func (r *ruleContextDropped) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	pfs, err := parseProject(projectRoot)
	if err != nil {
		return nil, err
	}
	var findings []fusa.Finding
	for _, pf := range pfs {
		ast.Inspect(pf.file, func(n ast.Node) bool {
			fn, ok := funcBodyAndParams(n)
			if !ok {
				return true
			}
			if !hasContextParam(fn.params) {
				return true
			}
			ast.Inspect(fn.body, func(inner ast.Node) bool {
				call, ok := inner.(*ast.CallExpr)
				if !ok {
					return true
				}
				if isSelectorCall(call, "context", "Background") || isSelectorCall(call, "context", "TODO") {
					findings = append(findings, fusa.Finding{
						RuleID:      r.ID(),
						Severity:    fusa.SeverityWarning,
						Message:     "context.Background()/TODO() called inside function that has a context parameter — propagate the incoming context instead",
						Location:    locationEnd(pf.fset, call.Pos(), call.End(), projectRoot),
						Remediation: "pass the incoming context.Context to downstream calls instead of creating a new one",
					})
				}
				return true
			})
			return true
		})
	}
	return findings, nil
}

type funcNode struct {
	params *ast.FieldList
	body   *ast.BlockStmt
}

func funcBodyAndParams(n ast.Node) (funcNode, bool) {
	switch fn := n.(type) {
	case *ast.FuncDecl:
		if fn.Body == nil {
			return funcNode{}, false
		}
		return funcNode{params: fn.Type.Params, body: fn.Body}, true
	case *ast.FuncLit:
		return funcNode{params: fn.Type.Params, body: fn.Body}, true
	}
	return funcNode{}, false
}

func hasContextParam(fields *ast.FieldList) bool {
	if fields == nil {
		return false
	}
	for _, f := range fields.List {
		sel, ok := f.Type.(*ast.SelectorExpr)
		if ok && isIdent(sel.X, "context") && sel.Sel.Name == "Context" {
			return true
		}
	}
	return false
}

// ─── ANA006: error not wrapped ────────────────────────────────────────────────

// ruleErrorNotWrapped flags fmt.Errorf calls that do not use %w, which means
// callers cannot use errors.Is/As to inspect the underlying error.
type ruleErrorNotWrapped struct{}

func (r *ruleErrorNotWrapped) ID() string { return "ANA006" }
func (r *ruleErrorNotWrapped) Description() string {
	return "fmt.Errorf without %%w loses error chain; callers cannot use errors.Is/As."
}

//fusa:req REQ-ANA006
func (r *ruleErrorNotWrapped) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	pfs, err := parseProject(projectRoot)
	if err != nil {
		return nil, err
	}
	var findings []fusa.Finding
	for _, pf := range pfs {
		ast.Inspect(pf.file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if !isSelectorCall(call, "fmt", "Errorf") {
				return true
			}
			if len(call.Args) == 0 {
				return true
			}
			// Check the first string literal argument for %w.
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok {
				return true
			}
			if lit.Kind != token.STRING {
				return true
			}
			fmtStr := strings.Trim(lit.Value, "`\"")
			if !strings.Contains(fmtStr, "%w") {
				findings = append(findings, fusa.Finding{
					RuleID:      r.ID(),
					Severity:    fusa.SeverityInfo,
					Message:     fmt.Sprintf("fmt.Errorf format string %q does not wrap error with %%w", fmtStr),
					Location:    locationEnd(pf.fset, call.Pos(), call.End(), projectRoot),
					Remediation: "add %w to the format string to preserve the error chain for errors.Is/As",
				})
			}
			return true
		})
	}
	return findings, nil
}

// ─── ANA007: nil dereference risk ────────────────────────────────────────────

// ruleNilDerefRisk flags assignments from two-return-value function calls
// (val, err := f()) where the non-error value is used on the very next line
// without an intervening error check.
type ruleNilDerefRisk struct{}

func (r *ruleNilDerefRisk) ID() string { return "ANA007" }
func (r *ruleNilDerefRisk) Description() string {
	return "Value from two-result function used without checking err — nil dereference risk."
}

//fusa:req REQ-ANA007
func (r *ruleNilDerefRisk) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	pfs, err := parseProject(projectRoot)
	if err != nil {
		return nil, err
	}
	var findings []fusa.Finding
	for _, pf := range pfs {
		ast.Inspect(pf.file, func(n ast.Node) bool {
			fn, ok := funcBodyAndParams(n)
			if !ok {
				return true
			}
			stmts := fn.body.List
			for i, stmt := range stmts {
				assign, ok := stmt.(*ast.AssignStmt)
				if !ok || len(assign.Lhs) != 2 || len(assign.Rhs) != 1 {
					continue
				}
				// Must be val, err := call()
				errIdent, ok := assign.Lhs[1].(*ast.Ident)
				if !ok || (errIdent.Name != "err" && errIdent.Name != "_") {
					continue
				}
				if _, isCall := assign.Rhs[0].(*ast.CallExpr); !isCall {
					continue
				}
				valIdent, ok := assign.Lhs[0].(*ast.Ident)
				if !ok {
					continue
				}
				if i+1 >= len(stmts) {
					continue
				}
				// Next statement must NOT be an error check.
				next := stmts[i+1]
				if isErrCheck(next, errIdent.Name) {
					continue
				}
				// Next statement must USE the value (member access or method call).
				if stmtUsesIdent(next, valIdent.Name) {
					findings = append(findings, fusa.Finding{
						RuleID:      r.ID(),
						Severity:    fusa.SeverityWarning,
						Message:     fmt.Sprintf("value %q from function call used before checking err — potential nil dereference", valIdent.Name),
						Location:    locationEnd(pf.fset, assign.Pos(), assign.End(), projectRoot),
						Remediation: "check err != nil before using the returned value",
					})
				}
			}
			return true
		})
	}
	return findings, nil
}

func isErrCheck(stmt ast.Stmt, errName string) bool {
	ifStmt, ok := stmt.(*ast.IfStmt)
	if !ok {
		return false
	}
	return stmtUsesIdent(ifStmt.Cond, errName)
}

func stmtUsesIdent(node ast.Node, name string) bool {
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && id.Name == name {
			found = true
			return false
		}
		return true
	})
	return found
}

// ─── ANA008: goroutine shared variable ───────────────────────────────────────

// ruleGoroutineSharedVar flags goroutine function literals that access
// package-level variable names without going through sync primitives,
// which is a common data-race pattern.
type ruleGoroutineSharedVar struct{}

func (r *ruleGoroutineSharedVar) ID() string { return "ANA008" }
func (r *ruleGoroutineSharedVar) Description() string {
	return "Goroutine accesses a package-level variable without synchronisation — potential data race."
}

//fusa:req REQ-ANA008
func (r *ruleGoroutineSharedVar) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	pfs, err := parseProject(projectRoot)
	if err != nil {
		return nil, err
	}
	var findings []fusa.Finding
	for _, pf := range pfs {
		pkgVars := packageLevelVarNames(pf.file)
		if len(pkgVars) == 0 {
			continue
		}
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
				id, ok := inner.(*ast.Ident)
				if !ok {
					return true
				}
				if _, shared := pkgVars[id.Name]; shared {
					findings = append(findings, fusa.Finding{
						RuleID:      r.ID(),
						Severity:    fusa.SeverityWarning,
						Message:     fmt.Sprintf("goroutine accesses package-level variable %q — protect with sync.Mutex or use atomic", id.Name),
						Location:    locationEnd(pf.fset, id.Pos(), id.End(), projectRoot),
						Remediation: "protect shared state with sync.Mutex, sync/atomic, or channel communication",
					})
					return false
				}
				return true
			})
			return true
		})
	}
	return findings, nil
}

func packageLevelVarNames(file *ast.File) map[string]struct{} {
	names := make(map[string]struct{})
	for _, decl := range file.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		if genDecl.Tok != token.VAR {
			continue
		}
		for _, spec := range genDecl.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, name := range vs.Names {
				names[name.Name] = struct{}{}
			}
		}
	}
	return names
}
