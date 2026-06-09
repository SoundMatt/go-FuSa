// Package comp provides cyclomatic complexity analysis for go-FuSa (DO-178C §6.3.4).
//
// COMP001 flags functions whose cyclomatic complexity exceeds a configurable
// threshold. Default thresholds align with DAL levels:
//
//	DAL-A: ≤ 4   (strictest)
//	DAL-B: ≤ 10  (default)
//	DAL-C: ≤ 15
//	DAL-D: ≤ 20
//
// Activate by importing this package for its side effects:
//
//	import _ "github.com/SoundMatt/go-FuSa/comp"
package comp

import (
	"context"
	"fmt"
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

// DefaultThreshold is the maximum cyclomatic complexity before a WARNING is raised.
const DefaultThreshold = 10

func init() {
	engine.Default.MustRegister(&ruleComplexity{})
}

// Complexity returns the cyclomatic complexity of a function body.
// V(G) = 1 + number of branching nodes (if, for, range, case, &&, ||, select case).
//
//fusa:req REQ-COMP001
func Complexity(fn *ast.FuncDecl) int {
	if fn.Body == nil {
		return 0
	}
	return 1 + countBranches(fn.Body)
}

func countBranches(node ast.Node) int {
	count := 0
	ast.Inspect(node, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.IfStmt:
			count++
			count += countLogicalOps(v.Cond)
		case *ast.ForStmt:
			count++
		case *ast.RangeStmt:
			count++
		case *ast.CaseClause:
			if v.List != nil { // non-default case
				count++
			}
		case *ast.CommClause:
			if v.Comm != nil { // non-default select case
				count++
			}
		case *ast.BinaryExpr:
			if v.Op == token.LAND || v.Op == token.LOR {
				count++
			}
		}
		return true
	})
	return count
}

func countLogicalOps(expr ast.Expr) int {
	count := 0
	ast.Inspect(expr, func(n ast.Node) bool {
		if b, ok := n.(*ast.BinaryExpr); ok {
			if b.Op == token.LAND || b.Op == token.LOR {
				count++
			}
		}
		return true
	})
	return count
}

// ─── COMP001 rule ─────────────────────────────────────────────────────────────

type ruleComplexity struct{}

func (r *ruleComplexity) ID() string { return "COMP001" }
func (r *ruleComplexity) Description() string {
	return "Function cyclomatic complexity exceeds threshold (DO-178C §6.3.4)."
}

//fusa:req REQ-COMP001
func (r *ruleComplexity) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	threshold := DefaultThreshold
	fset := token.NewFileSet()
	var findings []fusa.Finding

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
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			cc := Complexity(fn)
			if cc > threshold {
				pos := fset.Position(fn.Pos())
				name := fn.Name.Name
				if fn.Recv != nil && len(fn.Recv.List) > 0 {
					if t, ok2 := fn.Recv.List[0].Type.(*ast.StarExpr); ok2 {
						if id, ok3 := t.X.(*ast.Ident); ok3 {
							name = id.Name + "." + name
						}
					} else if id, ok2 := fn.Recv.List[0].Type.(*ast.Ident); ok2 {
						name = id.Name + "." + name
					}
				}
				findings = append(findings, fusa.Finding{
					RuleID:   r.ID(),
					Severity: fusa.SeverityWarning,
					Message: fmt.Sprintf(
						"function %s has cyclomatic complexity %d (threshold %d) — DO-178C §6.3.4",
						name, cc, threshold,
					),
					Location: fusa.Location{File: pos.Filename, Line: pos.Line},
					Remediation: fmt.Sprintf(
						"refactor %s to reduce branching; consider extracting helper functions", name,
					),
				})
			}
		}
		return nil
	})
	return findings, err
}
