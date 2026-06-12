package analyze

import (
	"context"
	"go/ast"
	"go/token"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/config"
	"github.com/SoundMatt/go-FuSa/engine"
)

func init() {
	engine.Default.MustRegister(&ruleDeadCode{})
}

// ruleDeadCode flags unreachable statements — code following an unconditional
// return, break, continue, or panic within the same block. DO-178C §6.4.4.2
// prohibits dead code at DAL-A/B.
type ruleDeadCode struct{}

func (r *ruleDeadCode) ID() string { return "ANA009" }
func (r *ruleDeadCode) Description() string {
	return "Unreachable statement follows unconditional return/break/continue/panic (DO-178C §6.4.4.2)."
}

//fusa:req REQ-ANA009
func (r *ruleDeadCode) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	pfs, err := parseProject(projectRoot)
	if err != nil {
		return nil, err
	}
	var findings []fusa.Finding
	for _, pf := range pfs {
		ast.Inspect(pf.file, func(n ast.Node) bool {
			block, ok := n.(*ast.BlockStmt)
			if !ok {
				return true
			}
			for i, stmt := range block.List {
				if isTerminating(stmt) && i+1 < len(block.List) {
					next := block.List[i+1]
					if _, isLabel := next.(*ast.LabeledStmt); isLabel {
						continue
					}
					findings = append(findings, fusa.Finding{
						RuleID:      r.ID(),
						Severity:    fusa.SeverityWarning,
						Message:     "unreachable statement after unconditional transfer of control",
						Location:    locationEnd(pf.fset, next.Pos(), next.End()),
						Remediation: "remove dead code — DO-178C §6.4.4.2 prohibits deactivated code at DAL-A/B",
					})
					break
				}
			}
			return true
		})
	}
	return findings, nil
}

// isTerminating reports whether a statement unconditionally transfers control.
func isTerminating(stmt ast.Stmt) bool {
	switch s := stmt.(type) {
	case *ast.ReturnStmt:
		return true
	case *ast.BranchStmt:
		return s.Tok == token.BREAK || s.Tok == token.CONTINUE || s.Tok == token.GOTO
	case *ast.ExprStmt:
		call, ok := s.X.(*ast.CallExpr)
		if !ok {
			return false
		}
		id, ok := call.Fun.(*ast.Ident)
		return ok && id.Name == "panic"
	}
	return false
}
