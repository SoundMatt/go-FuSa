// Package engine is the go-FuSa rule execution engine.
//
// Rules implement the Rule interface and are registered with a Registry.
// Call Registry.Run to execute all active rules against a project directory.
//
// The package-level Default registry is populated by built-in rules (this
// package's own init) and by sub-packages (lint, analyze) that register
// additional rules when imported. Application code should use Default unless
// a custom registry is needed for testing.
package engine

import (
	"context"
	"fmt"
	"sort"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/config"
)

// Rule is the interface implemented by every go-FuSa safety check.
type Rule interface {
	// ID returns the unique rule identifier (e.g. "FUSA001").
	ID() string
	// Description returns a short human-readable summary of the rule.
	Description() string
	// Run executes the rule against projectRoot and returns any findings.
	// An error indicates the rule could not run; it does not mean findings exist.
	Run(ctx context.Context, projectRoot string, cfg *config.Config) ([]fusa.Finding, error)
}

// Registry holds a set of registered rules.
// The zero value is not usable; use NewRegistry.
type Registry struct {
	rules []Rule
	index map[string]struct{} // guards against duplicate IDs
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{index: make(map[string]struct{})}
}

// Register adds r to the registry. It returns an error if r is nil or if a
// rule with the same ID has already been registered.
func (reg *Registry) Register(r Rule) error {
	//fusa:req REQ-ENG005
	if r == nil {
		return fmt.Errorf("engine: cannot register nil rule")
	}
	if _, dup := reg.index[r.ID()]; dup {
		return fmt.Errorf("engine: rule %q already registered", r.ID())
	}
	reg.rules = append(reg.rules, r)
	reg.index[r.ID()] = struct{}{}
	return nil
}

//fusa:req REQ-ENG004
// MustRegister calls Register and panics if it returns an error.
// Intended for use in package init functions where duplicate registration
// indicates a programming error that cannot be recovered from at runtime.
func (reg *Registry) MustRegister(r Rule) {
	if err := reg.Register(r); err != nil {
		panic(err)
	}
}

// Rules returns a copy of the registered rules sorted by ID.
func (reg *Registry) Rules() []Rule {
	out := make([]Rule, len(reg.rules))
	copy(out, reg.rules)
	//fusa:req REQ-ENG001
	sort.Slice(out, func(i, j int) bool { return out[i].ID() < out[j].ID() })
	return out
}

// Result holds the output of a Run call.
type Result struct {
	Findings []fusa.Finding
	// Errors collects per-rule execution errors. A rule error does not abort
	// the run; subsequent rules still execute.
	Errors []error
}

//fusa:req REQ-ENG003
// HasErrors reports whether any Finding carries SeverityError.
func (r *Result) HasErrors() bool {
	for _, f := range r.Findings {
		if f.Severity == fusa.SeverityError {
			return true
		}
	}
	return false
}

// Run executes all registered rules against projectRoot, skipping any whose
// ID appears in cfg.Rules.Exclude. Rule execution errors are collected in
// Result.Errors and do not abort the run.
func (reg *Registry) Run(ctx context.Context, projectRoot string, cfg *config.Config) (*Result, error) {
	//fusa:req REQ-CFG007
	excluded := make(map[string]struct{}, len(cfg.Rules.Exclude))
	for _, id := range cfg.Rules.Exclude {
		excluded[id] = struct{}{}
	}

	var result Result
	for _, rule := range reg.Rules() {
		//fusa:req REQ-ENG006
		if ctx.Err() != nil {
			break
		}
		if _, skip := excluded[rule.ID()]; skip {
			continue
		}
		findings, err := rule.Run(ctx, projectRoot, cfg)
		if err != nil {
			//fusa:req REQ-ENG002
			result.Errors = append(result.Errors, fmt.Errorf("rule %s: %w", rule.ID(), err))
			continue
		}
		result.Findings = append(result.Findings, findings...)
	}
	return &result, nil
}

// Default is the package-level registry used by all built-in rules.
// It is populated during package initialisation via init functions and is
// effectively read-only after program startup.
var Default = NewRegistry()
