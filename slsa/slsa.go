// Package slsa provides go-FuSa engine rules for SLSA (Supply-chain Levels for
// Software Artifacts) supply-chain integrity evidence (v0.15).
//
// SLSA defines four levels of supply-chain security assurance. go-FuSa already
// produces SLSA L1 provenance via 'gofusa release'. This package checks for L2
// and L3 requirements and emits advisory findings when they are not met.
//
//	SLSA001  provenance.json lacks a VCS revision (SLSA L1 completeness)
//	SLSA002  provenance.json lacks a builder identifier (SLSA L2)
//	SLSA003  No CODEOWNERS or branch-protection evidence (SLSA L3)
//
// Activate by importing this package for its side effects:
//
//	import _ "github.com/SoundMatt/go-FuSa/slsa"
package slsa

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/config"
	"github.com/SoundMatt/go-FuSa/engine"
)

// ProvenanceFile is the expected provenance filename (matches release package).
const ProvenanceFile = "provenance.json"

func init() {
	engine.Default.MustRegister(&ruleSLSA001{})
	engine.Default.MustRegister(&ruleSLSA002{})
	engine.Default.MustRegister(&ruleSLSA003{})
}

// ─── SLSA001: VCS revision present ───────────────────────────────────────────

type ruleSLSA001 struct{}

func (r *ruleSLSA001) ID() string { return "SLSA001" }
func (r *ruleSLSA001) Description() string {
	return "SLSA001: provenance.json should include vcsRevision for SLSA L1 source identification."
}

//fusa:req REQ-SLSA001
func (r *ruleSLSA001) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	data, err := os.ReadFile(filepath.Join(projectRoot, ProvenanceFile))
	if err != nil {
		return nil, nil // RELEASE002 already handles missing provenance
	}
	var prov map[string]interface{}
	if err := json.Unmarshal(data, &prov); err != nil {
		return nil, nil
	}
	rev, _ := prov["vcsRevision"].(string)
	if rev == "" {
		return []fusa.Finding{{
			RuleID:      r.ID(),
			Severity:    fusa.SeverityInfo,
			Message:     "provenance.json missing vcsRevision — SLSA L1 requires the source revision to be recorded",
			Location:    fusa.Location{File: ProvenanceFile},
			Remediation: "run 'gofusa release' from a git repository so vcsRevision is populated",
		}}, nil
	}
	return nil, nil
}

// ─── SLSA002: builder identifier ─────────────────────────────────────────────

type ruleSLSA002 struct{}

func (r *ruleSLSA002) ID() string { return "SLSA002" }
func (r *ruleSLSA002) Description() string {
	return "SLSA002: provenance.json should identify the build system (builder field) for SLSA L2."
}

//fusa:req REQ-SLSA002
func (r *ruleSLSA002) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	data, err := os.ReadFile(filepath.Join(projectRoot, ProvenanceFile))
	if err != nil {
		return nil, nil
	}
	var prov map[string]interface{}
	if err := json.Unmarshal(data, &prov); err != nil {
		return nil, nil
	}
	builder, _ := prov["builder"].(string)
	if builder == "" {
		return []fusa.Finding{{
			RuleID:      r.ID(),
			Severity:    fusa.SeverityInfo,
			Message:     "provenance.json missing builder field — SLSA L2 requires the build system to be identified",
			Location:    fusa.Location{File: ProvenanceFile},
			Remediation: "add a builder field to provenance.json (e.g., via CI environment variable GITHUB_ACTIONS_URL) and regenerate with 'gofusa release'",
		}}, nil
	}
	return nil, nil
}

// ─── SLSA003: two-party review evidence ──────────────────────────────────────

type ruleSLSA003 struct{}

func (r *ruleSLSA003) ID() string { return "SLSA003" }
func (r *ruleSLSA003) Description() string {
	return "SLSA003: No CODEOWNERS file or branch-protection policy found — SLSA L3 requires two-party review for all changes."
}

var codeownersFiles = []string{
	"CODEOWNERS",
	".github/CODEOWNERS",
	"docs/CODEOWNERS",
}

var branchProtectionFiles = []string{
	".github/branch-protection.json",
	".github/rulesets.json",
	"docs/branch-protection.md",
}

//fusa:req REQ-SLSA003
func (r *ruleSLSA003) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	for _, name := range append(codeownersFiles, branchProtectionFiles...) {
		if _, err := os.Stat(filepath.Join(projectRoot, name)); err == nil {
			return nil, nil
		}
	}
	return []fusa.Finding{{
		RuleID:      r.ID(),
		Severity:    fusa.SeverityInfo,
		Message:     "no CODEOWNERS file or branch-protection policy found — SLSA L3 requires documented two-party review",
		Location:    fusa.Location{File: ".github/CODEOWNERS"},
		Remediation: "create .github/CODEOWNERS and enable branch protection requiring at least one reviewer",
	}}, nil
}
