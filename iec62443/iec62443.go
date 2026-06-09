// Package iec62443 provides go-FuSa engine rules for IEC 62443 cybersecurity
// evidence (v0.15).
//
// IEC 62443 is the international standard for Industrial Automation and Control
// Systems (IACS) cybersecurity. It defines Security Levels (SL 1–4) and
// Component Security Requirements (IEC 62443-4-2).
//
// Rules in this package check for the presence and completeness of IEC 62443
// evidence artefacts in the project root:
//
//	IEC62443-001  Missing .fusa-iec62443.json security level declaration
//	IEC62443-002  Security Level not declared (target_sl absent or < 1)
//	IEC62443-003  Missing security policy documentation (CR 6.2)
//	IEC62443-004  Missing cyber incident response plan (CR 6.2.1)
//
// Activate by importing this package for its side effects:
//
//	import _ "github.com/SoundMatt/go-FuSa/iec62443"
package iec62443

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/config"
	"github.com/SoundMatt/go-FuSa/engine"
)

// ConfigFile is the IEC 62443 project configuration filename.
const ConfigFile = ".fusa-iec62443.json"

// ProjectConfig is the schema for .fusa-iec62443.json.
//
//fusa:req REQ-IEC62443-001
type ProjectConfig struct {
	TargetSL        int    `json:"target_sl"`         // 1–4; 0 means undeclared
	ComponentType   string `json:"component_type"`    // e.g., "application", "embedded", "gateway"
	ZoneConduit     bool   `json:"zone_conduit"`      // true if zone/conduit design is documented
	SecurityReqsDoc string `json:"security_reqs_doc"` // path to security requirements document
	IncidentRespDoc string `json:"incident_resp_doc"` // path to incident response plan
}

// LoadConfig reads .fusa-iec62443.json from root.
//
//fusa:req REQ-IEC62443-001
func LoadConfig(root string) (*ProjectConfig, error) {
	path := filepath.Join(root, ConfigFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg ProjectConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func init() {
	engine.Default.MustRegister(&ruleIECConfigPresent{})
	engine.Default.MustRegister(&ruleIECSLDeclared{})
	engine.Default.MustRegister(&ruleIECSecurityPolicy{})
	engine.Default.MustRegister(&ruleIECIncidentResponse{})
}

// ─── IEC62443-001: configuration present ─────────────────────────────────────

type ruleIECConfigPresent struct{}

func (r *ruleIECConfigPresent) ID() string { return "IEC62443-001" }
func (r *ruleIECConfigPresent) Description() string {
	return "IEC62443-001: Project should declare its IEC 62443 Security Level target in .fusa-iec62443.json."
}

//fusa:req REQ-IEC62443-001
func (r *ruleIECConfigPresent) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	path := filepath.Join(projectRoot, ConfigFile)
	if _, err := os.Stat(path); err == nil {
		return nil, nil
	}
	return []fusa.Finding{{
		RuleID:      r.ID(),
		Severity:    fusa.SeverityInfo,
		Message:     "no .fusa-iec62443.json found — IEC 62443 Security Level not declared",
		Location:    fusa.Location{File: ConfigFile},
		Remediation: "run 'gofusa init' or create .fusa-iec62443.json with target_sl, component_type, and incident_resp_doc",
	}}, nil
}

// ─── IEC62443-002: security level declared ───────────────────────────────────

type ruleIECSLDeclared struct{}

func (r *ruleIECSLDeclared) ID() string { return "IEC62443-002" }
func (r *ruleIECSLDeclared) Description() string {
	return "IEC62443-002: .fusa-iec62443.json must declare a Security Level target (target_sl 1–4) per IEC 62443-2-1 §4.3."
}

//fusa:req REQ-IEC62443-002
func (r *ruleIECSLDeclared) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	cfg, err := LoadConfig(projectRoot)
	if err != nil {
		return nil, nil // IEC62443-001 already reports the missing file
	}
	if cfg.TargetSL < 1 || cfg.TargetSL > 4 {
		return []fusa.Finding{{
			RuleID:      r.ID(),
			Severity:    fusa.SeverityWarning,
			Message:     "IEC 62443 target_sl is not in range 1–4; Security Level not meaningfully declared",
			Location:    fusa.Location{File: ConfigFile},
			Remediation: "set target_sl to 1 (casual), 2 (intentional low-resource), 3 (organised), or 4 (state-sponsored) per IEC 62443-2-1 §4.3",
		}}, nil
	}
	return nil, nil
}

// ─── IEC62443-003: security policy documentation ─────────────────────────────

type ruleIECSecurityPolicy struct{}

func (r *ruleIECSecurityPolicy) ID() string { return "IEC62443-003" }
func (r *ruleIECSecurityPolicy) Description() string {
	return "IEC62443-003: Project should have a security policy document (IEC 62443-4-2 CR 6.2 — Security Audit Log)."
}

var secPolicyFiles = []string{"SECURITY.md", "SECURITY_POLICY.md", "security-policy.md", "docs/SECURITY.md"}

//fusa:req REQ-IEC62443-003
func (r *ruleIECSecurityPolicy) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	for _, name := range secPolicyFiles {
		if _, err := os.Stat(filepath.Join(projectRoot, name)); err == nil {
			return nil, nil
		}
	}
	return []fusa.Finding{{
		RuleID:      r.ID(),
		Severity:    fusa.SeverityInfo,
		Message:     "no security policy document found (SECURITY.md or equivalent) — required for IEC 62443-4-2 CR 6.2",
		Location:    fusa.Location{File: "SECURITY.md"},
		Remediation: "create SECURITY.md documenting the vulnerability disclosure policy, security requirements, and contact",
	}}, nil
}

// ─── IEC62443-004: incident response plan ────────────────────────────────────

type ruleIECIncidentResponse struct{}

func (r *ruleIECIncidentResponse) ID() string { return "IEC62443-004" }
func (r *ruleIECIncidentResponse) Description() string {
	return "IEC62443-004: Project should have a cyber incident response plan (IEC 62443-4-2 CR 6.2.1)."
}

var incidentRespFiles = []string{
	"INCIDENT-RESPONSE.md", "incident-response.md",
	"docs/incident-response.md", "docs/INCIDENT-RESPONSE.md",
}

//fusa:req REQ-IEC62443-004
func (r *ruleIECIncidentResponse) Run(_ context.Context, projectRoot string, cfg *config.Config) ([]fusa.Finding, error) {
	// Also accept a configured path in .fusa-iec62443.json.
	if iec, err := LoadConfig(projectRoot); err == nil && iec.IncidentRespDoc != "" {
		if _, statErr := os.Stat(filepath.Join(projectRoot, iec.IncidentRespDoc)); statErr == nil {
			return nil, nil
		}
	}
	for _, name := range incidentRespFiles {
		if _, err := os.Stat(filepath.Join(projectRoot, name)); err == nil {
			return nil, nil
		}
	}
	return []fusa.Finding{{
		RuleID:      r.ID(),
		Severity:    fusa.SeverityInfo,
		Message:     "no cyber incident response plan found — required for IEC 62443-4-2 CR 6.2.1",
		Location:    fusa.Location{File: "INCIDENT-RESPONSE.md"},
		Remediation: "create INCIDENT-RESPONSE.md or set incident_resp_doc in .fusa-iec62443.json",
	}}, nil
}
