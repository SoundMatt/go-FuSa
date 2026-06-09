// Package fusa is the root package of go-FuSa, the functional safety
// enablement toolkit for Go projects.
//
// It exports sentinel errors and core value types shared across all
// sub-packages. Use the sub-packages (config, engine, report, lint, analyze)
// for concrete functionality.
package fusa

import "errors"

// Version is the current release of go-FuSa.
const Version = "0.21.0"

// Sentinel errors. Callers should use errors.Is for comparison.
//
//fusa:req REQ-NF001
var (
	//fusa:req REQ-ERR001
	// ErrNoConfig is returned when no .fusa.json is present.
	ErrNoConfig = errors.New("fusa: no configuration file found")

	//fusa:req REQ-ERR002
	// ErrInvalidConfig is returned when the configuration is malformed.
	ErrInvalidConfig = errors.New("fusa: invalid configuration")

	//fusa:req REQ-ERR003
	// ErrCheckFailed is returned when one or more ERROR-severity findings exist.
	ErrCheckFailed = errors.New("fusa: one or more safety checks failed")
)

// Severity ranks the importance of a Finding.
// It serialises as a string in JSON output.
type Severity string

const (
	SeverityInfo    Severity = "INFO"    // Informational observation.
	SeverityWarning Severity = "WARNING" // Should be addressed before release.
	SeverityError   Severity = "ERROR"   // Must be addressed; fails the check.
)

// String implements fmt.Stringer.
func (s Severity) String() string { return string(s) }

// Finding represents a single observation produced by a Rule.
type Finding struct {
	RuleID      string   `json:"ruleId"`
	Severity    Severity `json:"severity"`
	Message     string   `json:"message"`
	Location    Location `json:"location"`
	Remediation string   `json:"remediation,omitempty"`
}

// Location identifies the origin of a Finding.
type Location struct {
	File   string `json:"file"`
	Line   int    `json:"line,omitempty"`
	Column int    `json:"column,omitempty"`
}
