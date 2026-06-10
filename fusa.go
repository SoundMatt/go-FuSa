// Package fusa is the root package of go-FuSa, the functional safety
// enablement toolkit for Go projects.
//
// It exports sentinel errors and core value types shared across all
// sub-packages. Use the sub-packages (config, engine, report, lint, analyze)
// for concrete functionality.
package fusa

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"unicode"
)

// Version is the current release of go-FuSa.
const Version = "0.24.0"

// SpecVersion is the x-FuSa spec version this release implements.
const SpecVersion = "1.8"

// Exit codes (§2.3).
const (
	ExitOK       = 0 // success, no gate failure
	ExitGateFail = 1 // gate failure — tool ran, found problems
	ExitUsage    = 2 // usage error — bad flag/args
	ExitRuntime  = 3 // runtime/internal error — could not complete analysis
)

// Sentinel errors. Callers should use errors.Is for comparison.
//
//fusa:req REQ-NF001
var (
	//fusa:req REQ-ERR001
	ErrNoConfig = errors.New("fusa: no configuration file found")

	//fusa:req REQ-ERR002
	ErrInvalidConfig = errors.New("fusa: invalid configuration")

	//fusa:req REQ-ERR003
	ErrCheckFailed = errors.New("fusa: one or more safety checks failed")
)

// Severity ranks the importance of a Finding.
type Severity string

const (
	SeverityInfo    Severity = "INFO"
	SeverityWarning Severity = "WARNING"
	SeverityError   Severity = "ERROR"
)

func (s Severity) String() string { return string(s) }

// Category is the closed enum of finding categories (§4).
type Category string

const (
	CategoryLint        Category = "lint"
	CategoryStyle       Category = "style"
	CategorySafety      Category = "safety"
	CategorySecurity    Category = "security"
	CategoryCoverage    Category = "coverage"
	CategoryRequirement Category = "requirement"
	CategoryConcurrency Category = "concurrency"
	CategorySupplyChain Category = "supply-chain"
	CategoryConfig      Category = "config"
	CategoryOther       Category = "other"
)

// Disposition records a waiver decision on a finding (§4.1).
type Disposition string

const (
	DispositionOpen     Disposition = "open"
	DispositionAccepted Disposition = "accepted"
	DispositionDeferred Disposition = "deferred"
	DispositionRejected Disposition = "rejected"
)

// Finding represents a single observation produced by a Rule.
type Finding struct {
	RuleID      string      `json:"ruleId"`
	Severity    Severity    `json:"severity"`
	Message     string      `json:"message"`
	Location    Location    `json:"location"`
	Category    Category    `json:"category,omitempty"`
	Standard    string      `json:"standard,omitempty"`
	Clause      string      `json:"clause,omitempty"`
	Remediation string      `json:"remediation,omitempty"`
	Disposition Disposition `json:"disposition,omitempty"`
	Fingerprint string      `json:"fingerprint,omitempty"`
}

// Location identifies the origin of a Finding.
type Location struct {
	File      string `json:"file"`
	Line      int    `json:"line,omitempty"`
	Column    int    `json:"column,omitempty"`
	EndLine   int    `json:"endLine,omitempty"`
	EndColumn int    `json:"endColumn,omitempty"`
}

// DeriveCategory returns the category for a rule id using the §1.5.1 prefix registry.
// Rules with no recognised prefix map to CategoryOther.
func DeriveCategory(ruleID string) Category {
	// extract alphabetic prefix up to first digit or hyphen
	prefix := strings.ToUpper(ruleID)
	cut := strings.IndexFunc(prefix, func(r rune) bool {
		return unicode.IsDigit(r) || r == '-'
	})
	if cut > 0 {
		prefix = prefix[:cut]
	}
	switch prefix {
	case "LINT":
		return CategoryLint
	case "STYLE":
		return CategoryStyle
	case "FUSA":
		return CategorySafety
	case "SEC", "CWE", "CYBER":
		return CategorySecurity
	case "COV":
		return CategoryCoverage
	case "REQ", "TRACE":
		return CategoryRequirement
	case "CONC", "RACE":
		return CategoryConcurrency
	case "SBOM", "SLSA", "VULN", "RELEASE":
		return CategorySupplyChain
	case "CFG":
		return CategoryConfig
	case "ISO", "IEC", "DO", "MISRA", "AUTOSAR", "CERT", "UNECE":
		return CategorySafety
	case "ANA":
		return CategorySafety
	case "HARA", "TARA":
		return CategorySafety
	default:
		return CategoryOther
	}
}

// ComputeFingerprint returns the canonical §4.2 SHA-256 fingerprint for a finding.
// The finding's Location.File MUST already be project-relative before calling.
func ComputeFingerprint(f Finding) string {
	norm := normalizeMessage(f.Message)
	canonical := f.RuleID + "\x1f" + f.Location.File + "\x1f" + norm
	sum := sha256.Sum256([]byte(canonical))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// normalizeMessage replaces runs of ASCII digits with "#", collapses whitespace,
// and trims. NFC normalisation for non-ASCII is left to the caller (ASCII-only
// tools need no Unicode dependency per §4.2).
func normalizeMessage(msg string) string {
	var b strings.Builder
	b.Grow(len(msg))
	inDigits := false
	inSpace := false
	for _, r := range msg {
		switch {
		case r >= '0' && r <= '9':
			if !inDigits {
				b.WriteByte('#')
				inDigits = true
			}
			inSpace = false
		case r == ' ' || r == '\t' || r == '\n' || r == '\r':
			inDigits = false
			inSpace = true
		default:
			if inSpace && b.Len() > 0 {
				b.WriteByte(' ')
			}
			b.WriteRune(r)
			inDigits = false
			inSpace = false
		}
	}
	return strings.TrimSpace(b.String())
}
