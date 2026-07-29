// Package fusa is the root package of go-FuSa, the functional safety
// enablement toolkit for Go projects.
//
// It exports sentinel errors and core value types shared across all
// sub-packages. Use the sub-packages (config, engine, report, lint, analyze)
// for concrete functionality.
package fusa

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// Version is the current release of go-FuSa.
const Version = "0.46.0"

// SpecVersion is the x-FuSa spec version this release implements.
const SpecVersion = "1.15.0"

// SchemaVersion returns the MAJOR.MINOR prefix of SpecVersion, the value
// every report document's "schemaVersion" header field (§2.8/§3.1) MUST
// carry — the spec version a document *conforms to*, one level less precise
// than the tool's own SpecVersion (§9.1 `version --format json`).
func SchemaVersion() string {
	parts := strings.SplitN(SpecVersion, ".", 3)
	if len(parts) < 2 {
		return SpecVersion
	}
	return parts[0] + "." + parts[1]
}

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
//
//fusa:req REQ-CAT001
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
//
//fusa:req REQ-FP001
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

// docScaffoldFiles are the filenames `gofusa init`/`gofusa template` write
// into docs/safety/ by default (see template.Generate). Assess/report
// builders that check for these same files on disk also check
// docs/safety/<name> as a fallback to the bare project-root path, so a
// freshly-scaffolded project doesn't immediately report false gaps (#45).
var docScaffoldFiles = map[string]bool{
	"SAFETY_PLAN.md":   true,
	"HARA.md":          true,
	"TEST_EVIDENCE.md": true,
	"SVP.md":           true,
	"SCMP.md":          true,
	"SQAP.md":          true,
	"IEC61508-FSP.md":  true,
	"ISO26262-FMEA.md": true,
}

// ResolveDoc returns the on-disk path to name under projectRoot: the bare
// project-root-relative path if it exists there, otherwise
// docs/safety/<name> (gofusa's own scaffold default) if name is one of the
// files template.Generate writes and it exists there instead. It returns ""
// if neither location has the file.
//
//fusa:req REQ-DOC001
func ResolveDoc(projectRoot, name string) string {
	root := filepath.Join(projectRoot, filepath.FromSlash(name))
	if _, err := os.Stat(root); err == nil {
		return root
	}
	if docScaffoldFiles[name] {
		alt := filepath.Join(projectRoot, "docs", "safety", filepath.FromSlash(name))
		if _, err := os.Stat(alt); err == nil {
			return alt
		}
	}
	return ""
}

// ─── Content-quality baseline (x-FuSa spec §1.6/§1.6.1/§1.6.2) ────────────────

// AttestationStatus is the closed enum for Attestation.Status (§1.6.2).
// An absent/unrecognised status MUST be treated as StatusHeuristic
// (fail-safe) — see AttestationValid.
type AttestationStatus string

const (
	StatusHeuristic AttestationStatus = "heuristic"
	StatusReviewed  AttestationStatus = "reviewed"
)

// Attestation is the optional document-level §1.6.2 assertion that a named,
// independent human reviewed an evidence artifact's qualitative content. It
// is carried by fmea.json, .fusa-hara.json, tara.json, safety-case.json, and
// sas.json (each embeds *Attestation under the "attestation" key).
//
//fusa:req REQ-ATT001
type Attestation struct {
	Status               AttestationStatus `json:"status"`
	ImplementationAuthor string            `json:"implementationAuthor,omitempty"`
	IndependentReviewer  string            `json:"independentReviewer,omitempty"`
	ReviewedAt           string            `json:"reviewedAt,omitempty"` // RFC 3339
	ContentHash          string            `json:"contentHash,omitempty"`
}

// AttestationValid reports whether att is a non-stale, genuinely independent
// "reviewed" attestation for content whose current canonical hash is
// currentContentHash. It implements every §1.6.2 MUST in one place so every
// artifact package applies the identical fail-safe rule:
//
//   - a nil attestation, or one with Status != "reviewed", is never valid;
//   - IndependentReviewer MUST be set and MUST differ from
//     ImplementationAuthor (no self-attestation);
//   - ContentHash MUST be set and MUST equal currentContentHash — a mismatch
//     means the artifact changed since the review (stale) and the
//     attestation no longer applies.
//
// A caller MUST recompute currentContentHash via AttestationContentHash over
// the artifact's current substantive content before calling this function.
//
//fusa:req REQ-ATT002
func AttestationValid(att *Attestation, currentContentHash string) bool {
	if att == nil || att.Status != StatusReviewed {
		return false
	}
	if att.IndependentReviewer == "" || att.IndependentReviewer == att.ImplementationAuthor {
		return false
	}
	if att.ContentHash == "" || currentContentHash == "" || att.ContentHash != currentContentHash {
		return false
	}
	return true
}

// AttestationContentHash returns the §1.6.2/§6 "sha256:<hex>" integrity hash
// of content, computed over content's canonical (RFC 8785) JSON
// serialisation. Callers pass the artifact's substantive content (its
// entries/hazards/nodes) — never the attestation object itself, and never a
// generatedAt/timestamp field, both of which are self-referential or vary
// independently of substantive edits (§1.6.2).
//
//fusa:req REQ-ATT003
func AttestationContentHash(content interface{}) (string, error) {
	raw, err := json.Marshal(content)
	if err != nil {
		return "", fmt.Errorf("fusa: marshal attestation content: %w", err)
	}
	canon, err := CanonicalizeJSON(raw)
	if err != nil {
		return "", fmt.Errorf("fusa: canonicalize attestation content: %w", err)
	}
	sum := sha256.Sum256(canon)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// NowRFC3339 returns the current UTC time formatted per RFC 3339, the
// timestamp format used throughout the x-FuSa spec (createdAt, reviewedAt,
// generatedAt, …).
func NowRFC3339() string { return time.Now().UTC().Format(time.RFC3339) }

// CanonicalizeJSON re-serialises data per a practical subset of RFC 8785 (the
// JSON Canonicalization Scheme): object keys sorted lexicographically at
// every level, no insignificant whitespace, numbers in shortest round-trip
// form. This is the single canonicalization procedure §6 (qualify hash) and
// §1.6.2 (attestation contentHash) both specify, so every self-integrity
// hash in a go-FuSa document is computed the same, tool-order-independent
// way — Go's struct field order (or any other language's) is NOT a valid
// substitute, because it isn't the same across tools (§6).
//
//fusa:req REQ-ATT004
func CanonicalizeJSON(data []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v interface{}
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("fusa: canonicalize: decode: %w", err)
	}
	var buf bytes.Buffer
	if err := writeCanonicalJSON(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonicalJSON(buf *bytes.Buffer, v interface{}) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case json.Number:
		buf.WriteString(canonicalJSONNumber(x))
	case string:
		buf.Write(canonicalJSONString(x))
	case []interface{}:
		buf.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonicalJSON(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]interface{}:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			buf.Write(canonicalJSONString(k))
			buf.WriteByte(':')
			if err := writeCanonicalJSON(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("fusa: canonicalize: unsupported type %T", v)
	}
	return nil
}

// canonicalJSONNumber formats n in the shortest round-trip form: integers
// with no decimal point or exponent, everything else via Go's
// shortest-round-trip float formatting.
func canonicalJSONNumber(n json.Number) string {
	if i, err := n.Int64(); err == nil {
		return strconv.FormatInt(i, 10)
	}
	f, err := n.Float64()
	if err != nil {
		return n.String()
	}
	return strconv.FormatFloat(f, 'g', -1, 64)
}

// canonicalJSONString encodes s as a JSON string with HTML-escaping
// disabled, so the output matches standard JSON string escaping rather than
// Go's web-safe default (which would otherwise escape '<', '>', '&').
func canonicalJSONString(s string) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return bytes.TrimSuffix(b.Bytes(), []byte("\n"))
}
