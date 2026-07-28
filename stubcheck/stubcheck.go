// Package stubcheck implements the x-FuSa spec §1.6.1 content-quality
// detection heuristics — FUSA-STUB001 (placeholder/template text, always an
// ERROR) and FUSA-STUB002 (blanket qualitative fallback, a WARNING by
// default) — plus the §1.6.2 attestation mechanism that can suppress
// FUSA-STUB002 for a specific artifact.
//
// The two scan functions ([ScanPlaceholders], [ScanBlanketFallback]) are
// pure and artifact-agnostic: callers extract each evidence artifact's own
// qualitative text into a []Field and pass it in. Engine-rule glue that
// reads fmea.json/.fusa-hara.json/tara.json/safety-case.json/sas.json off
// disk and wires these scans into `gofusa check` lives in stubrules.go.
package stubcheck

import (
	"fmt"
	"regexp"
	"strings"

	fusa "github.com/SoundMatt/go-FuSa"
)

// RuleStub001 and RuleStub002 are the canonical §1.6.1 rule ids.
const (
	RuleStub001 = "FUSA-STUB001" // placeholder text — always ERROR, disposition-suppressible only
	RuleStub002 = "FUSA-STUB002" // blanket qualitative fallback — WARNING by default, attestation-suppressible
)

// minEntriesForRatio is §1.6.1 rule B's "≥10 entries" threshold.
const minEntriesForRatio = 10

// maxDistinctRatio is §1.6.1 rule B's "<0.1" threshold.
const maxDistinctRatio = 0.1

// Field is one qualitative text field collected across an artifact's
// entries, e.g. every FMEA entry's failureMode, or every TARA entry's
// threat. Values MUST be given in a stable, deterministic order (callers
// typically iterate the entries slice in file order) so Match.Index is
// reproducible across runs.
type Field struct {
	// Name is the field's JSON key, e.g. "failureMode", used only in
	// finding messages.
	Name string
	// Values holds one string per entry (empty string for an entry with no
	// value in this field — it is scanned for placeholders like any other
	// value, but excluded from the rule B distinct-value-ratio denominator,
	// since an absent value cannot be "blanket fallback" text).
	Values []string
}

// Match is one detected content-quality issue.
type Match struct {
	Field string // Field.Name
	Index int    // index into Field.Values (which entry), or -1 when not entry-specific
	Text  string // the offending text (rule A) or empty (rule B, which flags the field as a whole)
}

// placeholderBracket matches bracket-wrapped instructional text such as
// "[describe asset]" — a letter immediately after '[' distinguishes this
// from e.g. Markdown link syntax or a literal array-like value.
var placeholderBracket = regexp.MustCompile(`\[[A-Za-z][^\]]*\]`)

// placeholderSubstrings is the case-insensitive deny-list (§1.6.1 rule A).
var placeholderSubstrings = []string{
	"replace with",
	"example hazard",
	"tbd",
	"lorem ipsum",
	"fill in",
}

// ScanPlaceholders implements §1.6.1 rule A: every value in fields is
// checked against the canonical deny-list (bracket-wrapped instructional
// text, or a case-insensitive substring match on placeholderSubstrings).
// Always-on; the caller is expected to surface every Match as an ERROR
// finding with ruleId FUSA-STUB001 (never suppressed by attestation — see
// package doc).
//
//fusa:req REQ-STUB001
func ScanPlaceholders(fields []Field) []Match {
	var out []Match
	for _, f := range fields {
		for i, v := range f.Values {
			if v == "" {
				continue
			}
			if loc := placeholderBracket.FindString(v); loc != "" {
				out = append(out, Match{Field: f.Name, Index: i, Text: loc})
				continue
			}
			lower := strings.ToLower(v)
			for _, sub := range placeholderSubstrings {
				if strings.Contains(lower, sub) {
					out = append(out, Match{Field: f.Name, Index: i, Text: sub})
					break
				}
			}
		}
	}
	return out
}

// ScanBlanketFallback implements §1.6.1 rule B: for each field with at least
// minEntriesForRatio non-empty values, compute the distinct-value ratio
// (distinct values ÷ non-empty values). A ratio below maxDistinctRatio
// surfaces as one Match for the field (Index -1, since the finding is about
// the field's overall variance, not one entry). Advisory by default — see
// [Suppressed] for the §1.6.2 attestation escape hatch.
//
//fusa:req REQ-STUB002
func ScanBlanketFallback(fields []Field) []Match {
	var out []Match
	for _, f := range fields {
		nonEmpty := 0
		distinct := make(map[string]struct{})
		for _, v := range f.Values {
			if v == "" {
				continue
			}
			nonEmpty++
			distinct[v] = struct{}{}
		}
		if nonEmpty < minEntriesForRatio {
			continue
		}
		ratio := float64(len(distinct)) / float64(nonEmpty)
		if ratio < maxDistinctRatio {
			out = append(out, Match{Field: f.Name, Index: -1})
		}
	}
	return out
}

// PlaceholderFinding converts a rule-A Match into the canonical §4 Finding
// shape: category "safety", ruleId FUSA-STUB001, ERROR — suppressible only
// via a per-finding disposition (§1.2.3/§4.1), never via attestation.
//
//fusa:req REQ-STUB003
func PlaceholderFinding(artifactFile string, m Match) fusa.Finding {
	msg := fmt.Sprintf("placeholder/template text %q found in %s[%d]", m.Text, m.Field, m.Index)
	if m.Index < 0 {
		msg = fmt.Sprintf("placeholder/template text %q found in %s", m.Text, m.Field)
	}
	f := fusa.Finding{
		RuleID:      RuleStub001,
		Severity:    fusa.SeverityError,
		Message:     msg,
		Location:    fusa.Location{File: artifactFile},
		Category:    fusa.CategorySafety,
		Remediation: fmt.Sprintf("replace the placeholder text in %s's %s field with content specific to this project", artifactFile, m.Field),
	}
	f.Fingerprint = fusa.ComputeFingerprint(f)
	return f
}

// BlanketFallbackFinding converts a rule-B Match into the canonical §4
// Finding shape: category "safety", ruleId FUSA-STUB002, WARNING —
// suppressed entirely by the caller (never emitted) when the artifact
// carries a valid §1.6.2 attestation; see [fusa.AttestationValid].
//
//fusa:req REQ-STUB004
func BlanketFallbackFinding(artifactFile string, m Match) fusa.Finding {
	f := fusa.Finding{
		RuleID:   RuleStub002,
		Severity: fusa.SeverityWarning,
		Message: fmt.Sprintf(
			"field %q has a distinct-value ratio below %.0f%% across its entries — looks like one hardcoded string applied regardless of the underlying item",
			m.Field, maxDistinctRatio*100,
		),
		Location:    fusa.Location{File: artifactFile},
		Category:    fusa.CategorySafety,
		Remediation: fmt.Sprintf("vary %s's %s text with the actual signature/behaviour of each entry, or add a §1.6.2 attestation once a reviewer confirms the content is genuinely this repetitive", artifactFile, m.Field),
	}
	f.Fingerprint = fusa.ComputeFingerprint(f)
	return f
}
