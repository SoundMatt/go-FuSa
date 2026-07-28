package stubcheck_test

import (
	"testing"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/stubcheck"
)

//fusa:test REQ-STUB001
func TestScanPlaceholders_Bracket(t *testing.T) {
	fields := []stubcheck.Field{
		{Name: "hazards[].description", Values: []string{"[describe asset]", "a real hazard description"}},
	}
	matches := stubcheck.ScanPlaceholders(fields)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d: %+v", len(matches), matches)
	}
	if matches[0].Index != 0 {
		t.Errorf("expected match at index 0, got %d", matches[0].Index)
	}
}

//fusa:test REQ-STUB001
func TestScanPlaceholders_Substrings(t *testing.T) {
	cases := []string{
		"Example hazard — replace with project-specific hazard",
		"TBD",
		"tbd needs work",
		"lorem ipsum dolor sit amet",
		"please fill in this section",
	}
	for _, c := range cases {
		fields := []stubcheck.Field{{Name: "f", Values: []string{c}}}
		matches := stubcheck.ScanPlaceholders(fields)
		if len(matches) != 1 {
			t.Errorf("value %q: expected 1 match, got %d", c, len(matches))
		}
	}
}

//fusa:test REQ-STUB001
func TestScanPlaceholders_CleanTextNoMatch(t *testing.T) {
	fields := []stubcheck.Field{
		{Name: "f", Values: []string{"gofusa fails to report a genuine safety rule violation", ""}},
	}
	matches := stubcheck.ScanPlaceholders(fields)
	if len(matches) != 0 {
		t.Errorf("expected no matches, got %+v", matches)
	}
}

//fusa:test REQ-STUB002
func TestScanBlanketFallback_BelowThreshold(t *testing.T) {
	values := make([]string, 20)
	for i := range values {
		values[i] = "Incorrect output" // one value repeated for every entry
	}
	fields := []stubcheck.Field{{Name: "entries[].failureMode", Values: values}}
	matches := stubcheck.ScanBlanketFallback(fields)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Index != -1 {
		t.Errorf("expected field-level match (Index -1), got %d", matches[0].Index)
	}
}

//fusa:test REQ-STUB002
func TestScanBlanketFallback_AboveThreshold(t *testing.T) {
	values := make([]string, 20)
	for i := range values {
		values[i] = "distinct-value-" + string(rune('A'+i))
	}
	fields := []stubcheck.Field{{Name: "f", Values: values}}
	matches := stubcheck.ScanBlanketFallback(fields)
	if len(matches) != 0 {
		t.Errorf("expected no matches for fully-distinct values, got %+v", matches)
	}
}

//fusa:test REQ-STUB002
func TestScanBlanketFallback_UnderMinEntries(t *testing.T) {
	values := []string{"same", "same", "same"} // only 3 entries, below the 10-entry threshold
	fields := []stubcheck.Field{{Name: "f", Values: values}}
	matches := stubcheck.ScanBlanketFallback(fields)
	if len(matches) != 0 {
		t.Errorf("expected no matches below the entry threshold, got %+v", matches)
	}
}

//fusa:test REQ-STUB003
func TestPlaceholderFinding_Shape(t *testing.T) {
	f := stubcheck.PlaceholderFinding("fmea.json", stubcheck.Match{Field: "entries[].failureMode", Index: 2, Text: "TBD"})
	if f.RuleID != stubcheck.RuleStub001 {
		t.Errorf("RuleID = %q, want %q", f.RuleID, stubcheck.RuleStub001)
	}
	if f.Severity != fusa.SeverityError {
		t.Errorf("Severity = %q, want ERROR", f.Severity)
	}
	if f.Location.File != "fmea.json" {
		t.Errorf("Location.File = %q, want fmea.json", f.Location.File)
	}
	if f.Fingerprint == "" {
		t.Error("expected a non-empty fingerprint")
	}
}

//fusa:test REQ-STUB004
func TestBlanketFallbackFinding_Shape(t *testing.T) {
	f := stubcheck.BlanketFallbackFinding("tara.json", stubcheck.Match{Field: "threats[].threat", Index: -1})
	if f.RuleID != stubcheck.RuleStub002 {
		t.Errorf("RuleID = %q, want %q", f.RuleID, stubcheck.RuleStub002)
	}
	if f.Severity != fusa.SeverityWarning {
		t.Errorf("Severity = %q, want WARNING", f.Severity)
	}
}

//fusa:test REQ-STUB012
func TestAttestationSuppresses(t *testing.T) {
	content := []string{"a", "b", "c"}
	hash, err := fusa.AttestationContentHash(content)
	if err != nil {
		t.Fatalf("AttestationContentHash: %v", err)
	}

	valid := &fusa.Attestation{
		Status:               fusa.StatusReviewed,
		ImplementationAuthor: "auto",
		IndependentReviewer:  "Jane Doe <jane@example.com>",
		ContentHash:          hash,
	}
	if !stubcheck.AttestationSuppresses(valid, content) {
		t.Error("expected a valid, non-stale, independent attestation to suppress")
	}

	if stubcheck.AttestationSuppresses(nil, content) {
		t.Error("nil attestation must not suppress")
	}

	stale := &fusa.Attestation{
		Status:               fusa.StatusReviewed,
		ImplementationAuthor: "auto",
		IndependentReviewer:  "Jane Doe <jane@example.com>",
		ContentHash:          "sha256:deadbeef",
	}
	if stubcheck.AttestationSuppresses(stale, content) {
		t.Error("stale (hash-mismatched) attestation must not suppress")
	}

	selfAttested := &fusa.Attestation{
		Status:               fusa.StatusReviewed,
		ImplementationAuthor: "auto",
		IndependentReviewer:  "auto",
		ContentHash:          hash,
	}
	if stubcheck.AttestationSuppresses(selfAttested, content) {
		t.Error("self-attestation (same author/reviewer) must not suppress")
	}

	heuristic := &fusa.Attestation{Status: fusa.StatusHeuristic}
	if stubcheck.AttestationSuppresses(heuristic, content) {
		t.Error("heuristic status must not suppress")
	}
}
