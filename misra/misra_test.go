package misra_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/SoundMatt/go-FuSa/misra"
)

//fusa:test REQ-MISRA003
func TestAssess_NonEmpty(t *testing.T) {
	rep := misra.Assess()
	if rep == nil {
		t.Fatal("expected non-nil report")
	}
	if rep.Total < 40 {
		t.Errorf("expected at least 40 rules, got %d", rep.Total)
	}
	if len(rep.Rules) != rep.Total {
		t.Errorf("Rules length %d != Total %d", len(rep.Rules), rep.Total)
	}
}

//fusa:test REQ-MISRA003
func TestAssess_Counts(t *testing.T) {
	rep := misra.Assess()
	// Covered + NA + Manual should equal Total
	sum := rep.Covered + rep.NA + rep.Manual
	if sum != rep.Total {
		t.Errorf("Covered(%d) + NA(%d) + Manual(%d) = %d != Total(%d)",
			rep.Covered, rep.NA, rep.Manual, sum, rep.Total)
	}
}

//fusa:test REQ-MISRA002
func TestAssess_SpecificRules(t *testing.T) {
	rep := misra.Assess()

	tests := []struct {
		id             string
		wantCoverage   misra.Coverage
		wantGoFuSaRule string
	}{
		{"Dir 4.7", misra.CoverageGofusa, "LINT001"},
		{"Dir 4.8", misra.CoverageNA, ""},
		{"Rule 2.1", misra.CoverageGofusa, "ANA009"},
		{"Rule 2.2", misra.CoverageGofusa, "ANA009"},
		{"Rule 11.4", misra.CoverageGofusa, "LINT004"},
		{"Rule 17.7", misra.CoverageGofusa, "LINT001"},
		{"Rule 16.3", misra.CoverageNA, ""},
		{"Dir 4.14", misra.CoverageManual, ""},
	}

	ruleMap := make(map[string]misra.Rule)
	for _, r := range rep.Rules {
		ruleMap[r.ID] = r
	}

	for _, tc := range tests {
		r, ok := ruleMap[tc.id]
		if !ok {
			t.Errorf("rule %q not found in report", tc.id)
			continue
		}
		if r.Coverage != tc.wantCoverage {
			t.Errorf("rule %q: Coverage = %q, want %q", tc.id, r.Coverage, tc.wantCoverage)
		}
		if tc.wantGoFuSaRule != "" && r.GoFuSaRule != tc.wantGoFuSaRule {
			t.Errorf("rule %q: GoFuSaRule = %q, want %q", tc.id, r.GoFuSaRule, tc.wantGoFuSaRule)
		}
	}
}

//fusa:test REQ-MISRA004
func TestRender_Text(t *testing.T) {
	rep := misra.Assess()
	var buf bytes.Buffer
	if err := misra.Render(&buf, rep, "text"); err != nil {
		t.Fatalf("Render text: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "MISRA C:2023 Coverage Report") {
		t.Error("missing report header")
	}
	if !strings.Contains(out, "Directives") {
		t.Error("missing Directives section")
	}
	if !strings.Contains(out, "Rules") {
		t.Error("missing Rules section")
	}
}

//fusa:test REQ-MISRA004
func TestRender_JSON(t *testing.T) {
	rep := misra.Assess()
	var buf bytes.Buffer
	if err := misra.Render(&buf, rep, "json"); err != nil {
		t.Fatalf("Render json: %v", err)
	}
	if !strings.Contains(buf.String(), `"total"`) {
		t.Error("missing total field in JSON")
	}
	if !strings.Contains(buf.String(), `"rules"`) {
		t.Error("missing rules array in JSON")
	}
}

//fusa:test REQ-MISRA004
func TestRender_InvalidFormat(t *testing.T) {
	rep := misra.Assess()
	if err := misra.Render(&bytes.Buffer{}, rep, "html"); err == nil {
		t.Error("expected error for unsupported format")
	}
}

//fusa:test REQ-MISRA001
func TestCoverageConstants(t *testing.T) {
	if misra.CoverageGofusa != "go-FuSa rule" {
		t.Errorf("CoverageGofusa = %q", misra.CoverageGofusa)
	}
	if misra.CoverageNA != "N/A — Go type system prevents this" {
		t.Errorf("CoverageNA = %q", misra.CoverageNA)
	}
}
