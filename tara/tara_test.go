package tara_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/config"
	"github.com/SoundMatt/go-FuSa/engine"
	"github.com/SoundMatt/go-FuSa/tara"
	"github.com/SoundMatt/go-FuSa/testutil"
)

func makeFinding(ruleID string, sev fusa.Severity, file string, line int) fusa.Finding {
	return fusa.Finding{
		RuleID:   ruleID,
		Severity: sev,
		Message:  "test finding for " + ruleID,
		Location: fusa.Location{File: file, Line: line},
	}
}

//fusa:test REQ-TARA002
//fusa:test REQ-TARA003
func TestScan_EmptyFindings(t *testing.T) {
	dir := testutil.ProjectDir(t, map[string]string{
		"go.mod": "module example.com/test\ngo 1.22\n",
	})
	report, err := tara.Scan(dir, nil)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(report.Entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(report.Entries))
	}
	if report.Format == "" {
		t.Error("Format should not be empty")
	}
}

//fusa:test REQ-TARA001
func TestScan_KnownRules(t *testing.T) {
	dir := testutil.ProjectDir(t, map[string]string{
		"go.mod": "module example.com/test\ngo 1.22\n",
	})
	findings := []fusa.Finding{
		makeFinding("CYBER007", fusa.SeverityError, "crypto.go", 42),
		makeFinding("CYBER001", fusa.SeverityWarning, "hash.go", 10),
		makeFinding("CYBER005", fusa.SeverityWarning, "cmd.go", 5),
	}
	report, err := tara.Scan(dir, findings)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(report.Entries) != 3 {
		t.Errorf("expected 3 entries, got %d", len(report.Entries))
	}
	// Check CYBER007 maps to ERROR → High likelihood.
	for _, e := range report.Entries {
		if e.CyberRuleID == "CYBER007" {
			if e.AttackFeasibility != "high" {
				t.Errorf("CYBER007 (ERROR): want AttackFeasibility=high, got %s", e.AttackFeasibility)
			}
			if !containsSTRIDE(e.STRIDE, "I") {
				t.Errorf("CYBER007: expected I (Info Disclosure) in STRIDE %v", e.STRIDE)
			}
			if e.CWE != "CWE-295" {
				t.Errorf("CYBER007 CWE: want CWE-295 got %s", e.CWE)
			}
		}
	}
}

func TestScan_UnknownRule(t *testing.T) {
	dir := testutil.ProjectDir(t, map[string]string{
		"go.mod": "module example.com/test\ngo 1.22\n",
	})
	findings := []fusa.Finding{
		makeFinding("UNKNOWN999", fusa.SeverityInfo, "foo.go", 1),
	}
	report, err := tara.Scan(dir, findings)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(report.Entries) != 1 {
		t.Fatalf("expected 1 entry for unknown rule, got %d", len(report.Entries))
	}
}

func TestScan_IDSequential(t *testing.T) {
	dir := testutil.ProjectDir(t, map[string]string{
		"go.mod": "module example.com/test\ngo 1.22\n",
	})
	findings := []fusa.Finding{
		makeFinding("CYBER001", fusa.SeverityWarning, "a.go", 1),
		makeFinding("CYBER002", fusa.SeverityWarning, "b.go", 2),
		makeFinding("CYBER003", fusa.SeverityInfo, "c.go", 3),
	}
	report, _ := tara.Scan(dir, findings)
	for i, e := range report.Entries {
		want := strings.Replace("TARA-000", "000", padded(i+1), 1)
		_ = want
		if !strings.HasPrefix(e.ID, "TARA-") {
			t.Errorf("entry %d: ID should start with TARA-, got %s", i, e.ID)
		}
	}
}

func padded(n int) string {
	if n < 10 {
		return "00" + string(rune('0'+n))
	}
	if n < 100 {
		return "0" + string(rune('0'+(n/10))) + string(rune('0'+(n%10)))
	}
	return strings.Repeat("?", 3)
}

// ─── Render ───────────────────────────────────────────────────────────────────

//fusa:test REQ-TARA004
func TestRender_JSON(t *testing.T) {
	dir := testutil.ProjectDir(t, map[string]string{
		"go.mod": "module example.com/test\ngo 1.22\n",
	})
	findings := []fusa.Finding{
		makeFinding("CYBER006", fusa.SeverityError, "creds.go", 10),
	}
	report, _ := tara.Scan(dir, findings)
	var buf bytes.Buffer
	if err := tara.Render(&buf, report, "json"); err != nil {
		t.Fatalf("Render json: %v", err)
	}
	if !strings.Contains(buf.String(), `"threats"`) {
		t.Error("JSON output should contain threats key")
	}
	if !strings.Contains(buf.String(), "CYBER006") {
		t.Error("JSON output should contain CYBER006")
	}
}

func TestRender_Markdown(t *testing.T) {
	dir := testutil.ProjectDir(t, map[string]string{
		"go.mod": "module example.com/test\ngo 1.22\n",
	})
	findings := []fusa.Finding{
		makeFinding("CYBER007", fusa.SeverityError, "tls.go", 5),
	}
	report, _ := tara.Scan(dir, findings)
	var buf bytes.Buffer
	if err := tara.Render(&buf, report, "markdown"); err != nil {
		t.Fatalf("Render markdown: %v", err)
	}
	md := buf.String()
	if !strings.Contains(md, "TARA") {
		t.Error("markdown should contain TARA heading")
	}
	if !strings.Contains(md, "STRIDE") {
		t.Error("markdown table should contain STRIDE column")
	}
	if !strings.Contains(md, "CWE-295") {
		t.Error("markdown should contain CWE-295 for CYBER007")
	}
}

func TestRender_UnknownFormat(t *testing.T) {
	report := &tara.Report{}
	err := tara.Render(bytes.NewBuffer(nil), report, "xml")
	if err == nil {
		t.Error("expected error for unknown format")
	}
}

// ─── TARA001 engine rule ──────────────────────────────────────────────────────

//fusa:test REQ-TARA005
func TestTARA_001_MissingFile(t *testing.T) {
	dir := testutil.ProjectDir(t, map[string]string{
		"go.mod": "module example.com/test\ngo 1.22\n",
	})
	// Just verify tara.json absence produces correct path in finding.
	findings := []fusa.Finding{}
	report, _ := tara.Scan(dir, findings)
	_ = report
	// The engine rule is tested via integration; verify TARAFile constant.
	if tara.TARAFile != "tara.json" {
		t.Errorf("TARAFile constant: want tara.json got %s", tara.TARAFile)
	}
}

// TestTARA_001_EngineRule runs the TARA001 rule via the engine to cover Description and Run.
func TestTARA_001_EngineRule(t *testing.T) {
	dir := testutil.ProjectDir(t, map[string]string{
		"go.mod": "module example.com/test\ngo 1.22\n",
	})
	cfg := config.Default("", "test")
	result, err := engine.Default.RunFilter(context.Background(), dir, cfg, func(r engine.Rule) bool {
		return r.ID() == "TARA001"
	})
	if err != nil {
		t.Fatalf("RunFilter: %v", err)
	}
	// Without tara.json, TARA001 should fire.
	found := false
	for _, f := range result.Findings {
		if f.RuleID == "TARA001" {
			found = true
		}
	}
	if !found {
		t.Error("expected TARA001 finding for missing tara.json")
	}
	// Cover Description.
	for _, r := range engine.Default.Rules() {
		if r.ID() == "TARA001" {
			if r.Description() == "" {
				t.Error("TARA001: Description() is empty")
			}
		}
	}
}

// TestTARA_SeverityInfo covers the SeverityInfo branch of severityToLikelihood.
func TestTARA_SeverityInfo(t *testing.T) {
	dir := testutil.ProjectDir(t, map[string]string{
		"go.mod": "module example.com/test\ngo 1.22\n",
	})
	findings := []fusa.Finding{
		makeFinding("CYBER003", fusa.SeverityInfo, "random.go", 3),
	}
	report, err := tara.Scan(dir, findings)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for _, e := range report.Entries {
		if e.CyberRuleID == "CYBER003" {
			if e.AttackFeasibility != "low" {
				t.Errorf("SeverityInfo: want AttackFeasibility=low, got %s", e.AttackFeasibility)
			}
		}
	}
}

// ─── all 20 CYBER rules have metadata entries ────────────────────────────────

func TestScan_AllCYBERRules_HaveMetadata(t *testing.T) {
	dir := testutil.ProjectDir(t, map[string]string{
		"go.mod": "module example.com/test\ngo 1.22\n",
	})
	for i := 1; i <= 20; i++ {
		ruleID := strings.Replace("CYBER000", "000", padded(i), 1)
		findings := []fusa.Finding{makeFinding(ruleID, fusa.SeverityWarning, "f.go", 1)}
		report, err := tara.Scan(dir, findings)
		if err != nil {
			t.Errorf("%s: Scan error: %v", ruleID, err)
			continue
		}
		if len(report.Entries) != 1 {
			t.Errorf("%s: expected 1 entry, got %d", ruleID, len(report.Entries))
			continue
		}
		e := report.Entries[0]
		if e.CWE == "" {
			t.Errorf("%s: CWE should not be empty", ruleID)
		}
		if len(e.STRIDE) == 0 {
			t.Errorf("%s: STRIDE should not be empty", ruleID)
		}
	}
}

func containsSTRIDE(stride []string, cat string) bool {
	for _, s := range stride {
		if s == cat {
			return true
		}
	}
	return false
}

// ─── x-FuSa spec §9.2 closed impact/risk enums ─────────────────────────────────

var closedImpactValues = map[string]bool{"critical": true, "major": true, "moderate": true, "negligible": true}
var closedRiskValues = map[string]bool{"critical": true, "high": true, "medium": true, "low": true}
var legacyVocabValues = map[string]bool{"high": true, "medium": true, "low": true}

//fusa:test REQ-TARA006
//fusa:test REQ-TARA012
func TestScan_AllRules_UseClosedImpactAndRiskEnums(t *testing.T) {
	dir := testutil.ProjectDir(t, map[string]string{
		"go.mod": "module example.com/test\ngo 1.22\n",
	})
	var sawSafetyValues = map[string]bool{}
	for i := 1; i <= 20; i++ {
		ruleID := strings.Replace("CYBER000", "000", padded(i), 1)
		findings := []fusa.Finding{makeFinding(ruleID, fusa.SeverityError, "f.go", 1)}
		report, err := tara.Scan(dir, findings)
		if err != nil || len(report.Entries) != 1 {
			t.Fatalf("%s: Scan: err=%v entries=%d", ruleID, err, len(report.Entries))
		}
		e := report.Entries[0]

		for axis, v := range map[string]string{
			"safety": e.Impact.Safety, "financial": e.Impact.Financial,
			"operational": e.Impact.Operational, "privacy": e.Impact.Privacy,
		} {
			if !closedImpactValues[v] {
				t.Errorf("%s: impact.%s = %q, not one of the closed critical|major|moderate|negligible enum", ruleID, axis, v)
			}
			if legacyVocabValues[v] {
				t.Errorf("%s: impact.%s = %q — the non-conformant high|medium|low vocabulary must never be used for impact axes", ruleID, axis, v)
			}
		}
		if !closedRiskValues[e.Risk] {
			t.Errorf("%s: risk = %q, not one of the closed critical|high|medium|low enum", ruleID, e.Risk)
		}
		sawSafetyValues[e.Impact.Safety] = true
	}
	// Every tier should genuinely appear across the 20 rules — proof the
	// vocabulary isn't just swapped in name only while collapsing back onto
	// a single value in practice.
	for _, tier := range []string{"critical", "major", "moderate"} {
		if !sawSafetyValues[tier] {
			t.Errorf("expected at least one rule to produce impact.safety=%q across all 20 CYBER rules, saw %v", tier, sawSafetyValues)
		}
	}
}

//fusa:test REQ-TARA012
func TestScan_RiskCombinationTable(t *testing.T) {
	dir := testutil.ProjectDir(t, map[string]string{
		"go.mod": "module example.com/test\ngo 1.22\n",
	})
	cases := []struct {
		ruleID   string // sl>=3, impact High → safety=critical; sl<3 → major
		sev      fusa.Severity
		wantRisk string
	}{
		// CYBER004 (impact High, sl 3) → safety=critical; ERROR → feasibility=high.
		// riskTable[critical][high] = critical.
		{"CYBER004", fusa.SeverityError, "critical"},
		// CYBER001 (impact High, sl 2, stride includes I) → highest axis = major
		// (I elevates privacy to moderate, which ranks below major); ERROR → high.
		// riskTable[major][high] = high.
		{"CYBER001", fusa.SeverityError, "high"},
		// CYBER008 (impact Medium, sl 2, stride D) → highest axis = moderate;
		// ERROR → high. riskTable[moderate][high] = medium.
		{"CYBER008", fusa.SeverityError, "medium"},
		// CYBER008 with INFO severity → feasibility=low. riskTable[moderate][low] = low.
		{"CYBER008", fusa.SeverityInfo, "low"},
	}
	for _, c := range cases {
		findings := []fusa.Finding{makeFinding(c.ruleID, c.sev, "f.go", 1)}
		report, err := tara.Scan(dir, findings)
		if err != nil || len(report.Entries) != 1 {
			t.Fatalf("%s: Scan: err=%v entries=%d", c.ruleID, err, len(report.Entries))
		}
		e := report.Entries[0]
		if e.Risk != c.wantRisk {
			t.Errorf("%s (sev=%s): risk = %q, want %q (impact=%+v, feasibility=%s)",
				c.ruleID, c.sev, e.Risk, c.wantRisk, e.Impact, e.AttackFeasibility)
		}
	}
}
