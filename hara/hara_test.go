package hara_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SoundMatt/go-FuSa/config"
	"github.com/SoundMatt/go-FuSa/engine"
	"github.com/SoundMatt/go-FuSa/hara"
)

// ─── DetermineASIL ────────────────────────────────────────────────────────────

//fusa:test REQ-HARA006
func TestDetermineASIL_Table4(t *testing.T) {
	tests := []struct {
		s    hara.Severity
		e    hara.Exposure
		c    hara.Controllability
		want hara.ASIL
	}{
		// S0 always QM
		{hara.SeverityS0, hara.ExposureE4, hara.ControllabilityC3, hara.ASILQM},
		// E0 always QM
		{hara.SeverityS3, hara.ExposureE0, hara.ControllabilityC3, hara.ASILQM},
		// C0 always QM
		{hara.SeverityS3, hara.ExposureE4, hara.ControllabilityC0, hara.ASILQM},
		// S1 spot checks (1 + E + C)
		{hara.SeverityS1, hara.ExposureE4, hara.ControllabilityC3, hara.ASILB},  // 8
		{hara.SeverityS1, hara.ExposureE4, hara.ControllabilityC2, hara.ASILA},  // 7
		{hara.SeverityS1, hara.ExposureE4, hara.ControllabilityC1, hara.ASILQM}, // 6
		// S2 spot checks (2 + E + C)
		{hara.SeverityS2, hara.ExposureE4, hara.ControllabilityC3, hara.ASILC}, // 9
		{hara.SeverityS2, hara.ExposureE4, hara.ControllabilityC2, hara.ASILB}, // 8
		{hara.SeverityS2, hara.ExposureE4, hara.ControllabilityC1, hara.ASILA}, // 7
		{hara.SeverityS2, hara.ExposureE3, hara.ControllabilityC2, hara.ASILA}, // 7
		// S3 spot checks (3 + E + C)
		{hara.SeverityS3, hara.ExposureE4, hara.ControllabilityC1, hara.ASILB},  // 8
		{hara.SeverityS3, hara.ExposureE4, hara.ControllabilityC2, hara.ASILC},  // 9
		{hara.SeverityS3, hara.ExposureE4, hara.ControllabilityC3, hara.ASILD},  // 10 (only ASIL-D cell)
		{hara.SeverityS3, hara.ExposureE1, hara.ControllabilityC1, hara.ASILQM}, // 5
		{hara.SeverityS3, hara.ExposureE1, hara.ControllabilityC3, hara.ASILA},  // 7
		// Unknown combo falls back to QM
		{hara.Severity("SX"), hara.ExposureE4, hara.ControllabilityC3, hara.ASILQM},
	}

	for _, tt := range tests {
		got := hara.DetermineASIL(tt.s, tt.e, tt.c)
		if got != tt.want {
			t.Errorf("DetermineASIL(%s,%s,%s) = %s, want %s", tt.s, tt.e, tt.c, got, tt.want)
		}
	}
}

// TestDetermineASIL_Exhaustive verifies every rated S×E×C cell against the
// additive ISO 26262-3:2018 Table 4 model, and that every C0 cell is QM.
//
//fusa:test REQ-HARA006
func TestDetermineASIL_Exhaustive(t *testing.T) {
	sVal := map[hara.Severity]int{hara.SeverityS1: 1, hara.SeverityS2: 2, hara.SeverityS3: 3}
	eVal := map[hara.Exposure]int{hara.ExposureE1: 1, hara.ExposureE2: 2, hara.ExposureE3: 3, hara.ExposureE4: 4}
	cVal := map[hara.Controllability]int{hara.ControllabilityC1: 1, hara.ControllabilityC2: 2, hara.ControllabilityC3: 3}

	fromSum := func(n int) hara.ASIL {
		switch n {
		case 7:
			return hara.ASILA
		case 8:
			return hara.ASILB
		case 9:
			return hara.ASILC
		case 10:
			return hara.ASILD
		default:
			return hara.ASILQM
		}
	}

	dCells := 0
	for s, sv := range sVal {
		for e, ev := range eVal {
			// Rated controllability C1..C3.
			for c, cv := range cVal {
				want := fromSum(sv + ev + cv)
				if want == hara.ASILD {
					dCells++
				}
				if got := hara.DetermineASIL(s, e, c); got != want {
					t.Errorf("DetermineASIL(%s,%s,%s) = %s, want %s", s, e, c, got, want)
				}
			}
			// C0 (unrated controllability) is always QM.
			if got := hara.DetermineASIL(s, e, hara.ControllabilityC0); got != hara.ASILQM {
				t.Errorf("DetermineASIL(%s,%s,C0) = %s, want QM", s, e, got)
			}
		}
	}
	if dCells != 1 {
		t.Errorf("expected exactly one ASIL-D cell (S3+E4+C3), found %d", dCells)
	}
}

//fusa:test REQ-HARA006
func TestDetermineASIL_EmptySeverity(t *testing.T) {
	if got := hara.DetermineASIL("", hara.ExposureE4, hara.ControllabilityC3); got != hara.ASILQM {
		t.Errorf("empty severity should be QM, got %s", got)
	}
}

//fusa:test REQ-HARA006
func TestDetermineASIL_EmptyExposure(t *testing.T) {
	if got := hara.DetermineASIL(hara.SeverityS3, "", hara.ControllabilityC3); got != hara.ASILQM {
		t.Errorf("empty exposure should be QM, got %s", got)
	}
}

// ─── Load / Save ──────────────────────────────────────────────────────────────

//fusa:test REQ-HARA007
func TestLoad_Missing(t *testing.T) {
	dir := t.TempDir()
	h, err := hara.Load(dir)
	if err != nil {
		t.Fatalf("Load on missing file: %v", err)
	}
	if h == nil {
		t.Fatal("expected non-nil HARA for missing file")
	}
	if len(h.Hazards) != 0 {
		t.Errorf("expected 0 hazards, got %d", len(h.Hazards))
	}
}

//fusa:test REQ-HARA007
func TestLoad_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, hara.HARAFile), []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := hara.Load(dir)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

//fusa:test REQ-HARA008
//fusa:test REQ-HARA001
//fusa:test REQ-HARA002
//fusa:test REQ-HARA003
//fusa:test REQ-HARA004
//fusa:test REQ-HARA005
func TestSave_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	h := &hara.HARA{
		Project:   "test",
		Standard:  "ISO 26262",
		CreatedAt: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
		Situations: []hara.OperationalSituation{
			{ID: "OS-001", Description: "Normal operation"},
		},
		Hazards: []hara.Hazard{
			{
				ID:          "H-001",
				Description: "False negative",
				Situations:  []string{"OS-001"},
				Risk: hara.RiskRating{
					Severity:        hara.SeverityS2,
					Exposure:        hara.ExposureE4,
					Controllability: hara.ControllabilityC2,
					ASIL:            hara.ASILC,
				},
				SafetyGoals: []string{"SG-001"},
			},
		},
		SafetyGoals: []hara.SafetyGoal{
			{
				ID:          "SG-001",
				Description: "Report every violation",
				HazardIDs:   []string{"H-001"},
				ASIL:        hara.ASILC,
				SafeState:   "halt analysis",
			},
		},
	}
	path := filepath.Join(dir, hara.HARAFile)
	if err := hara.Save(path, h); err != nil {
		t.Fatalf("Save: %v", err)
	}
	loaded, err := hara.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(loaded.Hazards) != 1 {
		t.Fatalf("expected 1 hazard, got %d", len(loaded.Hazards))
	}
	if loaded.Hazards[0].Risk.ASIL != hara.ASILC {
		t.Errorf("ASIL = %s, want ASIL-C", loaded.Hazards[0].Risk.ASIL)
	}
}

// ─── Validate ─────────────────────────────────────────────────────────────────

//fusa:test REQ-HARA009
func TestValidate_Complete(t *testing.T) {
	h := &hara.HARA{
		Hazards: []hara.Hazard{
			{
				ID:          "H-001",
				Description: "test",
				Risk: hara.RiskRating{
					Severity:        hara.SeverityS2,
					Exposure:        hara.ExposureE3,
					Controllability: hara.ControllabilityC2,
					ASIL:            hara.ASILA, // S2+E3+C2 = 7 → ASIL-A
				},
				SafetyGoals: []string{"SG-001"},
			},
		},
		SafetyGoals: []hara.SafetyGoal{
			{ID: "SG-001", Description: "goal", ASIL: hara.ASILA, FSSRRefs: []string{"REQ-TEST001"}},
		},
	}
	findings := hara.Validate(h)
	if len(findings) != 0 {
		t.Errorf("complete HARA should have no gaps, got: %v", findings)
	}
}

//fusa:test REQ-HARA009
func TestValidate_IncompleteRisk(t *testing.T) {
	h := &hara.HARA{
		Hazards: []hara.Hazard{
			{ID: "H-001", Description: "test", SafetyGoals: []string{"SG-001"},
				Risk: hara.RiskRating{Severity: hara.SeverityS2}},
		},
		SafetyGoals: []hara.SafetyGoal{{ID: "SG-001", ASIL: hara.ASILA}},
	}
	findings := hara.Validate(h)
	found := false
	for _, f := range findings {
		if f.HazardID == "H-001" && strings.Contains(f.Message, "incomplete risk rating") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected incomplete risk rating finding, got: %v", findings)
	}
}

//fusa:test REQ-HARA009
func TestValidate_NoSafetyGoal(t *testing.T) {
	h := &hara.HARA{
		Hazards: []hara.Hazard{
			{ID: "H-001", Description: "test",
				Risk: hara.RiskRating{Severity: hara.SeverityS2, Exposure: hara.ExposureE3, Controllability: hara.ControllabilityC2}},
		},
	}
	findings := hara.Validate(h)
	found := false
	for _, f := range findings {
		if f.HazardID == "H-001" && strings.Contains(f.Message, "no linked safety goal") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected no safety goal finding, got: %v", findings)
	}
}

//fusa:test REQ-HARA009
func TestValidate_UnknownGoalRef(t *testing.T) {
	h := &hara.HARA{
		Hazards: []hara.Hazard{
			{ID: "H-001", Description: "test", SafetyGoals: []string{"SG-GHOST"},
				Risk: hara.RiskRating{Severity: hara.SeverityS1, Exposure: hara.ExposureE2, Controllability: hara.ControllabilityC1}},
		},
		SafetyGoals: []hara.SafetyGoal{{ID: "SG-001", ASIL: hara.ASILA}},
	}
	findings := hara.Validate(h)
	found := false
	for _, f := range findings {
		if strings.Contains(f.Message, "unknown safety goal SG-GHOST") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected unknown goal ref finding, got: %v", findings)
	}
}

//fusa:test REQ-HARA009
func TestValidate_NoASIL(t *testing.T) {
	h := &hara.HARA{
		Hazards: []hara.Hazard{
			{ID: "H-001", Description: "test", SafetyGoals: []string{"SG-001"},
				Risk: hara.RiskRating{Severity: hara.SeverityS1, Exposure: hara.ExposureE2, Controllability: hara.ControllabilityC1}},
		},
		SafetyGoals: []hara.SafetyGoal{{ID: "SG-001", Description: "goal"}},
	}
	findings := hara.Validate(h)
	found := false
	for _, f := range findings {
		if f.SafetyGoalID == "SG-001" && strings.Contains(f.Message, "no ASIL") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected no ASIL finding, got: %v", findings)
	}
}

// ─── Render ───────────────────────────────────────────────────────────────────

//fusa:test REQ-HARA010
func TestRender_JSON(t *testing.T) {
	h := &hara.HARA{Project: "myproject", Standard: "ISO 26262"}
	var buf bytes.Buffer
	if err := hara.Render(&buf, h, "json"); err != nil {
		t.Fatalf("Render json: %v", err)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if out["project"] != "myproject" {
		t.Errorf("project = %v, want myproject", out["project"])
	}
}

//fusa:test REQ-HARA010
func TestRender_EmptyFormat(t *testing.T) {
	h := &hara.HARA{Project: "p"}
	var buf bytes.Buffer
	if err := hara.Render(&buf, h, ""); err != nil {
		t.Fatalf("Render empty format: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("expected non-empty output for empty format (defaults to json)")
	}
}

//fusa:test REQ-HARA010
func TestRender_Text(t *testing.T) {
	h := &hara.HARA{
		Project:  "testproj",
		Standard: "ISO 26262",
		Situations: []hara.OperationalSituation{
			{ID: "OS-001", Description: "Normal driving"},
		},
		Hazards: []hara.Hazard{
			{
				ID:          "H-001",
				Description: "False negative",
				Situations:  []string{"OS-001"},
				Risk: hara.RiskRating{
					Severity:        hara.SeverityS2,
					Exposure:        hara.ExposureE4,
					Controllability: hara.ControllabilityC2,
				},
				SafetyGoals: []string{"SG-001"},
			},
		},
		SafetyGoals: []hara.SafetyGoal{
			{ID: "SG-001", Description: "Report all", ASIL: hara.ASILC, SafeState: "halt"},
		},
	}
	var buf bytes.Buffer
	if err := hara.Render(&buf, h, "text"); err != nil {
		t.Fatalf("Render text: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"# Hazard Analysis", "H-001", "SG-001", "ASIL-C", "halt", "OS-001"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in text render output", want)
		}
	}
}

//fusa:test REQ-HARA010
func TestRender_Markdown(t *testing.T) {
	h := &hara.HARA{Project: "p", Standard: "ISO 26262"}
	var buf bytes.Buffer
	if err := hara.Render(&buf, h, "markdown"); err != nil {
		t.Fatalf("Render markdown: %v", err)
	}
	if !strings.Contains(buf.String(), "# Hazard Analysis") {
		t.Error("markdown render missing header")
	}
}

//fusa:test REQ-HARA010
func TestRender_Unknown(t *testing.T) {
	h := &hara.HARA{}
	var buf bytes.Buffer
	if err := hara.Render(&buf, h, "pdf"); err == nil {
		t.Error("expected error for unknown format pdf")
	}
}

//fusa:test REQ-HARA010
func TestRender_WithGaps(t *testing.T) {
	// Hazard with no safety goal → gap line in render output
	h := &hara.HARA{
		Project: "gaptest",
		Hazards: []hara.Hazard{
			{ID: "H-999", Description: "ungated hazard",
				Risk: hara.RiskRating{Severity: hara.SeverityS2, Exposure: hara.ExposureE3, Controllability: hara.ControllabilityC2}},
		},
	}
	var buf bytes.Buffer
	if err := hara.Render(&buf, h, "text"); err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Gaps") {
		t.Error("expected Gaps section in output with ungated hazard")
	}
}

// ─── Engine rules ─────────────────────────────────────────────────────────────

func findingsForRule(t *testing.T, dir string, ruleIDStr string) bool {
	t.Helper()
	cfg := config.Default("github.com/x/y", "y")
	result, err := engine.Default.Run(context.Background(), dir, cfg)
	if err != nil {
		t.Fatalf("engine.Run: %v", err)
	}
	for _, f := range result.Findings {
		if f.RuleID == ruleIDStr {
			return true
		}
	}
	return false
}

//fusa:test REQ-HARA011
func TestHARA001_NoFile(t *testing.T) {
	dir := t.TempDir()
	if !findingsForRule(t, dir, "HARA001") {
		t.Error("HARA001 should fire when .fusa-hara.json is absent")
	}
}

//fusa:test REQ-HARA011
func TestHARA001_WithFile(t *testing.T) {
	dir := t.TempDir()
	h := &hara.HARA{Project: "p", Standard: "ISO 26262"}
	if err := hara.Save(filepath.Join(dir, hara.HARAFile), h); err != nil {
		t.Fatal(err)
	}
	if findingsForRule(t, dir, "HARA001") {
		t.Error("HARA001 should not fire when .fusa-hara.json exists")
	}
}

//fusa:test REQ-HARA011
func TestHARA001_ISO26262Config_Warning(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default("github.com/x/y", "y")
	cfg.Project.Standard = "ISO26262"
	result, err := engine.Default.Run(context.Background(), dir, cfg)
	if err != nil {
		t.Fatalf("engine.Run: %v", err)
	}
	for _, f := range result.Findings {
		if f.RuleID == "HARA001" {
			if f.Severity != "WARNING" {
				t.Errorf("HARA001 severity for ISO26262 project = %s, want WARNING", f.Severity)
			}
			return
		}
	}
	t.Error("HARA001 should fire for ISO26262 project without HARA file")
}

//fusa:test REQ-HARA012
func TestHARA002_IncompleteRisk(t *testing.T) {
	dir := t.TempDir()
	h := &hara.HARA{
		Hazards: []hara.Hazard{
			{ID: "H-001", Description: "test", SafetyGoals: []string{"SG-001"},
				Risk: hara.RiskRating{Severity: hara.SeverityS2}},
		},
		SafetyGoals: []hara.SafetyGoal{{ID: "SG-001", ASIL: hara.ASILA}},
	}
	if err := hara.Save(filepath.Join(dir, hara.HARAFile), h); err != nil {
		t.Fatal(err)
	}
	if !findingsForRule(t, dir, "HARA002") {
		t.Error("HARA002 should fire for hazard with incomplete risk rating")
	}
}

//fusa:test REQ-HARA013
func TestHARA003_NoSafetyGoal(t *testing.T) {
	dir := t.TempDir()
	h := &hara.HARA{
		Hazards: []hara.Hazard{
			{ID: "H-001", Description: "test",
				Risk: hara.RiskRating{Severity: hara.SeverityS2, Exposure: hara.ExposureE3, Controllability: hara.ControllabilityC2}},
		},
	}
	if err := hara.Save(filepath.Join(dir, hara.HARAFile), h); err != nil {
		t.Fatal(err)
	}
	if !findingsForRule(t, dir, "HARA003") {
		t.Error("HARA003 should fire for hazard with no safety goal")
	}
}

//fusa:test REQ-HARA014
func TestHARA004_NoASIL(t *testing.T) {
	dir := t.TempDir()
	h := &hara.HARA{
		Hazards: []hara.Hazard{
			{ID: "H-001", Description: "test", SafetyGoals: []string{"SG-001"},
				Risk: hara.RiskRating{Severity: hara.SeverityS1, Exposure: hara.ExposureE2, Controllability: hara.ControllabilityC1}},
		},
		SafetyGoals: []hara.SafetyGoal{{ID: "SG-001", Description: "no ASIL"}},
	}
	if err := hara.Save(filepath.Join(dir, hara.HARAFile), h); err != nil {
		t.Fatal(err)
	}
	if !findingsForRule(t, dir, "HARA004") {
		t.Error("HARA004 should fire for safety goal with no ASIL")
	}
}

//fusa:test REQ-HARA011
func TestHARA_Descriptions(t *testing.T) {
	ruleIDs := []string{"HARA001", "HARA002", "HARA003", "HARA004", "HARA005"}
	for _, id := range ruleIDs {
		found := false
		for _, r := range engine.Default.Rules() {
			if r.ID() == id {
				found = true
				if r.Description() == "" {
					t.Errorf("%s: Description() returned empty string", id)
				}
			}
		}
		if !found {
			t.Errorf("%s not registered in engine", id)
		}
	}
}

// ─── HARA005 — ASIL consistency ───────────────────────────────────────────────

func findingsForRuleWithCfg(t *testing.T, dir string, ruleIDStr string, cfg *config.Config) bool {
	t.Helper()
	result, err := engine.Default.Run(context.Background(), dir, cfg)
	if err != nil {
		t.Fatalf("engine.Run: %v", err)
	}
	for _, f := range result.Findings {
		if f.RuleID == ruleIDStr {
			return true
		}
	}
	return false
}

func writeHARAWithASIL(t *testing.T, dir string, hazardASIL hara.ASIL) {
	t.Helper()
	h := &hara.HARA{
		Project:  "test",
		Standard: "ISO 26262",
		Hazards: []hara.Hazard{{
			ID:          "H-001",
			Description: "test hazard",
			Risk: hara.RiskRating{
				Severity:        hara.SeverityS2,
				Exposure:        hara.ExposureE4,
				Controllability: hara.ControllabilityC2,
				ASIL:            hazardASIL,
			},
			SafetyGoals: []string{"SG-001"},
		}},
		SafetyGoals: []hara.SafetyGoal{{
			ID:          "SG-001",
			Description: "safety goal",
			ASIL:        hazardASIL,
		}},
	}
	if err := hara.Save(filepath.Join(dir, hara.HARAFile), h); err != nil {
		t.Fatal(err)
	}
}

//fusa:test REQ-HARA015
func TestHARA005_FiresWhenHazardASILExceedsProject(t *testing.T) {
	dir := t.TempDir()
	writeHARAWithASIL(t, dir, hara.ASILC)
	cfg := config.Default("github.com/x/y", "y")
	cfg.Project.ASIL = "ASIL-A" // project declares ASIL-A but hazard is ASIL-C
	if !findingsForRuleWithCfg(t, dir, "HARA005", cfg) {
		t.Error("HARA005 should fire when hazard ASIL-C > project ASIL-A")
	}
}

//fusa:test REQ-HARA015
func TestHARA005_SilentWhenHazardASILMeetsProject(t *testing.T) {
	dir := t.TempDir()
	writeHARAWithASIL(t, dir, hara.ASILB)
	cfg := config.Default("github.com/x/y", "y")
	cfg.Project.ASIL = "ASIL-B" // project matches highest hazard
	if findingsForRuleWithCfg(t, dir, "HARA005", cfg) {
		t.Error("HARA005 should not fire when project ASIL >= hazard ASIL")
	}
}

//fusa:test REQ-HARA015
func TestHARA005_SilentWhenProjectASILHigher(t *testing.T) {
	dir := t.TempDir()
	writeHARAWithASIL(t, dir, hara.ASILA)
	cfg := config.Default("github.com/x/y", "y")
	cfg.Project.ASIL = "ASIL-D"
	if findingsForRuleWithCfg(t, dir, "HARA005", cfg) {
		t.Error("HARA005 should not fire when project ASIL-D >= hazard ASIL-A")
	}
}

//fusa:test REQ-HARA015
func TestHARA005_SilentWhenNoHARAFile(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default("github.com/x/y", "y")
	cfg.Project.ASIL = "ASIL-A"
	if findingsForRuleWithCfg(t, dir, "HARA005", cfg) {
		t.Error("HARA005 should not fire when no HARA file present")
	}
}

//fusa:test REQ-HARA015
func TestHARA005_SilentWhenNoProjectASIL(t *testing.T) {
	dir := t.TempDir()
	writeHARAWithASIL(t, dir, hara.ASILC)
	cfg := config.Default("github.com/x/y", "y")
	cfg.Project.ASIL = "" // no ASIL declared
	if findingsForRuleWithCfg(t, dir, "HARA005", cfg) {
		t.Error("HARA005 should not fire when project has no ASIL declared")
	}
}

// ─── HARA008: risk.asil cross-validated against DetermineASIL(S,E,C) ──────────

//fusa:test REQ-HARA024
func TestValidateASIL_MismatchFlagged(t *testing.T) {
	h := &hara.HARA{Hazards: []hara.Hazard{{
		ID: "H-001",
		Risk: hara.RiskRating{
			Severity: hara.SeverityS1, Exposure: hara.ExposureE1, Controllability: hara.ControllabilityC1,
			ASIL: hara.ASILD, // S1×E1×C1 derives QM, not ASIL-D
		},
	}}}
	findings := hara.ValidateASIL(h)
	if len(findings) != 1 {
		t.Fatalf("expected 1 mismatch finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].HazardID != "H-001" {
		t.Errorf("HazardID = %q, want H-001", findings[0].HazardID)
	}
}

//fusa:test REQ-HARA024
func TestValidateASIL_MatchingASILNotFlagged(t *testing.T) {
	h := &hara.HARA{Hazards: []hara.Hazard{{
		ID: "H-001",
		Risk: hara.RiskRating{
			Severity: hara.SeverityS2, Exposure: hara.ExposureE4, Controllability: hara.ControllabilityC2,
			ASIL: hara.ASILB, // S2+E4+C2 = 8 → ASIL-B — matches
		},
	}}}
	if findings := hara.ValidateASIL(h); len(findings) != 0 {
		t.Errorf("expected no findings for a correctly-derived ASIL, got %+v", findings)
	}
}

//fusa:test REQ-HARA024
func TestValidateASIL_IncompleteSECSkipped(t *testing.T) {
	// A hazard with an incomplete S/E/C rating is HARA002's job, not
	// HARA008's — DetermineASIL would otherwise report a misleading
	// "should be QM" for missing inputs rather than a genuine mismatch.
	h := &hara.HARA{Hazards: []hara.Hazard{{
		ID:   "H-001",
		Risk: hara.RiskRating{Severity: hara.SeverityS2, ASIL: hara.ASILC}, // E/C missing
	}}}
	if findings := hara.ValidateASIL(h); len(findings) != 0 {
		t.Errorf("expected ValidateASIL to skip a hazard with incomplete S/E/C, got %+v", findings)
	}
}

//fusa:test REQ-HARA024
func TestValidateASIL_EmptyASILSkipped(t *testing.T) {
	h := &hara.HARA{Hazards: []hara.Hazard{{
		ID: "H-001",
		Risk: hara.RiskRating{
			Severity: hara.SeverityS2, Exposure: hara.ExposureE4, Controllability: hara.ControllabilityC2,
			// ASIL left empty — nothing to cross-check yet.
		},
	}}}
	if findings := hara.ValidateASIL(h); len(findings) != 0 {
		t.Errorf("expected no findings when risk.asil is unset, got %+v", findings)
	}
}

func writeHARAWithMismatchedASIL(t *testing.T, dir string) {
	t.Helper()
	h := &hara.HARA{
		Project:  "test",
		Standard: "iso26262",
		Hazards: []hara.Hazard{{
			ID:          "H-001",
			Description: "test hazard",
			Risk: hara.RiskRating{
				Severity: hara.SeverityS1, Exposure: hara.ExposureE1, Controllability: hara.ControllabilityC1,
				ASIL: hara.ASILD, // S1×E1×C1 derives QM — a false ASIL-D claim
			},
			SafetyGoals: []string{"SG-001"},
		}},
		SafetyGoals: []hara.SafetyGoal{{ID: "SG-001", Description: "goal", ASIL: hara.ASILD}},
	}
	if err := hara.Save(filepath.Join(dir, hara.HARAFile), h); err != nil {
		t.Fatal(err)
	}
}

//fusa:test REQ-HARA024
func TestHARA008_FiresOnMismatchedASIL(t *testing.T) {
	dir := t.TempDir()
	writeHARAWithMismatchedASIL(t, dir)
	if !findingsForRule(t, dir, "HARA008") {
		t.Error("HARA008 should fire when a hazard's risk.asil disagrees with its S/E/C-derived ASIL")
	}
}

//fusa:test REQ-HARA024
func TestHARA008_SilentWhenASILMatches(t *testing.T) {
	dir := t.TempDir()
	writeHARAWithASIL(t, dir, hara.ASILB) // S2+E4+C2 = 8 genuinely derives ASIL-B
	if findingsForRule(t, dir, "HARA008") {
		t.Error("HARA008 should not fire when risk.asil matches DetermineASIL(S,E,C)")
	}
}

// Validate's rendered "Gaps" section (hara show) should surface an ASIL
// mismatch too, not just the engine rule — see go-FuSa#62.
//
//fusa:test REQ-HARA009
//fusa:test REQ-HARA024
func TestValidate_IncludesASILMismatch(t *testing.T) {
	h := &hara.HARA{Hazards: []hara.Hazard{{
		ID: "H-001",
		Risk: hara.RiskRating{
			Severity: hara.SeverityS1, Exposure: hara.ExposureE1, Controllability: hara.ControllabilityC1,
			ASIL: hara.ASILD,
		},
	}}}
	findings := hara.Validate(h)
	found := false
	for _, f := range findings {
		if f.HazardID == "H-001" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected Validate to include the ASIL mismatch finding, got %+v", findings)
	}
}

// ─── standard field canonicalisation (x-FuSa spec §2.4.1) ─────────────────────

//fusa:test REQ-HARA025
func TestLoad_NormalizesLegacyStandardDisplayString(t *testing.T) {
	dir := t.TempDir()
	h := &hara.HARA{Project: "p", Standard: "ISO 26262"}
	if err := hara.Save(filepath.Join(dir, hara.HARAFile), h); err != nil {
		t.Fatal(err)
	}
	loaded, err := hara.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Standard != "iso26262" {
		t.Errorf("Standard = %q, want canonical id %q", loaded.Standard, "iso26262")
	}
}

//fusa:test REQ-HARA025
func TestLoad_CanonicalStandardUnchanged(t *testing.T) {
	dir := t.TempDir()
	h := &hara.HARA{Project: "p", Standard: "iso26262"}
	if err := hara.Save(filepath.Join(dir, hara.HARAFile), h); err != nil {
		t.Fatal(err)
	}
	loaded, err := hara.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Standard != "iso26262" {
		t.Errorf("Standard = %q, want unchanged %q", loaded.Standard, "iso26262")
	}
}

//fusa:test REQ-HARA025
func TestLoad_UnrecognisedStandardPassedThrough(t *testing.T) {
	dir := t.TempDir()
	h := &hara.HARA{Project: "p", Standard: "some-future-standard"}
	if err := hara.Save(filepath.Join(dir, hara.HARAFile), h); err != nil {
		t.Fatal(err)
	}
	loaded, err := hara.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Standard != "some-future-standard" {
		t.Errorf("Standard = %q, want unrecognised id passed through verbatim", loaded.Standard)
	}
}
