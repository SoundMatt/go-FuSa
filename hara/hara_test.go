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
		// S1 spot checks
		{hara.SeverityS1, hara.ExposureE4, hara.ControllabilityC3, hara.ASILB},
		{hara.SeverityS1, hara.ExposureE4, hara.ControllabilityC2, hara.ASILA},
		{hara.SeverityS1, hara.ExposureE4, hara.ControllabilityC1, hara.ASILQM},
		// S2 spot checks
		{hara.SeverityS2, hara.ExposureE4, hara.ControllabilityC3, hara.ASILD},
		{hara.SeverityS2, hara.ExposureE4, hara.ControllabilityC2, hara.ASILC},
		{hara.SeverityS2, hara.ExposureE4, hara.ControllabilityC1, hara.ASILB},
		{hara.SeverityS2, hara.ExposureE4, hara.ControllabilityC0, hara.ASILA},
		{hara.SeverityS2, hara.ExposureE3, hara.ControllabilityC2, hara.ASILB},
		// S3 spot checks
		{hara.SeverityS3, hara.ExposureE4, hara.ControllabilityC0, hara.ASILC},
		{hara.SeverityS3, hara.ExposureE4, hara.ControllabilityC1, hara.ASILD},
		{hara.SeverityS3, hara.ExposureE4, hara.ControllabilityC2, hara.ASILD},
		{hara.SeverityS3, hara.ExposureE4, hara.ControllabilityC3, hara.ASILD},
		{hara.SeverityS3, hara.ExposureE1, hara.ControllabilityC0, hara.ASILQM},
		{hara.SeverityS3, hara.ExposureE1, hara.ControllabilityC1, hara.ASILA},
		{hara.SeverityS3, hara.ExposureE1, hara.ControllabilityC3, hara.ASILC},
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

func TestDetermineASIL_EmptySeverity(t *testing.T) {
	if got := hara.DetermineASIL("", hara.ExposureE4, hara.ControllabilityC3); got != hara.ASILQM {
		t.Errorf("empty severity should be QM, got %s", got)
	}
}

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
					ASIL:            hara.ASILB,
				},
				SafetyGoals: []string{"SG-001"},
			},
		},
		SafetyGoals: []hara.SafetyGoal{
			{ID: "SG-001", Description: "goal", ASIL: hara.ASILB},
		},
	}
	findings := hara.Validate(h)
	if len(findings) != 0 {
		t.Errorf("complete HARA should have no gaps, got: %v", findings)
	}
}

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

func TestRender_Unknown(t *testing.T) {
	h := &hara.HARA{}
	var buf bytes.Buffer
	if err := hara.Render(&buf, h, "pdf"); err == nil {
		t.Error("expected error for unknown format pdf")
	}
}

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

func TestHARA001_NoFile(t *testing.T) {
	dir := t.TempDir()
	if !findingsForRule(t, dir, "HARA001") {
		t.Error("HARA001 should fire when .fusa-hara.json is absent")
	}
}

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

func TestHARA005_FiresWhenHazardASILExceedsProject(t *testing.T) {
	dir := t.TempDir()
	writeHARAWithASIL(t, dir, hara.ASILC)
	cfg := config.Default("github.com/x/y", "y")
	cfg.Project.ASIL = "ASIL-A" // project declares ASIL-A but hazard is ASIL-C
	if !findingsForRuleWithCfg(t, dir, "HARA005", cfg) {
		t.Error("HARA005 should fire when hazard ASIL-C > project ASIL-A")
	}
}

func TestHARA005_SilentWhenHazardASILMeetsProject(t *testing.T) {
	dir := t.TempDir()
	writeHARAWithASIL(t, dir, hara.ASILB)
	cfg := config.Default("github.com/x/y", "y")
	cfg.Project.ASIL = "ASIL-B" // project matches highest hazard
	if findingsForRuleWithCfg(t, dir, "HARA005", cfg) {
		t.Error("HARA005 should not fire when project ASIL >= hazard ASIL")
	}
}

func TestHARA005_SilentWhenProjectASILHigher(t *testing.T) {
	dir := t.TempDir()
	writeHARAWithASIL(t, dir, hara.ASILA)
	cfg := config.Default("github.com/x/y", "y")
	cfg.Project.ASIL = "ASIL-D"
	if findingsForRuleWithCfg(t, dir, "HARA005", cfg) {
		t.Error("HARA005 should not fire when project ASIL-D >= hazard ASIL-A")
	}
}

func TestHARA005_SilentWhenNoHARAFile(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default("github.com/x/y", "y")
	cfg.Project.ASIL = "ASIL-A"
	if findingsForRuleWithCfg(t, dir, "HARA005", cfg) {
		t.Error("HARA005 should not fire when no HARA file present")
	}
}

func TestHARA005_SilentWhenNoProjectASIL(t *testing.T) {
	dir := t.TempDir()
	writeHARAWithASIL(t, dir, hara.ASILC)
	cfg := config.Default("github.com/x/y", "y")
	cfg.Project.ASIL = "" // no ASIL declared
	if findingsForRuleWithCfg(t, dir, "HARA005", cfg) {
		t.Error("HARA005 should not fire when project has no ASIL declared")
	}
}
