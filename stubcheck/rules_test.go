package stubcheck_test

import (
	"context"
	"testing"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/config"
	"github.com/SoundMatt/go-FuSa/engine"
	"github.com/SoundMatt/go-FuSa/fmea"
	"github.com/SoundMatt/go-FuSa/hara"
	"github.com/SoundMatt/go-FuSa/safetycase"
	"github.com/SoundMatt/go-FuSa/sas"
	"github.com/SoundMatt/go-FuSa/stubcheck"
	"github.com/SoundMatt/go-FuSa/tara"
	"github.com/SoundMatt/go-FuSa/testutil"
)

func findByRule(findings []fusa.Finding, ruleID string) []fusa.Finding {
	var out []fusa.Finding
	for _, f := range findings {
		if f.RuleID == ruleID {
			out = append(out, f)
		}
	}
	return out
}

//fusa:test REQ-STUB010
func TestRulePlaceholder_DetectsHaraTemplate(t *testing.T) {
	haraJSON := `{
  "project": "test", "standard": "iso26262",
  "operationalSituations": [{"id": "OS-001", "description": "Normal operation"}],
  "hazards": [{
    "id": "H-001",
    "description": "Example hazard — replace with project-specific hazard",
    "situations": ["OS-001"],
    "risk": {"severity": "S2", "exposure": "E3", "controllability": "C2", "asil": "ASIL-B"},
    "safetyGoals": ["SG-001"]
  }],
  "safetyGoals": [{"id": "SG-001", "description": "goal", "hazards": ["H-001"], "asil": "ASIL-B", "fssrRefs": ["REQ-001"]}]
}`
	dir := testutil.ProjectDir(t, map[string]string{hara.HARAFile: haraJSON})

	result, err := engine.Default.Run(context.Background(), dir, config.Default("", "test"))
	if err != nil {
		t.Fatalf("engine.Run: %v", err)
	}
	matches := findByRule(result.Findings, stubcheck.RuleStub001)
	if len(matches) == 0 {
		t.Fatal("expected at least one FUSA-STUB001 finding for the placeholder hazard description")
	}
	for _, f := range matches {
		if f.Severity != fusa.SeverityError {
			t.Errorf("FUSA-STUB001 finding severity = %q, want ERROR", f.Severity)
		}
		if f.Location.File != hara.HARAFile {
			t.Errorf("FUSA-STUB001 finding file = %q, want %q", f.Location.File, hara.HARAFile)
		}
	}
}

//fusa:test REQ-STUB011
func TestRuleBlanketFallback_CleanHaraProducesNoFinding(t *testing.T) {
	// 10 hazards, every description distinct — should not trip rule B.
	hazards := ""
	safetyGoals := ""
	for i := 1; i <= 10; i++ {
		if i > 1 {
			hazards += ","
			safetyGoals += ","
		}
		hazards += `{"id":"H-00` + itoa(i) + `","description":"distinct hazard number ` + itoa(i) + ` with its own specific wording","situations":[],"risk":{"severity":"S1","exposure":"E1","controllability":"C1","asil":"QM"},"safetyGoals":["SG-00` + itoa(i) + `"]}`
		safetyGoals += `{"id":"SG-00` + itoa(i) + `","description":"distinct goal ` + itoa(i) + `","hazards":["H-00` + itoa(i) + `"],"asil":"QM","fssrRefs":["REQ-00` + itoa(i) + `"]}`
	}
	haraJSON := `{"project":"test","standard":"iso26262","operationalSituations":[],"hazards":[` + hazards + `],"safetyGoals":[` + safetyGoals + `]}`
	dir := testutil.ProjectDir(t, map[string]string{hara.HARAFile: haraJSON})

	result, err := engine.Default.Run(context.Background(), dir, config.Default("", "test"))
	if err != nil {
		t.Fatalf("engine.Run: %v", err)
	}
	if matches := findByRule(result.Findings, stubcheck.RuleStub002); len(matches) != 0 {
		t.Errorf("expected no FUSA-STUB002 findings for distinct hazard text, got %+v", matches)
	}
	if matches := findByRule(result.Findings, stubcheck.RuleStub001); len(matches) != 0 {
		t.Errorf("expected no FUSA-STUB001 findings for clean text, got %+v", matches)
	}
}

//fusa:test REQ-STUB011
func TestRuleBlanketFallback_RepeatedHazardTextWarns(t *testing.T) {
	hazards := ""
	safetyGoals := ""
	for i := 1; i <= 11; i++ {
		if i > 1 {
			hazards += ","
			safetyGoals += ","
		}
		// Every hazard shares the exact same description — a blanket fallback.
		hazards += `{"id":"H-00` + itoa(i) + `","description":"generic hazard text","situations":[],"risk":{"severity":"S1","exposure":"E1","controllability":"C1","asil":"QM"},"safetyGoals":["SG-00` + itoa(i) + `"]}`
		safetyGoals += `{"id":"SG-00` + itoa(i) + `","description":"distinct goal ` + itoa(i) + `","hazards":["H-00` + itoa(i) + `"],"asil":"QM","fssrRefs":["REQ-00` + itoa(i) + `"]}`
	}
	haraJSON := `{"project":"test","standard":"iso26262","operationalSituations":[],"hazards":[` + hazards + `],"safetyGoals":[` + safetyGoals + `]}`
	dir := testutil.ProjectDir(t, map[string]string{hara.HARAFile: haraJSON})

	result, err := engine.Default.Run(context.Background(), dir, config.Default("", "test"))
	if err != nil {
		t.Fatalf("engine.Run: %v", err)
	}
	matches := findByRule(result.Findings, stubcheck.RuleStub002)
	if len(matches) == 0 {
		t.Fatal("expected a FUSA-STUB002 finding for the repeated hazard description")
	}
	for _, f := range matches {
		if f.Severity != fusa.SeverityWarning {
			t.Errorf("FUSA-STUB002 finding severity = %q, want WARNING", f.Severity)
		}
	}
}

func itoa(n int) string {
	if n < 10 {
		return string(rune('0' + n))
	}
	return string(rune('0'+n/10)) + string(rune('0'+n%10))
}

// ─── per-artifact field extraction ────────────────────────────────────────────

//fusa:test REQ-STUB006
func TestFmeaFields(t *testing.T) {
	r := &fmea.Report{Entries: []fmea.Entry{
		{FailureMode: "mode-a", Effect: "effect-a", Cause: "cause-a"},
		{FailureMode: "mode-b", Effect: "effect-b", Cause: ""},
	}}
	fields := stubcheck.FmeaFields(r)
	if len(fields) != 3 {
		t.Fatalf("expected 3 fields, got %d", len(fields))
	}
	if fields[0].Values[0] != "mode-a" || fields[0].Values[1] != "mode-b" {
		t.Errorf("unexpected failureMode values: %+v", fields[0].Values)
	}
}

//fusa:test REQ-STUB007
func TestTaraFields(t *testing.T) {
	r := &tara.Report{Entries: []tara.ThreatEntry{
		{Threat: "threat-a", Asset: "asset-a"},
		{Threat: "threat-b", Asset: "asset-b"},
	}}
	fields := stubcheck.TaraFields(r)
	if len(fields) != 2 {
		t.Fatalf("expected 2 fields, got %d", len(fields))
	}
	if fields[0].Values[0] != "threat-a" {
		t.Errorf("unexpected threat value: %q", fields[0].Values[0])
	}
}

//fusa:test REQ-STUB008
func TestSafetyCaseFields(t *testing.T) {
	sc := &safetycase.SafetyCase{Nodes: []safetycase.Node{
		{ID: "G1", Type: safetycase.NodeGoal, Text: "goal text"},
	}}
	fields := stubcheck.SafetyCaseFields(sc)
	if len(fields) != 1 || fields[0].Values[0] != "goal text" {
		t.Errorf("unexpected fields: %+v", fields)
	}
}

//fusa:test REQ-STUB009
func TestSasFields(t *testing.T) {
	s := &sas.SAS{Deviations: []string{"deviation one"}}
	fields := stubcheck.SasFields(s)
	if len(fields) != 1 || fields[0].Values[0] != "deviation one" {
		t.Errorf("unexpected fields: %+v", fields)
	}
}

//fusa:test REQ-STUB005
//fusa:test REQ-STUB006
//fusa:test REQ-STUB007
//fusa:test REQ-STUB008
func TestLoadArtifacts_AllPresent(t *testing.T) {
	haraJSON := `{"project":"t","standard":"iso26262","operationalSituations":[],"hazards":[],"safetyGoals":[]}`
	fmeaJSON := `{"entries":[{"failureMode":"m","effect":"e"}]}`
	taraJSON := `{"threats":[{"threat":"t","asset":"a"}]}`
	scJSON := `{"nodes":[{"id":"G1","type":"goal","text":"txt"}]}`
	dir := testutil.ProjectDir(t, map[string]string{
		hara.HARAFile:           haraJSON,
		fmea.FMEAFile:           fmeaJSON,
		tara.TARAFile:           taraJSON,
		safetycase.SafeCaseFile: scJSON,
	})
	result, err := engine.Default.Run(context.Background(), dir, config.Default("", "test"))
	if err != nil {
		t.Fatalf("engine.Run: %v", err)
	}
	_ = result // just exercising loadArtifacts across every known artifact type without error
}
