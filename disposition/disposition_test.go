package disposition_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/SoundMatt/go-FuSa/disposition"
)

func TestLoad_MissingFile(t *testing.T) {
	dir := t.TempDir()
	log, err := disposition.Load(dir)
	if err != nil {
		t.Fatalf("Load missing file: %v", err)
	}
	if log == nil {
		t.Fatal("expected non-nil log")
	}
	if len(log.Entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(log.Entries))
	}
}

func TestLoad_InvalidFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, disposition.DispositionsFile), []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := disposition.Load(dir)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestLoad_ValidFile(t *testing.T) {
	dir := t.TempDir()
	content := `{"project":"p","entries":[{"ruleID":"LINT001","rationale":"accepted","reviewer":"Alice","date":"2026-01-01T00:00:00Z","action":"accept"}]}`
	if err := os.WriteFile(filepath.Join(dir, disposition.DispositionsFile), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	log, err := disposition.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(log.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(log.Entries))
	}
	if log.Entries[0].RuleID != "LINT001" {
		t.Errorf("RuleID = %q", log.Entries[0].RuleID)
	}
}

func TestSave_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, disposition.DispositionsFile)
	log := &disposition.Log{
		Project: "test",
		Entries: []disposition.Entry{
			{
				RuleID:    "FUSA001",
				Rationale: "intentional",
				Reviewer:  "Bob",
				Date:      time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
				Action:    disposition.ActionAccept,
			},
		},
	}
	if err := disposition.Save(path, log); err != nil {
		t.Fatalf("Save: %v", err)
	}
	loaded, err := disposition.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(loaded.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(loaded.Entries))
	}
	if loaded.Entries[0].RuleID != "FUSA001" {
		t.Errorf("RuleID = %q", loaded.Entries[0].RuleID)
	}
}

func TestAdd_Dedup(t *testing.T) {
	log := &disposition.Log{}
	e1 := disposition.Entry{RuleID: "LINT001", Action: disposition.ActionAccept, Rationale: "first"}
	e2 := disposition.Entry{RuleID: "LINT001", Action: disposition.ActionAccept, Rationale: "updated"}
	e3 := disposition.Entry{RuleID: "LINT001", Action: disposition.ActionFix, Rationale: "fix"}

	log = disposition.Add(log, e1)
	if len(log.Entries) != 1 {
		t.Errorf("after first add: %d entries", len(log.Entries))
	}

	log = disposition.Add(log, e2)
	if len(log.Entries) != 1 {
		t.Errorf("after dedup add: %d entries", len(log.Entries))
	}
	if log.Entries[0].Rationale != "updated" {
		t.Errorf("Rationale = %q, want updated", log.Entries[0].Rationale)
	}

	// Different action = different entry
	log = disposition.Add(log, e3)
	if len(log.Entries) != 2 {
		t.Errorf("after different-action add: %d entries", len(log.Entries))
	}
}

func TestIsDispositioned(t *testing.T) {
	log := &disposition.Log{
		Entries: []disposition.Entry{
			{RuleID: "LINT001", Action: disposition.ActionAccept},
		},
	}
	if !disposition.IsDispositioned(log, "LINT001") {
		t.Error("LINT001 should be dispositioned")
	}
	if disposition.IsDispositioned(log, "LINT002") {
		t.Error("LINT002 should not be dispositioned")
	}
}

func TestRule_NoCheckReport(t *testing.T) {
	// Rule fires INFO when check-report.json is absent
	// We test this indirectly via the Load behaviour; the engine test verifies the rule
	dir := t.TempDir()
	log, err := disposition.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if log == nil {
		t.Error("expected non-nil log")
	}
}

func TestRule_UndispositionedError(t *testing.T) {
	dir := t.TempDir()
	// Write a check-report.json with an ERROR finding
	report := `[{"ruleId":"FUSA001","severity":"ERROR","message":"test"}]`
	if err := os.WriteFile(filepath.Join(dir, "check-report.json"), []byte(report), 0o644); err != nil {
		t.Fatal(err)
	}
	// No dispositions file — all errors should be undispositioned
	// We verify indirectly: load returns empty log, IsDispositioned returns false
	log, err := disposition.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if disposition.IsDispositioned(log, "FUSA001") {
		t.Error("FUSA001 should not be dispositioned without dispositions file")
	}
}

func TestRule_DispositionedError(t *testing.T) {
	dir := t.TempDir()
	report := `[{"ruleId":"FUSA001","severity":"ERROR","message":"test"}]`
	if err := os.WriteFile(filepath.Join(dir, "check-report.json"), []byte(report), 0o644); err != nil {
		t.Fatal(err)
	}
	// Write disposition
	log := &disposition.Log{Entries: []disposition.Entry{
		{RuleID: "FUSA001", Action: disposition.ActionAccept, Rationale: "intentional"},
	}}
	if err := disposition.Save(filepath.Join(dir, disposition.DispositionsFile), log); err != nil {
		t.Fatal(err)
	}
	loaded, _ := disposition.Load(dir)
	if !disposition.IsDispositioned(loaded, "FUSA001") {
		t.Error("FUSA001 should be dispositioned")
	}
}
