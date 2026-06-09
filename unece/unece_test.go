package unece_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SoundMatt/go-FuSa/config"
	"github.com/SoundMatt/go-FuSa/engine"
	"github.com/SoundMatt/go-FuSa/unece"
)

// TestAssess_EmptyDir verifies TC-1 through TC-6 are GAP and TC-7 through TC-9 are MANUAL.
//
//fusa:test REQ-UNECE-001
func TestAssess_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	rep, err := unece.Assess(dir)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	gapIDs := map[string]bool{}
	manualIDs := map[string]bool{}
	for _, cat := range rep.Categories {
		switch cat.Status {
		case "GAP":
			gapIDs[cat.ID] = true
		case "MANUAL":
			manualIDs[cat.ID] = true
		}
	}

	for _, id := range []string{"TC-1", "TC-2", "TC-3", "TC-4", "TC-5", "TC-6"} {
		if !gapIDs[id] {
			t.Errorf("expected %s to be GAP in empty dir", id)
		}
	}
	for _, id := range []string{"TC-7", "TC-8", "TC-9"} {
		if !manualIDs[id] {
			t.Errorf("expected %s to be MANUAL", id)
		}
	}
}

// TestAssess_WithEvidence verifies that providing evidence files results in passes.
//
//fusa:test REQ-UNECE-001
func TestAssess_WithEvidence(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{"tara.json", "provenance.json", "check-report.json", "sbom.json"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := unece.Assess(dir)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if rep.Pass == 0 {
		t.Error("expected PASS categories when evidence present")
	}
	// TC-2 uses provenance.json, TC-4 uses check-report.json, TC-5 uses sbom.json
	for _, cat := range rep.Categories {
		switch cat.ID {
		case "TC-2", "TC-4", "TC-5":
			if cat.Status != "PASS" {
				t.Errorf("%s expected PASS, got %s", cat.ID, cat.Status)
			}
		}
	}
}

// TestUNECE001_Description verifies the rule has a non-empty description.
//
//fusa:test REQ-UNECE-001
func TestUNECE001_Description(t *testing.T) {
	for _, r := range engine.Default.Rules() {
		if r.ID() == "UNECE001" {
			if r.Description() == "" {
				t.Error("UNECE001 Description empty")
			}
			return
		}
	}
	t.Error("UNECE001 not registered")
}

// TestUNECE001_Run verifies the rule fires for ISO21434 project without tara.json.
//
//fusa:test REQ-UNECE-001
func TestUNECE001_Run(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default("github.com/example/test", "test")
	cfg.Project.Standard = "ISO21434"

	for _, r := range engine.Default.Rules() {
		if r.ID() == "UNECE001" {
			findings, err := r.Run(context.Background(), dir, cfg)
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if len(findings) == 0 {
				t.Error("expected finding when tara.json absent and standard is ISO21434")
			}
			// Write tara.json — should go silent
			if werr := os.WriteFile(filepath.Join(dir, "tara.json"), []byte("{}"), 0o644); werr != nil {
				t.Fatal(werr)
			}
			findings2, err := r.Run(context.Background(), dir, cfg)
			if err != nil {
				t.Fatalf("Run (with tara.json): %v", err)
			}
			if len(findings2) != 0 {
				t.Error("expected no findings when tara.json present")
			}
			return
		}
	}
	t.Error("UNECE001 not registered")
}

// TestUNECE001_Run_NilCfg verifies the rule is silent with nil config.
//
//fusa:test REQ-UNECE-001
func TestUNECE001_Run_NilCfg(t *testing.T) {
	dir := t.TempDir()
	for _, r := range engine.Default.Rules() {
		if r.ID() == "UNECE001" {
			findings, err := r.Run(context.Background(), dir, nil)
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if len(findings) != 0 {
				t.Error("expected no findings with nil config")
			}
			return
		}
	}
	t.Error("UNECE001 not registered")
}

// TestRender_Text verifies text rendering runs without error.
//
//fusa:test REQ-UNECE-001
func TestRender_Text(t *testing.T) {
	dir := t.TempDir()
	rep, err := unece.Assess(dir)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	var buf bytes.Buffer
	if err := unece.Render(&buf, rep, "text"); err != nil {
		t.Fatalf("Render text: %v", err)
	}
	if !strings.Contains(buf.String(), "UN R.155") {
		t.Error("expected 'UN R.155' in text output")
	}
}

// TestRender_JSON verifies JSON rendering produces valid JSON.
//
//fusa:test REQ-UNECE-001
func TestRender_JSON(t *testing.T) {
	dir := t.TempDir()
	rep, err := unece.Assess(dir)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	var buf bytes.Buffer
	if err := unece.Render(&buf, rep, "json"); err != nil {
		t.Fatalf("Render json: %v", err)
	}
	var parsed unece.Report
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("Render json: invalid JSON: %v", err)
	}
	if len(parsed.Categories) == 0 {
		t.Error("expected categories in JSON output")
	}
}

// TestRender_UnknownFormat verifies error on unknown format.
//
//fusa:test REQ-UNECE-001
func TestRender_UnknownFormat(t *testing.T) {
	dir := t.TempDir()
	rep, _ := unece.Assess(dir)
	var buf bytes.Buffer
	if err := unece.Render(&buf, rep, "xml"); err == nil {
		t.Error("expected error for unknown format")
	}
}
