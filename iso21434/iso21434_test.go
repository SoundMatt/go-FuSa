package iso21434_test

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
	"github.com/SoundMatt/go-FuSa/iso21434"
)

// TestAssess_EmptyDir expects gaps for all automatable objectives that apply
// at CAL-1, and MANUAL for manual objectives.
func TestAssess_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	rep, err := iso21434.Assess(dir, "CAL-1")
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if rep.Gap == 0 {
		t.Error("expected gaps in empty directory")
	}
	if rep.Manual == 0 {
		t.Error("expected MANUAL objectives")
	}
}

// TestAssess_WithEvidence checks that providing evidence files results in passes.
func TestAssess_WithEvidence(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{"tara.json", "vuln.json", "sbom.json", "provenance.json",
		".fusa-reqs.json", "check-report.json"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := iso21434.Assess(dir, "CAL-1")
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if rep.Pass == 0 {
		t.Error("expected PASS objectives when evidence present")
	}
}

// TestAssess_CAL4_HigherMinCAL verifies CAL-4 objectives with MinCAL:2 apply.
func TestAssess_CAL4_HigherMinCAL(t *testing.T) {
	dir := t.TempDir()
	// Write tara.json so objectives that reference it pass
	if err := os.WriteFile(filepath.Join(dir, "tara.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := iso21434.Assess(dir, "CAL-4")
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	// At CAL-4, MinCAL:2 objectives should apply (no N/A due to CAL level)
	for _, obj := range rep.Objectives {
		if obj.EvidenceFile != "" && obj.MinCAL == 2 {
			if obj.Status == iso21434.StatusNA {
				t.Errorf("objective %s should not be N/A at CAL-4", obj.ID)
			}
		}
	}
}

// TestAssess_CAL1_NA verifies objectives with MinCAL:2 are N/A at CAL-1.
func TestAssess_CAL1_NA(t *testing.T) {
	dir := t.TempDir()
	rep, err := iso21434.Assess(dir, "CAL-1")
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	hasNA := false
	for _, obj := range rep.Objectives {
		if obj.MinCAL >= 2 && obj.EvidenceFile != "" && obj.Status == iso21434.StatusNA {
			hasNA = true
			break
		}
	}
	if !hasNA {
		t.Error("expected at least one N/A objective at CAL-1 for MinCAL>=2 objectives")
	}
}

// TestISO21434001_Description checks the rule description is non-empty.
func TestISO21434001_Description(t *testing.T) {
	for _, r := range engine.Default.Rules() {
		if r.ID() == "ISO21434001" {
			if r.Description() == "" {
				t.Error("ISO21434001 Description empty")
			}
			return
		}
	}
	t.Error("ISO21434001 not registered")
}

// TestISO21434001_Run verifies rule fires for ISO21434 project without tara.json.
func TestISO21434001_Run(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default("github.com/example/test", "test")
	cfg.Project.Standard = "ISO21434"

	for _, r := range engine.Default.Rules() {
		if r.ID() == "ISO21434001" {
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
	t.Error("ISO21434001 not registered")
}

// TestISO21434001_Run_NonISO21434 verifies rule is silent for non-ISO21434 projects.
func TestISO21434001_Run_NonISO21434(t *testing.T) {
	dir := t.TempDir()
	for _, r := range engine.Default.Rules() {
		if r.ID() == "ISO21434001" {
			cfg := config.Default("github.com/example/test", "test")
			cfg.Project.Standard = "ISO26262"
			findings, err := r.Run(context.Background(), dir, cfg)
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if len(findings) != 0 {
				t.Error("expected no findings for non-ISO21434 project")
			}
			return
		}
	}
	t.Error("ISO21434001 not registered")
}

// TestISO21434001_Run_NilCfg verifies rule is silent with nil config.
func TestISO21434001_Run_NilCfg(t *testing.T) {
	dir := t.TempDir()
	for _, r := range engine.Default.Rules() {
		if r.ID() == "ISO21434001" {
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
	t.Error("ISO21434001 not registered")
}

// TestRender_Text verifies text rendering runs without error.
func TestRender_Text(t *testing.T) {
	dir := t.TempDir()
	rep, err := iso21434.Assess(dir, "CAL-1")
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	var buf bytes.Buffer
	if err := iso21434.Render(&buf, rep, "text"); err != nil {
		t.Fatalf("Render text: %v", err)
	}
	if !strings.Contains(buf.String(), "ISO 21434") {
		t.Error("expected 'ISO 21434' in text output")
	}
}

// TestRender_JSON verifies JSON rendering produces valid JSON.
func TestRender_JSON(t *testing.T) {
	dir := t.TempDir()
	rep, err := iso21434.Assess(dir, "CAL-2")
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	var buf bytes.Buffer
	if err := iso21434.Render(&buf, rep, "json"); err != nil {
		t.Fatalf("Render json: %v", err)
	}
	var parsed iso21434.Report
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("Render json: invalid JSON: %v", err)
	}
	if len(parsed.Objectives) == 0 {
		t.Error("expected objectives in JSON output")
	}
}

// TestRender_UnknownFormat verifies error on unknown format.
func TestRender_UnknownFormat(t *testing.T) {
	dir := t.TempDir()
	rep, _ := iso21434.Assess(dir, "CAL-1")
	var buf bytes.Buffer
	if err := iso21434.Render(&buf, rep, "xml"); err == nil {
		t.Error("expected error for unknown format")
	}
}

// TestEngineRun_ISO21434001 verifies the engine fires ISO21434001 for ISO21434 projects.
func TestEngineRun_ISO21434001(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/test\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default("example.com/test", "test")
	cfg.Project.Standard = "ISO21434"

	result, err := engine.Default.Run(context.Background(), dir, cfg)
	if err != nil {
		t.Fatalf("engine.Run: %v", err)
	}
	found := false
	for _, f := range result.Findings {
		if f.RuleID == "ISO21434001" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected ISO21434001 finding in engine run for ISO21434 project without tara.json")
	}
}
