package pr_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SoundMatt/go-FuSa/pr"
)

func TestLoadSave_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "problems.json")

	log := &pr.Log{
		Project: "test-project",
		Reports: []pr.ProblemReport{
			{
				ID:       "PR-001",
				Title:    "First problem",
				Severity: pr.PRSeverityMinor,
				Status:   pr.StatusOpen,
				Created:  time.Now().UTC(),
				Updated:  time.Now().UTC(),
			},
		},
	}
	if err := pr.Save(path, log); err != nil {
		t.Fatalf("Save: %v", err)
	}
	loaded, err := pr.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Project != "test-project" {
		t.Errorf("Project = %q", loaded.Project)
	}
	if len(loaded.Reports) != 1 {
		t.Fatalf("len(Reports) = %d, want 1", len(loaded.Reports))
	}
	if loaded.Reports[0].ID != "PR-001" {
		t.Errorf("ID = %q", loaded.Reports[0].ID)
	}
}

func TestLoad_Missing(t *testing.T) {
	log, err := pr.Load("/does/not/exist/.fusa-problems.json")
	if err != nil {
		t.Fatalf("Load missing: %v", err)
	}
	if log == nil {
		t.Error("expected non-nil log for missing file")
	}
}

func TestAdd(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "problems.json")
	// Create empty log first
	if err := pr.Save(path, &pr.Log{Project: "proj"}); err != nil {
		t.Fatal(err)
	}
	report := pr.ProblemReport{
		ID:       "PR-002",
		Title:    "Second problem",
		Severity: pr.PRSeverityMajor,
		Status:   pr.StatusOpen,
	}
	if err := pr.Add(path, report); err != nil {
		t.Fatalf("Add: %v", err)
	}
	loaded, _ := pr.Load(path)
	if len(loaded.Reports) != 1 {
		t.Fatalf("expected 1 report after Add, got %d", len(loaded.Reports))
	}
	if loaded.Reports[0].ID != "PR-002" {
		t.Errorf("ID = %q", loaded.Reports[0].ID)
	}
}

func TestClose(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "problems.json")
	log := &pr.Log{
		Project: "proj",
		Reports: []pr.ProblemReport{
			{ID: "PR-003", Title: "TBF", Severity: pr.PRSeverityCritical, Status: pr.StatusOpen,
				Created: time.Now(), Updated: time.Now()},
		},
	}
	if err := pr.Save(path, log); err != nil {
		t.Fatal(err)
	}
	if err := pr.Close(path, "PR-003", "fixed in v1.2"); err != nil {
		t.Fatalf("Close: %v", err)
	}
	loaded, _ := pr.Load(path)
	if loaded.Reports[0].Status != pr.StatusClosed {
		t.Errorf("Status = %v, want closed", loaded.Reports[0].Status)
	}
	if loaded.Reports[0].Resolution != "fixed in v1.2" {
		t.Errorf("Resolution = %q", loaded.Reports[0].Resolution)
	}
}

func TestClose_NotFound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "problems.json")
	if err := pr.Save(path, &pr.Log{}); err != nil {
		t.Fatal(err)
	}
	if err := pr.Close(path, "NO-SUCH", ""); err == nil {
		t.Error("expected error closing non-existent ID")
	}
}

func TestRender_Text(t *testing.T) {
	log := &pr.Log{
		Project: "proj",
		Reports: []pr.ProblemReport{
			{ID: "PR-001", Title: "A bug", Severity: pr.PRSeverityMinor, Status: pr.StatusOpen,
				PhaseFound: pr.PhaseDevelopment, Created: time.Now(), Updated: time.Now()},
		},
	}
	var buf bytes.Buffer
	if err := pr.Render(&buf, log, "text"); err != nil {
		t.Fatalf("Render text: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "PR-001") {
		t.Error("missing PR-001 in text output")
	}
	if !strings.Contains(out, "1 open") {
		t.Error("missing open count")
	}
}

func TestRender_JSON(t *testing.T) {
	log := &pr.Log{Project: "p"}
	var buf bytes.Buffer
	if err := pr.Render(&buf, log, "json"); err != nil {
		t.Fatalf("Render json: %v", err)
	}
	if !strings.Contains(buf.String(), `"project"`) {
		t.Error("missing project field in JSON")
	}
}

func TestRender_InvalidFormat(t *testing.T) {
	if err := pr.Render(&bytes.Buffer{}, &pr.Log{}, "csv"); err == nil {
		t.Error("expected error for unsupported format")
	}
}

func TestPR001_Rule_NoFile(t *testing.T) {
	// Engine rule registered at init — just verify the file exists
	// (rule is exercised via integration through the engine).
	// Make sure the package compiled and the constants are correct.
	if pr.ProblemsFile != ".fusa-problems.json" {
		t.Errorf("ProblemsFile = %q", pr.ProblemsFile)
	}
	if pr.StatusClosed != "closed" {
		t.Errorf("StatusClosed = %q", pr.StatusClosed)
	}
}

func TestPhaseAndSeverityConstants(t *testing.T) {
	if pr.PhasePlanning != "planning" {
		t.Error("PhasePlanning")
	}
	if pr.PRSeverityCritical != "critical" {
		t.Error("PRSeverityCritical")
	}
	if pr.StatusOpen != "open" {
		t.Error("StatusOpen")
	}
}

func TestAdd_CreatesDefaultStatus(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "probs.json")
	if err := os.WriteFile(path, []byte(`{"project":"x","reports":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// Report with no explicit status — Add should default to open
	report := pr.ProblemReport{ID: "PR-004", Title: "test"}
	if err := pr.Add(path, report); err != nil {
		t.Fatalf("Add: %v", err)
	}
	loaded, _ := pr.Load(path)
	if loaded.Reports[0].Status != pr.StatusOpen {
		t.Errorf("default status = %v, want open", loaded.Reports[0].Status)
	}
}
