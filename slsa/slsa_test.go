package slsa_test

import (
	"context"
	"strings"
	"testing"

	"github.com/SoundMatt/go-FuSa/config"
	"github.com/SoundMatt/go-FuSa/engine"
	"github.com/SoundMatt/go-FuSa/testutil"

	_ "github.com/SoundMatt/go-FuSa/slsa" // register rules
)

func runSLSA(t *testing.T, files map[string]string) map[string]int {
	t.Helper()
	dir := testutil.ProjectDir(t, files)
	cfg := config.Default("", "test")
	result, err := engine.Default.RunFilter(context.Background(), dir, cfg, func(r engine.Rule) bool {
		return strings.HasPrefix(r.ID(), "SLSA")
	})
	if err != nil {
		t.Fatalf("runSLSA: %v", err)
	}
	counts := make(map[string]int)
	for _, f := range result.Findings {
		counts[f.RuleID]++
	}
	return counts
}

// ─── SLSA001 ──────────────────────────────────────────────────────────────────

//fusa:test REQ-SLSA001
func TestSLSA001_MissingRevision(t *testing.T) {
	counts := runSLSA(t, map[string]string{
		"go.mod":          "module example.com/test\ngo 1.22\n",
		"provenance.json": `{"format":"go-FuSa Provenance v1","module":"example.com/test"}`,
	})
	if counts["SLSA001"] == 0 {
		t.Error("expected SLSA001 finding when vcsRevision missing")
	}
}

func TestSLSA001_RevisionPresent(t *testing.T) {
	counts := runSLSA(t, map[string]string{
		"go.mod":          "module example.com/test\ngo 1.22\n",
		"provenance.json": `{"format":"go-FuSa Provenance v1","vcsRevision":"abc123"}`,
	})
	if counts["SLSA001"] != 0 {
		t.Errorf("expected no SLSA001 when vcsRevision present, got %d", counts["SLSA001"])
	}
}

func TestSLSA001_MissingProvenanceFile(t *testing.T) {
	counts := runSLSA(t, map[string]string{
		"go.mod": "module example.com/test\ngo 1.22\n",
	})
	// No provenance.json at all — SLSA001 should not fire (RELEASE002 handles that).
	if counts["SLSA001"] != 0 {
		t.Errorf("SLSA001 should not fire when provenance.json absent (RELEASE002 covers it), got %d", counts["SLSA001"])
	}
}

// ─── SLSA002 ──────────────────────────────────────────────────────────────────

//fusa:test REQ-SLSA002
func TestSLSA002_MissingBuilder(t *testing.T) {
	counts := runSLSA(t, map[string]string{
		"go.mod":          "module example.com/test\ngo 1.22\n",
		"provenance.json": `{"vcsRevision":"abc"}`,
	})
	if counts["SLSA002"] == 0 {
		t.Error("expected SLSA002 finding when builder field missing")
	}
}

func TestSLSA002_BuilderPresent(t *testing.T) {
	counts := runSLSA(t, map[string]string{
		"go.mod":          "module example.com/test\ngo 1.22\n",
		"provenance.json": `{"vcsRevision":"abc","builder":"https://github.com/actions/runner"}`,
	})
	if counts["SLSA002"] != 0 {
		t.Errorf("expected no SLSA002 when builder present, got %d", counts["SLSA002"])
	}
}

// ─── SLSA003 ──────────────────────────────────────────────────────────────────

//fusa:test REQ-SLSA003
func TestSLSA003_MissingCODEOWNERS(t *testing.T) {
	counts := runSLSA(t, map[string]string{
		"go.mod": "module example.com/test\ngo 1.22\n",
	})
	if counts["SLSA003"] == 0 {
		t.Error("expected SLSA003 finding when no CODEOWNERS or branch protection")
	}
}

func TestSLSA003_CODEOWNERSPresent(t *testing.T) {
	counts := runSLSA(t, map[string]string{
		"go.mod":             "module example.com/test\ngo 1.22\n",
		".github/CODEOWNERS": "* @security-team\n",
	})
	if counts["SLSA003"] != 0 {
		t.Errorf("expected no SLSA003 when CODEOWNERS present, got %d", counts["SLSA003"])
	}
}

func TestSLSA003_RootCODEOWNERS(t *testing.T) {
	counts := runSLSA(t, map[string]string{
		"go.mod":     "module example.com/test\ngo 1.22\n",
		"CODEOWNERS": "* @admin\n",
	})
	if counts["SLSA003"] != 0 {
		t.Errorf("expected no SLSA003 with root CODEOWNERS, got %d", counts["SLSA003"])
	}
}

// ─── full project ─────────────────────────────────────────────────────────────

func TestSLSA_FullProject_NoFindings(t *testing.T) {
	counts := runSLSA(t, map[string]string{
		"go.mod":          "module example.com/test\ngo 1.22\n",
		"provenance.json": `{"vcsRevision":"abc123","builder":"https://github.com/actions/runner"}`,
		"CODEOWNERS":      "* @admin\n",
	})
	for id, n := range counts {
		if n > 0 {
			t.Errorf("unexpected SLSA finding %s in complete project", id)
		}
	}
}

// TestSLSA_Descriptions ensures Description() is non-empty for all three SLSA rules.
func TestSLSA_Descriptions(t *testing.T) {
	for _, r := range engine.Default.Rules() {
		if !strings.HasPrefix(r.ID(), "SLSA") {
			continue
		}
		if r.Description() == "" {
			t.Errorf("rule %s: Description() is empty", r.ID())
		}
	}
}
