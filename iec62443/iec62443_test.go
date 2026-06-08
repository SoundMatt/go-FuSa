package iec62443_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SoundMatt/go-FuSa/config"
	"github.com/SoundMatt/go-FuSa/engine"
	"github.com/SoundMatt/go-FuSa/iec62443"
	"github.com/SoundMatt/go-FuSa/testutil"

	_ "github.com/SoundMatt/go-FuSa/iec62443" // register rules
)

// runIEC runs only IEC62443-* rules and returns ruleID-keyed findings.
func runIEC(t *testing.T, files map[string]string) map[string]int {
	t.Helper()
	dir := testutil.ProjectDir(t, files)
	cfg := config.Default("", "test")
	result, err := engine.Default.RunFilter(context.Background(), dir, cfg, func(r engine.Rule) bool {
		return strings.HasPrefix(r.ID(), "IEC62443-")
	})
	if err != nil {
		t.Fatalf("runIEC: %v", err)
	}
	counts := make(map[string]int)
	for _, f := range result.Findings {
		counts[f.RuleID]++
	}
	return counts
}

// ─── IEC62443-001 ─────────────────────────────────────────────────────────────

func TestIEC62443_001_MissingConfig(t *testing.T) {
	counts := runIEC(t, map[string]string{
		"go.mod": "module example.com/test\ngo 1.22\n",
	})
	if counts["IEC62443-001"] == 0 {
		t.Error("expected IEC62443-001 finding for missing .fusa-iec62443.json")
	}
}

func TestIEC62443_001_ConfigPresent(t *testing.T) {
	counts := runIEC(t, map[string]string{
		"go.mod":              "module example.com/test\ngo 1.22\n",
		".fusa-iec62443.json": `{"target_sl":2,"component_type":"application"}`,
	})
	if counts["IEC62443-001"] != 0 {
		t.Errorf("expected no IEC62443-001 when config present, got %d", counts["IEC62443-001"])
	}
}

// ─── IEC62443-002 ─────────────────────────────────────────────────────────────

func TestIEC62443_002_SLZero(t *testing.T) {
	counts := runIEC(t, map[string]string{
		"go.mod":              "module example.com/test\ngo 1.22\n",
		".fusa-iec62443.json": `{"target_sl":0}`,
	})
	if counts["IEC62443-002"] == 0 {
		t.Error("expected IEC62443-002 finding for target_sl=0")
	}
}

func TestIEC62443_002_SLValid(t *testing.T) {
	counts := runIEC(t, map[string]string{
		"go.mod":              "module example.com/test\ngo 1.22\n",
		".fusa-iec62443.json": `{"target_sl":2}`,
	})
	if counts["IEC62443-002"] != 0 {
		t.Errorf("expected no IEC62443-002 for valid SL, got %d", counts["IEC62443-002"])
	}
}

func TestIEC62443_002_SL5Invalid(t *testing.T) {
	counts := runIEC(t, map[string]string{
		"go.mod":              "module example.com/test\ngo 1.22\n",
		".fusa-iec62443.json": `{"target_sl":5}`,
	})
	if counts["IEC62443-002"] == 0 {
		t.Error("expected IEC62443-002 for target_sl=5 (out of range)")
	}
}

// ─── IEC62443-003 ─────────────────────────────────────────────────────────────

func TestIEC62443_003_MissingSecurityPolicy(t *testing.T) {
	counts := runIEC(t, map[string]string{
		"go.mod": "module example.com/test\ngo 1.22\n",
	})
	if counts["IEC62443-003"] == 0 {
		t.Error("expected IEC62443-003 for missing SECURITY.md")
	}
}

func TestIEC62443_003_SecurityPolicyPresent(t *testing.T) {
	counts := runIEC(t, map[string]string{
		"go.mod":      "module example.com/test\ngo 1.22\n",
		"SECURITY.md": "# Security Policy\n",
	})
	if counts["IEC62443-003"] != 0 {
		t.Errorf("expected no IEC62443-003 when SECURITY.md present, got %d", counts["IEC62443-003"])
	}
}

// ─── IEC62443-004 ─────────────────────────────────────────────────────────────

func TestIEC62443_004_MissingIncidentResponse(t *testing.T) {
	counts := runIEC(t, map[string]string{
		"go.mod": "module example.com/test\ngo 1.22\n",
	})
	if counts["IEC62443-004"] == 0 {
		t.Error("expected IEC62443-004 for missing incident response plan")
	}
}

func TestIEC62443_004_IncidentResponsePresent(t *testing.T) {
	counts := runIEC(t, map[string]string{
		"go.mod":               "module example.com/test\ngo 1.22\n",
		"INCIDENT-RESPONSE.md": "# IR Plan\n",
	})
	if counts["IEC62443-004"] != 0 {
		t.Errorf("expected no IEC62443-004 when INCIDENT-RESPONSE.md present, got %d", counts["IEC62443-004"])
	}
}

func TestIEC62443_004_ConfiguredPath(t *testing.T) {
	counts := runIEC(t, map[string]string{
		"go.mod":              "module example.com/test\ngo 1.22\n",
		".fusa-iec62443.json": `{"target_sl":2,"incident_resp_doc":"docs/ir.md"}`,
		"docs/ir.md":          "# IR Plan\n",
	})
	if counts["IEC62443-004"] != 0 {
		t.Errorf("expected no IEC62443-004 when configured path exists, got %d", counts["IEC62443-004"])
	}
}

// ─── LoadConfig ───────────────────────────────────────────────────────────────

func TestLoadConfig_Valid(t *testing.T) {
	dir := testutil.ProjectDir(t, map[string]string{
		".fusa-iec62443.json": `{"target_sl":3,"component_type":"gateway","zone_conduit":true}`,
	})
	cfg, err := iec62443.LoadConfig(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.TargetSL != 3 {
		t.Errorf("target_sl: want 3 got %d", cfg.TargetSL)
	}
	if cfg.ComponentType != "gateway" {
		t.Errorf("component_type: want gateway got %s", cfg.ComponentType)
	}
	if !cfg.ZoneConduit {
		t.Error("zone_conduit: want true")
	}
}

func TestLoadConfig_Missing(t *testing.T) {
	_, err := iec62443.LoadConfig(t.TempDir())
	if err == nil {
		t.Error("expected error for missing config file")
	}
}

func TestLoadConfig_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, iec62443.ConfigFile), []byte("{bad json"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := iec62443.LoadConfig(dir)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

// ─── integration: all rules pass on complete project ─────────────────────────

func TestIEC62443_FullProject_NoFindings(t *testing.T) {
	counts := runIEC(t, map[string]string{
		"go.mod":               "module example.com/test\ngo 1.22\n",
		".fusa-iec62443.json":  `{"target_sl":2,"component_type":"application"}`,
		"SECURITY.md":          "# Security\n",
		"INCIDENT-RESPONSE.md": "# IR\n",
	})
	for id, n := range counts {
		if n > 0 {
			t.Errorf("unexpected finding %s in complete project", id)
		}
	}
}
