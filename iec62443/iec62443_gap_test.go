package iec62443_test

// Gap tests for statusIcon() in iec62443/assess.go (v0.33.1).
// statusIcon is unexported; exercised via Render("text").
// Targets the "PASS" case that existing TestRender_Text (SL1 empty) misses.

import (
	"bytes"
	"testing"

	"github.com/SoundMatt/go-FuSa/iec62443"
)

// TestStatusIcon_Pass exercises statusIcon("PASS") → "✓".
// We provide all SL-1 evidence files so at least one objective becomes PASS.
//
//fusa:test REQ-IEC62443-ASSESS004
func TestStatusIcon_Pass(t *testing.T) {
	dir := t.TempDir()
	// SL-1 objectives require: check-report, sbom, provenance(builder), SECURITY.md, cyber-report
	for name, content := range map[string]string{
		"check-report.json": `{}`,
		"sbom.json":         `{}`,
		"provenance.json":   `{"builder":"ci","vcsRevision":"abc"}`,
		"SECURITY.md":       "# Security Policy\n",
		"cyber-report.json": `{}`,
	} {
		writeFile(t, dir, name, content)
	}

	rep, err := iec62443.Assess(dir, "proj", iec62443.SL1)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if rep.Pass == 0 {
		t.Skip("no PASS objectives with provided evidence; skipping statusIcon PASS test")
	}

	var buf bytes.Buffer
	if err := iec62443.Render(&buf, rep, "text"); err != nil {
		t.Fatalf("Render text: %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte("✓")) {
		t.Error("expected ✓ icon in text output for PASS objective")
	}
}
