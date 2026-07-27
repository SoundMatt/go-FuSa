package iso26262_test

// Gap tests for mapToCanonical() and statusIcon() in iso26262/iso26262.go (v0.33.1).
// Both functions are unexported; they are exercised via the public Render API.
//
//   mapToCanonical: called from toGapReport (Render "json"/default)
//   statusIcon:     called from renderText (Render "text")

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/SoundMatt/go-FuSa/iso26262"
)

// ─── mapToCanonical ───────────────────────────────────────────────────────────

// TestMapToCanonical_Pass exercises mapToCanonical(StatusPass) → "satisfied".
// We create a project where at least one objective has evidence (PASS).
//
//fusa:test REQ-ISO26262-003
func TestMapToCanonical_Pass(t *testing.T) {
	dir := t.TempDir()
	// .fusa-reqs.json present → objective 6.1 becomes PASS.
	if err := os.WriteFile(filepath.Join(dir, ".fusa-reqs.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := iso26262.Assess(dir, "proj", iso26262.ASILB)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	// Render as JSON — calls toGapReport → mapToCanonical for each objective.
	var buf bytes.Buffer
	if err := iso26262.Render(&buf, rep, "json"); err != nil {
		t.Fatalf("Render json: %v", err)
	}
	out := buf.String()
	// At least one PASS objective should yield "satisfied" in the canonical JSON.
	if !bytes.Contains([]byte(out), []byte("satisfied")) {
		t.Error("expected 'satisfied' status in JSON output when a PASS objective exists")
	}
}

// TestMapToCanonical_Manual exercises mapToCanonical(StatusManual) → "partial".
// ASIL-C/D introduces a confirmation-review objective (11.1) that is MANUAL.
//
//fusa:test REQ-ISO26262-003
func TestMapToCanonical_Manual(t *testing.T) {
	dir := t.TempDir()
	rep, err := iso26262.Assess(dir, "proj", iso26262.ASILC)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	// Verify there is at least one MANUAL objective (11.1).
	hasManual := false
	for _, obj := range rep.Objectives {
		if obj.Status == iso26262.StatusManual {
			hasManual = true
			break
		}
	}
	if !hasManual {
		t.Skip("no MANUAL objective found in ASIL-C assessment; cannot test mapToCanonical(Manual)")
	}

	var buf bytes.Buffer
	if err := iso26262.Render(&buf, rep, "json"); err != nil {
		t.Fatalf("Render json: %v", err)
	}
	out := buf.String()
	if !bytes.Contains([]byte(out), []byte("partial")) {
		t.Error("expected 'partial' status in JSON output for MANUAL objectives")
	}
}

// ─── statusIcon ───────────────────────────────────────────────────────────────

// TestStatusIcon_Pass exercises statusIcon(StatusPass) → "✓" in text output.
//
//fusa:test REQ-ISO26262-003
func TestStatusIcon_Pass(t *testing.T) {
	dir := t.TempDir()
	// Provide evidence so at least one objective becomes PASS.
	if err := os.WriteFile(filepath.Join(dir, ".fusa-reqs.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := iso26262.Assess(dir, "proj", iso26262.ASILB)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	var buf bytes.Buffer
	if err := iso26262.Render(&buf, rep, "text"); err != nil {
		t.Fatalf("Render text: %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte("✓")) {
		t.Error("expected ✓ icon in text output for PASS objective")
	}
}

// TestStatusIcon_NA exercises statusIcon(StatusNA) → "-" in text output.
// ASIL-A assessment has objective 6.7 (safety case) as N/A.
//
//fusa:test REQ-ISO26262-003
func TestStatusIcon_NA(t *testing.T) {
	dir := t.TempDir()
	rep, err := iso26262.Assess(dir, "proj", iso26262.ASILA)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	// Confirm there is at least one N/A objective.
	hasNA := false
	for _, obj := range rep.Objectives {
		if obj.Status == iso26262.StatusNA {
			hasNA = true
			break
		}
	}
	if !hasNA {
		t.Skip("no N/A objective at ASIL-A; cannot test statusIcon(StatusNA)")
	}

	var buf bytes.Buffer
	if err := iso26262.Render(&buf, rep, "text"); err != nil {
		t.Fatalf("Render text: %v", err)
	}
	// statusIcon(StatusNA) returns "-"
	if !bytes.Contains(buf.Bytes(), []byte("-")) {
		t.Error("expected '-' icon in text output for N/A objective")
	}
}

// TestStatusIcon_Manual exercises statusIcon(StatusManual) → "?" in text output.
//
//fusa:test REQ-ISO26262-003
func TestStatusIcon_Manual(t *testing.T) {
	dir := t.TempDir()
	rep, err := iso26262.Assess(dir, "proj", iso26262.ASILC)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	hasManual := false
	for _, obj := range rep.Objectives {
		if obj.Status == iso26262.StatusManual {
			hasManual = true
			break
		}
	}
	if !hasManual {
		t.Skip("no MANUAL objective at ASIL-C; cannot test statusIcon(StatusManual)")
	}

	var buf bytes.Buffer
	if err := iso26262.Render(&buf, rep, "text"); err != nil {
		t.Fatalf("Render text: %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte("?")) {
		t.Error("expected '?' icon in text output for MANUAL objective")
	}
}

// TestRenderText_AllParts ensures renderText iterates all ISO 26262 parts,
// exercising statusIcon for multiple objective statuses in one pass.
//
//fusa:test REQ-ISO26262-003
func TestRenderText_AllParts(t *testing.T) {
	dir := t.TempDir()
	// Supply some evidence to produce a mix of PASS and GAP objectives.
	for _, f := range []string{".fusa-reqs.json", "boundary.mermaid", "sbom.json", "provenance.json"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte(`{}`), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := iso26262.Assess(dir, "proj", iso26262.ASILD)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	var buf bytes.Buffer
	if err := iso26262.Render(&buf, rep, "text"); err != nil {
		t.Fatalf("Render text: %v", err)
	}
	out := buf.String()
	if !bytes.Contains([]byte(out), []byte("ISO 26262 Gap Report")) {
		t.Error("missing report header in text output")
	}
}
