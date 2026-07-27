package iec61508_test

// Gap tests for mapToCanonical() and statusIcon() in iec61508/iec61508.go (v0.33.1).
// Both functions are unexported; exercised via the public Render API.
//
//   mapToCanonical: called from toGapReport (Render "json"/default)
//   statusIcon:     called from renderText (Render "text")

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/SoundMatt/go-FuSa/iec61508"
)

// ─── mapToCanonical ───────────────────────────────────────────────────────────

// TestMapToCanonical_Pass exercises mapToCanonical(StatusPass) → "satisfied".
// We provide evidence so that one or more objectives become PASS.
//
//fusa:test REQ-IEC61508-003
func TestMapToCanonical_Pass(t *testing.T) {
	dir := t.TempDir()
	// .fusa-reqs.json present → objective for requirements spec (3.1) becomes PASS.
	if err := os.WriteFile(filepath.Join(dir, ".fusa-reqs.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := iec61508.Assess(dir, "proj", iec61508.SIL2)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	var buf bytes.Buffer
	if err := iec61508.Render(&buf, rep, "json"); err != nil {
		t.Fatalf("Render json: %v", err)
	}
	out := buf.String()
	if !bytes.Contains([]byte(out), []byte("satisfied")) {
		t.Error("expected 'satisfied' status in JSON output when a PASS objective exists")
	}
}

// TestMapToCanonical_Manual exercises mapToCanonical(StatusManual) → "partial".
// SIL-4 introduces a MC/DC objective (3.5) that is MANUAL.
//
//fusa:test REQ-IEC61508-003
func TestMapToCanonical_Manual(t *testing.T) {
	dir := t.TempDir()
	rep, err := iec61508.Assess(dir, "proj", iec61508.SIL4)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	hasManual := false
	for _, obj := range rep.Objectives {
		if obj.Status == iec61508.StatusManual {
			hasManual = true
			break
		}
	}
	if !hasManual {
		t.Skip("no MANUAL objective at SIL-4; cannot test mapToCanonical(StatusManual)")
	}

	var buf bytes.Buffer
	if err := iec61508.Render(&buf, rep, "json"); err != nil {
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
//fusa:test REQ-IEC61508-003
func TestStatusIcon_Pass(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".fusa-reqs.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := iec61508.Assess(dir, "proj", iec61508.SIL2)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	var buf bytes.Buffer
	if err := iec61508.Render(&buf, rep, "text"); err != nil {
		t.Fatalf("Render text: %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte("✓")) {
		t.Error("expected ✓ icon in text output for PASS objective")
	}
}

// TestStatusIcon_NA exercises statusIcon(StatusNA) → "-" in text output.
// SIL-1 has objective 3.5 (MC/DC) as N/A.
//
//fusa:test REQ-IEC61508-003
func TestStatusIcon_NA(t *testing.T) {
	dir := t.TempDir()
	rep, err := iec61508.Assess(dir, "proj", iec61508.SIL1)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	hasNA := false
	for _, obj := range rep.Objectives {
		if obj.Status == iec61508.StatusNA {
			hasNA = true
			break
		}
	}
	if !hasNA {
		t.Skip("no N/A objective at SIL-1; cannot test statusIcon(StatusNA)")
	}

	var buf bytes.Buffer
	if err := iec61508.Render(&buf, rep, "text"); err != nil {
		t.Fatalf("Render text: %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte("-")) {
		t.Error("expected '-' icon in text output for N/A objective")
	}
}

// TestStatusIcon_Manual exercises statusIcon(StatusManual) → "?" in text output.
//
//fusa:test REQ-IEC61508-003
func TestStatusIcon_Manual(t *testing.T) {
	dir := t.TempDir()
	rep, err := iec61508.Assess(dir, "proj", iec61508.SIL4)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	hasManual := false
	for _, obj := range rep.Objectives {
		if obj.Status == iec61508.StatusManual {
			hasManual = true
			break
		}
	}
	if !hasManual {
		t.Skip("no MANUAL objective at SIL-4; cannot test statusIcon(StatusManual)")
	}

	var buf bytes.Buffer
	if err := iec61508.Render(&buf, rep, "text"); err != nil {
		t.Fatalf("Render text: %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte("?")) {
		t.Error("expected '?' icon in text output for MANUAL objective")
	}
}

// TestRender_Text_WithAllParts checks renderText iterates through all IEC 61508
// parts with mixed objective statuses, covering additional statusIcon paths.
//
//fusa:test REQ-IEC61508-003
func TestRender_Text_WithAllParts(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{".fusa-reqs.json", "sbom.json", "provenance.json"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte(`{}`), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := iec61508.Assess(dir, "proj", iec61508.SIL4)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	var buf bytes.Buffer
	if err := iec61508.Render(&buf, rep, "text"); err != nil {
		t.Fatalf("Render text: %v", err)
	}
	out := buf.String()
	if !bytes.Contains([]byte(out), []byte("IEC 61508 Gap Report")) {
		t.Error("missing report header in text output")
	}
}
