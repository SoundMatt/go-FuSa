package iec62443_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SoundMatt/go-FuSa/iec62443"
)

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

//fusa:test REQ-IEC62443-ASSESS001
func TestAssess_SL1_Empty(t *testing.T) {
	dir := t.TempDir()
	rep, err := iec62443.Assess(dir, "proj", iec62443.SL1)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if rep.SL != iec62443.SL1 {
		t.Errorf("SL = %v, want SL-1", rep.SL)
	}
	// 6 SL-1 objectives, all gaps on empty dir; 6 above-SL N/A
	if rep.Gap != 6 {
		t.Errorf("Gap = %d, want 6 on empty dir at SL-1", rep.Gap)
	}
	if rep.NA != 6 {
		t.Errorf("NA = %d, want 6 at SL-1", rep.NA)
	}
}

//fusa:test REQ-IEC62443-ASSESS002
func TestAssess_SL2_AllEvidence(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ".fusa-iec62443.json", `{"target_sl":2,"component_type":"application"}`)
	writeFile(t, dir, "check-report.json", `{}`)
	writeFile(t, dir, "sbom.json", `{}`)
	writeFile(t, dir, "provenance.json", `{"builder":"ci","vcsRevision":"abc"}`)
	writeFile(t, dir, "SECURITY.md", `# Security Policy`)
	writeFile(t, dir, "cyber-report.json", `{}`)
	writeFile(t, dir, "INCIDENT-RESPONSE.md", `# Incident Response`)
	writeFile(t, dir, "safety-case.json", `{}`)

	rep, err := iec62443.Assess(dir, "proj", iec62443.SL2)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if rep.Gap != 0 {
		t.Errorf("Gap = %d, want 0 when all SL-2 evidence present", rep.Gap)
	}
	if rep.NA != 2 {
		t.Errorf("NA = %d, want 2 (SL-3 objectives)", rep.NA)
	}
}

//fusa:test REQ-IEC62443-ASSESS003
func TestAssess_SL3_AllEvidence(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ".fusa-iec62443.json", `{"target_sl":3}`)
	writeFile(t, dir, "check-report.json", `{}`)
	writeFile(t, dir, "sbom.json", `{}`)
	writeFile(t, dir, "provenance.json", `{"builder":"ci"}`)
	writeFile(t, dir, "SECURITY.md", `# Security`)
	writeFile(t, dir, "cyber-report.json", `{}`)
	writeFile(t, dir, "INCIDENT-RESPONSE.md", `# IR`)
	writeFile(t, dir, "safety-case.json", `{}`)
	writeFile(t, dir, "boundary.mermaid", `graph TD`)
	writeFile(t, dir, "audit-pack.zip", `fake`)

	rep, err := iec62443.Assess(dir, "proj", iec62443.SL3)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if rep.Gap != 0 {
		t.Errorf("Gap = %d, want 0 when all SL-3 evidence present", rep.Gap)
	}
	if rep.NA != 0 {
		t.Errorf("NA = %d, want 0 at SL-3", rep.NA)
	}
}

//fusa:test REQ-IEC62443-ASSESS003
func TestAssess_CR14_ProvenanceHasBuilder(t *testing.T) {
	dir := t.TempDir()
	// provenance without builder: gap
	writeFile(t, dir, "provenance.json", `{"vcsRevision":"abc"}`)
	rep, err := iec62443.Assess(dir, "proj", iec62443.SL2)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	found := false
	for _, obj := range rep.Objectives {
		if obj.ID == "IEC62443-CR-1.4" && obj.Status == "GAP" {
			found = true
		}
	}
	if !found {
		t.Error("expected IEC62443-CR-1.4 GAP when builder field missing")
	}
}

//fusa:test REQ-IEC62443-ASSESS003
func TestAssess_CR14_ProvenanceMissing(t *testing.T) {
	dir := t.TempDir()
	rep, err := iec62443.Assess(dir, "proj", iec62443.SL2)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	for _, obj := range rep.Objectives {
		if obj.ID == "IEC62443-CR-1.4" && obj.Status == "GAP" {
			return
		}
	}
	t.Error("expected IEC62443-CR-1.4 GAP when provenance.json missing")
}

//fusa:test REQ-IEC62443-ASSESS003
func TestAssess_CR621_ConfiguredPath(t *testing.T) {
	dir := t.TempDir()
	// incident_resp_doc set to a custom path
	writeFile(t, dir, ".fusa-iec62443.json", `{"target_sl":2,"incident_resp_doc":"docs/ir.md"}`)
	writeFile(t, dir, "docs/ir.md", `# IR`)
	// Provide other required SL-2 evidence
	writeFile(t, dir, "check-report.json", `{}`)
	writeFile(t, dir, "sbom.json", `{}`)
	writeFile(t, dir, "provenance.json", `{"builder":"ci"}`)
	writeFile(t, dir, "SECURITY.md", `# Sec`)
	writeFile(t, dir, "cyber-report.json", `{}`)
	writeFile(t, dir, "safety-case.json", `{}`)

	rep, err := iec62443.Assess(dir, "proj", iec62443.SL2)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	for _, obj := range rep.Objectives {
		if obj.ID == "IEC62443-CR-6.2.1" {
			if obj.Status != "PASS" {
				t.Errorf("IEC62443-CR-6.2.1 = %s, want PASS with configured path", obj.Status)
			}
			return
		}
	}
	t.Error("IEC62443-CR-6.2.1 not found in report")
}

//fusa:test REQ-IEC62443-ASSESS003
func TestAssess_CR62_SecurityMDVariants(t *testing.T) {
	for _, name := range []string{"SECURITY.md", "SECURITY_POLICY.md", "security-policy.md"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, dir, name, `# Security`)
			rep, err := iec62443.Assess(dir, "proj", iec62443.SL1)
			if err != nil {
				t.Fatalf("Assess: %v", err)
			}
			for _, obj := range rep.Objectives {
				if obj.ID == "IEC62443-CR-6.2" && obj.Status == "PASS" {
					return
				}
			}
			t.Errorf("expected IEC62443-CR-6.2 PASS with %s", name)
		})
	}
}

//fusa:test REQ-IEC62443-ASSESS003
func TestAssess_SL4_SameAsSL3(t *testing.T) {
	dir := t.TempDir()
	rep3, _ := iec62443.Assess(dir, "proj", iec62443.SL3)
	rep4, _ := iec62443.Assess(dir, "proj", iec62443.SL4)
	if len(rep3.Objectives) != len(rep4.Objectives) {
		t.Errorf("SL4 objectives(%d) != SL3 objectives(%d)", len(rep4.Objectives), len(rep3.Objectives))
	}
}

//fusa:test REQ-IEC62443-ASSESS004
func TestRender_Text(t *testing.T) {
	dir := t.TempDir()
	rep, err := iec62443.Assess(dir, "proj", iec62443.SL1)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	var buf bytes.Buffer
	if err := iec62443.Render(&buf, rep, "text"); err != nil {
		t.Fatalf("Render text: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "IEC 62443 Gap Report") {
		t.Error("missing report header")
	}
	if !strings.Contains(out, "SL-1") {
		t.Error("missing SL in output")
	}
}

//fusa:test REQ-IEC62443-ASSESS004
func TestRender_JSON(t *testing.T) {
	dir := t.TempDir()
	rep, err := iec62443.Assess(dir, "proj", iec62443.SL2)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	var buf bytes.Buffer
	if err := iec62443.Render(&buf, rep, "json"); err != nil {
		t.Fatalf("Render json: %v", err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("JSON parse: %v", err)
	}
	if doc["standard"] != "iec62443" {
		t.Errorf("standard = %v, want iec62443", doc["standard"])
	}
	if doc["kind"] != "gap-report" {
		t.Errorf("kind = %v, want gap-report", doc["kind"])
	}
}

//fusa:test REQ-IEC62443-ASSESS004
func TestRender_InvalidFormat(t *testing.T) {
	dir := t.TempDir()
	rep, _ := iec62443.Assess(dir, "proj", iec62443.SL1)
	if err := iec62443.Render(&bytes.Buffer{}, rep, "xml"); err == nil {
		t.Error("expected error for unsupported format")
	}
}

//fusa:test REQ-IEC62443-ASSESS003
func TestAssess_CR14_BadProvenanceJSON(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "provenance.json", "not json")
	rep, err := iec62443.Assess(dir, "proj", iec62443.SL2)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	for _, obj := range rep.Objectives {
		if obj.ID == "IEC62443-CR-1.4" && obj.Status == "GAP" {
			return
		}
	}
	t.Error("expected IEC62443-CR-1.4 GAP when provenance.json is invalid JSON")
}

//fusa:test REQ-IEC62443-ASSESS004
func TestRender_Text_WithGaps(t *testing.T) {
	dir := t.TempDir()
	rep, err := iec62443.Assess(dir, "proj", iec62443.SL2)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	var buf bytes.Buffer
	if err := iec62443.Render(&buf, rep, "text"); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "Action items") {
		t.Error("expected Action items section for non-zero gaps")
	}
}
