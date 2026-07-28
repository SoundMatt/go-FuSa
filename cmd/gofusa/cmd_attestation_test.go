package main

// cmd_attestation_test.go covers x-FuSa spec §1.6.2's carry-forward MUST
// (spec v1.15.0): before an artifact-producing command rebuilds its output,
// it must load any existing attestation from the prior saved output file and
// carry it forward onto the freshly-built result, rather than discarding it
// (go-FuSa#57). Each artifact command (fmea/tara/safety-case/sas) is run
// twice: the first run produces a fresh artifact with no attestation; a
// "reviewed" attestation with a matching contentHash is then hand-added; the
// second run must preserve that attestation rather than silently wiping it.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	fusa "github.com/SoundMatt/go-FuSa"
)

//fusa:test REQ-CLI-HELPERS005
func TestCarryForwardAttestation_AbsentFile(t *testing.T) {
	if att := carryForwardAttestation(filepath.Join(t.TempDir(), "does-not-exist.json")); att != nil {
		t.Errorf("expected nil for an absent file, got %+v", att)
	}
}

//fusa:test REQ-CLI-HELPERS005
func TestCarryForwardAttestation_MalformedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("{not valid json"), 0o640); err != nil {
		t.Fatal(err)
	}
	if att := carryForwardAttestation(path); att != nil {
		t.Errorf("expected nil for a malformed file, got %+v", att)
	}
}

//fusa:test REQ-CLI-HELPERS005
func TestCarryForwardAttestation_NoAttestationField(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "no-att.json")
	if err := os.WriteFile(path, []byte(`{"entries":[]}`), 0o640); err != nil {
		t.Fatal(err)
	}
	if att := carryForwardAttestation(path); att != nil {
		t.Errorf("expected nil when no attestation key is present, got %+v", att)
	}
}

//fusa:test REQ-CLI-HELPERS005
func TestCarryForwardAttestation_CarriesReviewedStatus(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "with-att.json")
	body := `{"entries":[],"attestation":{"status":"reviewed","implementationAuthor":"auto","independentReviewer":"Jane Doe","contentHash":"sha256:deadbeef"}}`
	if err := os.WriteFile(path, []byte(body), 0o640); err != nil {
		t.Fatal(err)
	}
	att := carryForwardAttestation(path)
	if att == nil {
		t.Fatal("expected a non-nil attestation")
	}
	if att.Status != fusa.StatusReviewed || att.IndependentReviewer != "Jane Doe" {
		t.Errorf("unexpected attestation: %+v", att)
	}
}

//fusa:test REQ-CLI013
//fusa:test REQ-STUB012
func TestRunFmea_CarriesForwardAttestation(t *testing.T) {
	dir := t.TempDir()
	writeSafetyFuncSource(t, dir)

	var out1, err1 bytes.Buffer
	if code := runFmea([]string{"--dir", dir}, &out1, &err1); code != fusa.ExitOK {
		t.Fatalf("first run: exit %d, stderr: %s", code, err1.String())
	}

	fmeaPath := filepath.Join(dir, "fmea.json")
	injectReviewedAttestation(t, fmeaPath, "entries")

	var out2, err2 bytes.Buffer
	if code := runFmea([]string{"--dir", dir}, &out2, &err2); code != fusa.ExitOK {
		t.Fatalf("second run: exit %d, stderr: %s", code, err2.String())
	}
	assertAttestationPreserved(t, fmeaPath)
}

//fusa:test REQ-CLI019
//fusa:test REQ-STUB012
func TestRunTara_CarriesForwardAttestation(t *testing.T) {
	dir := t.TempDir()

	var out1, err1 bytes.Buffer
	if code := runTara([]string{"--dir", dir}, &out1, &err1); code != fusa.ExitOK {
		t.Fatalf("first run: exit %d, stderr: %s", code, err1.String())
	}

	taraPath := filepath.Join(dir, "tara.json")
	injectReviewedAttestation(t, taraPath, "threats")

	var out2, err2 bytes.Buffer
	if code := runTara([]string{"--dir", dir}, &out2, &err2); code != fusa.ExitOK {
		t.Fatalf("second run: exit %d, stderr: %s", code, err2.String())
	}
	assertAttestationPreserved(t, taraPath)
}

//fusa:test REQ-CLI012
//fusa:test REQ-STUB012
func TestRunSafetyCase_CarriesForwardAttestation(t *testing.T) {
	dir := t.TempDir()

	var out1, err1 bytes.Buffer
	if code := runSafetyCase([]string{"--dir", dir}, &out1, &err1); code != fusa.ExitOK {
		t.Fatalf("first run: exit %d, stderr: %s", code, err1.String())
	}

	scPath := filepath.Join(dir, "safety-case.json")
	injectReviewedAttestationSC(t, scPath)

	var out2, err2 bytes.Buffer
	if code := runSafetyCase([]string{"--dir", dir}, &out2, &err2); code != fusa.ExitOK {
		t.Fatalf("second run: exit %d, stderr: %s", code, err2.String())
	}
	assertAttestationPreserved(t, scPath)
}

//fusa:test REQ-CLI-SAS001
//fusa:test REQ-STUB012
func TestRunSas_CarriesForwardAttestation(t *testing.T) {
	dir := t.TempDir()
	sasJSONPath := filepath.Join(dir, "sas.json")

	var out1, err1 bytes.Buffer
	// --format markdown (the default) writes the primary output to
	// --output and the json companion alongside it — exercise that path,
	// since it's the common case (`gofusa sas` with no flags).
	outFile := filepath.Join(dir, "sas.md")
	if code := runSas([]string{"--dir", dir, "--output", outFile}, &out1, &err1); code != fusa.ExitGateFail && code != fusa.ExitOK {
		t.Fatalf("first run: unexpected exit %d, stderr: %s", code, err1.String())
	}
	if _, err := os.Stat(sasJSONPath); err != nil {
		t.Fatalf("sas.json companion not written: %v", err)
	}

	injectReviewedAttestation(t, sasJSONPath, "deviations")

	var out2, err2 bytes.Buffer
	runSas([]string{"--dir", dir, "--output", outFile}, &out2, &err2)
	assertAttestationPreserved(t, sasJSONPath)
}

// ─── shared test helpers ────────────────────────────────────────────────────

func writeSafetyFuncSource(t *testing.T, dir string) {
	t.Helper()
	src := "package main\n\n//fusa:req REQ-001\nfunc SafetyFunc() error { return nil }\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
}

// injectReviewedAttestation reads the JSON artifact at path, computes the
// canonical content hash over its contentKey field (e.g. "entries",
// "threats", "deviations" — whichever field the command's own
// gateContentQuality call hashes), and rewrites the file with a valid
// "reviewed" attestation whose contentHash matches that field's current
// content, so a second run's regenerated content — if unchanged — carries a
// *currently-valid* (not stale) attestation forward.
func injectReviewedAttestation(t *testing.T, path, contentKey string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var doc map[string]interface{}
	if unmarshalErr := json.Unmarshal(data, &doc); unmarshalErr != nil {
		t.Fatalf("unmarshal %s: %v", path, unmarshalErr)
	}
	hash, err := fusa.AttestationContentHash(doc[contentKey])
	if err != nil {
		t.Fatalf("AttestationContentHash: %v", err)
	}
	doc["attestation"] = fusa.Attestation{
		Status:               fusa.StatusReviewed,
		ImplementationAuthor: "auto",
		IndependentReviewer:  "Jane Doe <jane@example.com>",
		ReviewedAt:           fusa.NowRFC3339(),
		ContentHash:          hash,
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("marshal %s: %v", path, err)
	}
	if err := os.WriteFile(path, out, 0o640); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// injectReviewedAttestationSC is injectReviewedAttestation specialised for
// safety-case.json, whose content hash is computed over {nodes, edges}
// together (matching cmd_safetycase.go's gateContentQuality call), not a
// single top-level field.
func injectReviewedAttestationSC(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var doc map[string]interface{}
	if unmarshalErr := json.Unmarshal(data, &doc); unmarshalErr != nil {
		t.Fatalf("unmarshal %s: %v", path, unmarshalErr)
	}
	content := struct {
		Nodes interface{} `json:"nodes"`
		Edges interface{} `json:"edges"`
	}{doc["nodes"], doc["edges"]}
	hash, err := fusa.AttestationContentHash(content)
	if err != nil {
		t.Fatalf("AttestationContentHash: %v", err)
	}
	doc["attestation"] = fusa.Attestation{
		Status:               fusa.StatusReviewed,
		ImplementationAuthor: "auto",
		IndependentReviewer:  "Jane Doe <jane@example.com>",
		ReviewedAt:           fusa.NowRFC3339(),
		ContentHash:          hash,
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("marshal %s: %v", path, err)
	}
	if err := os.WriteFile(path, out, 0o640); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// assertAttestationPreserved fails the test unless path's current
// "attestation" field is present with status "reviewed" — i.e. the
// regenerating command carried it forward rather than discarding it.
func assertAttestationPreserved(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var doc struct {
		Attestation *fusa.Attestation `json:"attestation"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal %s: %v", path, err)
	}
	if doc.Attestation == nil {
		t.Fatalf("%s: attestation was discarded on regeneration", path)
	}
	if doc.Attestation.Status != fusa.StatusReviewed {
		t.Errorf("%s: attestation.status = %q, want %q", path, doc.Attestation.Status, fusa.StatusReviewed)
	}
	if doc.Attestation.IndependentReviewer != "Jane Doe <jane@example.com>" {
		t.Errorf("%s: attestation.independentReviewer = %q, want the carried-forward reviewer", path, doc.Attestation.IndependentReviewer)
	}
}
