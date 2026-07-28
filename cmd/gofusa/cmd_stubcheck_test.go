package main

// cmd_stubcheck_test.go covers two x-FuSa spec §1.6.1 conformance fixes:
//
//   - detection runs only inside each artifact-producing command's own
//     gateContentQuality gate, never inside `gofusa check` (§1.6.1 "Who
//     runs this (MUST)");
//   - FUSA-STUB001 is suppressible via a per-finding disposition entry in
//     .fusa-dispositions.json (§1.6.1 rule A), while FUSA-STUB002 remains
//     suppressible only by a valid §1.6.2 attestation, never a disposition.

import (
	"bytes"
	"strings"
	"testing"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/stubcheck"
	"github.com/SoundMatt/go-FuSa/testutil"
)

//fusa:test REQ-STUB013
func TestGateContentQuality_DispositionSuppressesStub001(t *testing.T) {
	dir := testutil.ProjectDir(t, map[string]string{})
	fields := []stubcheck.Field{{Name: "hazards[].description", Values: []string{"TBD — replace with project-specific hazard"}}}

	var errBuf bytes.Buffer
	code := gateContentQuality(&errBuf, "hara", dir, "hara.json", fields, nil, nil, false)
	if code != fusa.ExitGateFail {
		t.Fatalf("without a disposition: code = %d, want ExitGateFail", code)
	}
	if !strings.Contains(errBuf.String(), "FUSA-STUB001") {
		t.Errorf("expected FUSA-STUB001 to be printed, got: %s", errBuf.String())
	}

	// Now add a disposition entry for FUSA-STUB001 and re-run.
	dispositionJSON := `{
  "project": "test",
  "entries": [
    {"ruleID": "FUSA-STUB001", "rationale": "legitimate use of the word TBD in a hazard title", "reviewer": "Jane Doe", "date": "2026-01-01T00:00:00Z", "action": "accept"}
  ]
}`
	dir2 := testutil.ProjectDir(t, map[string]string{".fusa-dispositions.json": dispositionJSON})
	var errBuf2 bytes.Buffer
	code2 := gateContentQuality(&errBuf2, "hara", dir2, "hara.json", fields, nil, nil, false)
	if code2 != fusa.ExitOK {
		t.Fatalf("with a FUSA-STUB001 disposition: code = %d, want ExitOK; stderr=%s", code2, errBuf2.String())
	}
	if strings.Contains(errBuf2.String(), "placeholder/template text") {
		t.Errorf("expected the FUSA-STUB001 finding message body to be suppressed, got: %s", errBuf2.String())
	}
	if !strings.Contains(errBuf2.String(), "suppressed by disposition") {
		t.Errorf("expected a suppression notice, got: %s", errBuf2.String())
	}
}

//fusa:test REQ-STUB013
func TestGateContentQuality_Stub001DispositionDoesNotSuppressStub002(t *testing.T) {
	// A FUSA-STUB001 disposition must not accidentally suppress an unrelated
	// FUSA-STUB002 (blanket-fallback) finding — only a valid attestation may.
	dispositionJSON := `{
  "project": "test",
  "entries": [
    {"ruleID": "FUSA-STUB001", "rationale": "unrelated", "reviewer": "Jane Doe", "date": "2026-01-01T00:00:00Z", "action": "accept"}
  ]
}`
	dir := testutil.ProjectDir(t, map[string]string{".fusa-dispositions.json": dispositionJSON})

	values := make([]string, 11)
	for i := range values {
		values[i] = "generic repeated text"
	}
	fields := []stubcheck.Field{{Name: "entries[].failureMode", Values: values}}

	var errBuf bytes.Buffer
	code := gateContentQuality(&errBuf, "fmea", dir, "fmea.json", fields, nil, nil, true)
	if code != fusa.ExitGateFail {
		t.Fatalf("code = %d, want ExitGateFail (STUB002 must still gate under --strict without an attestation)", code)
	}
	if !strings.Contains(errBuf.String(), "FUSA-STUB002") {
		t.Errorf("expected FUSA-STUB002 to be printed, got: %s", errBuf.String())
	}
}

//fusa:test REQ-STUB013
func TestGateContentQuality_MalformedDispositionsFileFailsSafe(t *testing.T) {
	dir := testutil.ProjectDir(t, map[string]string{".fusa-dispositions.json": "{not valid json"})
	fields := []stubcheck.Field{{Name: "hazards[].description", Values: []string{"TBD"}}}

	var errBuf bytes.Buffer
	code := gateContentQuality(&errBuf, "hara", dir, "hara.json", fields, nil, nil, false)
	if code != fusa.ExitGateFail {
		t.Fatalf("code = %d, want ExitGateFail — an unreadable dispositions log must not silently suppress", code)
	}
}

//fusa:test REQ-CLI-CHECK001
func TestRunCheck_DoesNotSurfaceFusaStubFindings(t *testing.T) {
	files := testutil.MinimalProject()
	// A fmea.json with hardcoded, repeated content that would trip both
	// FUSA-STUB001 (the literal "TBD") and FUSA-STUB002 (a blanket-fallback
	// failureMode) if `check` still read evidence artifacts (it must not).
	entries := `[`
	for i := 0; i < 11; i++ {
		if i > 0 {
			entries += ","
		}
		entries += `{"failureMode":"TBD","effect":"TBD","cause":"TBD"}`
	}
	entries += `]`
	files["fmea.json"] = `{"entries":` + entries + `}`

	dir := testutil.ProjectDir(t, files)

	var out, errBuf bytes.Buffer
	runCheck([]string{"--dir", dir, "--format", "json"}, &out, &errBuf)

	if strings.Contains(out.String(), "FUSA-STUB") {
		t.Errorf("gofusa check must not surface FUSA-STUB findings (x-FuSa spec §1.6.1); got: %s", out.String())
	}
}
