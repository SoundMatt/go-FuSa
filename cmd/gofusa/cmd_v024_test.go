package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"strings"
	"testing"
)

// newCapFlagSet returns a flag.FlagSet with a single --format string flag,
// used by TestParseFlags_* helpers to avoid importing internal flag logic.
func newCapFlagSet() *flag.FlagSet {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(&bytes.Buffer{}) // suppress flag error output
	fs.String("format", "json", "output format")
	return fs
}

// ─── runCapabilities ──────────────────────────────────────────────────────────

//fusa:test REQ-CLI-CAP001
func TestRunCapabilities_DefaultJSON(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runCapabilities(nil, &out, &errBuf)
	if code != 0 {
		t.Fatalf("runCapabilities exit %d; stderr: %s", code, errBuf.String())
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v; raw: %s", err, out.String())
	}
	if doc["kind"] != "capabilities" {
		t.Errorf("kind = %q, want capabilities", doc["kind"])
	}
	if doc["tool"] != "go-FuSa" {
		t.Errorf("tool = %q, want go-FuSa", doc["tool"])
	}
	if doc["language"] != "go" {
		t.Errorf("language = %q, want go", doc["language"])
	}
}

//fusa:test REQ-CLI-CAP001
func TestRunCapabilities_ExplicitJSONFormat(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runCapabilities([]string{"--format", "json"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("runCapabilities --format json exit %d; stderr: %s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), `"commands"`) {
		t.Errorf("expected commands field; got: %s", out.String())
	}
}

//fusa:test REQ-CLI-CAP001
func TestRunCapabilities_Standards(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runCapabilities(nil, &out, &errBuf)
	if code != 0 {
		t.Fatalf("exit %d; stderr: %s", code, errBuf.String())
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	standards, ok := doc["standards"].([]interface{})
	if !ok || len(standards) == 0 {
		t.Errorf("expected non-empty standards slice; got: %v", doc["standards"])
	}
}

//fusa:test REQ-CLI-CAP001
func TestRunCapabilities_Formats(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runCapabilities(nil, &out, &errBuf)
	if code != 0 {
		t.Fatalf("exit %d; stderr: %s", code, errBuf.String())
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	formats, ok := doc["formats"].(map[string]interface{})
	if !ok || len(formats) == 0 {
		t.Errorf("expected non-empty formats map; got: %v", doc["formats"])
	}
}

//fusa:test REQ-CLI-CAP001
func TestRunCapabilities_VersionAndSpec(t *testing.T) {
	var out, errBuf bytes.Buffer
	runCapabilities(nil, &out, &errBuf)
	var doc map[string]interface{}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["toolVersion"] == "" || doc["toolVersion"] == nil {
		t.Error("toolVersion should be populated")
	}
	if doc["specVersion"] == "" || doc["specVersion"] == nil {
		t.Error("specVersion should be populated")
	}
}

//fusa:test REQ-CLI-CAP001
func TestRunCapabilities_UnsupportedFormat(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runCapabilities([]string{"--format", "text"}, &out, &errBuf)
	if code != 2 {
		t.Errorf("expected exit 2 for unsupported format, got %d", code)
	}
	if !strings.Contains(errBuf.String(), "unsupported format") {
		t.Errorf("expected 'unsupported format' in stderr; got: %s", errBuf.String())
	}
}

//fusa:test REQ-CLI-CAP001
func TestRunCapabilities_BadFlag(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runCapabilities([]string{"--nonexistent-flag"}, &out, &errBuf)
	if code != 2 {
		t.Errorf("expected exit 2 for unknown flag, got %d", code)
	}
}

//fusa:test REQ-CLI-CAP001
func TestRunCapabilities_GeneratedAt(t *testing.T) {
	var out, errBuf bytes.Buffer
	runCapabilities(nil, &out, &errBuf)
	if !strings.Contains(out.String(), "generatedAt") {
		t.Errorf("missing generatedAt field; got: %s", out.String())
	}
}

// ─── helpers: usageErrorf / runtimeErrorf ─────────────────────────────────────

//fusa:test REQ-CLI-HELPERS001
func TestUsageErrorf_ReturnsExitUsage(t *testing.T) {
	var errBuf bytes.Buffer
	code := usageErrorf(&errBuf, "mycommand", "bad value %q for flag %s", "xyz", "--foo")
	if code != 2 {
		t.Errorf("usageErrorf returned %d, want 2 (ExitUsage)", code)
	}
}

//fusa:test REQ-CLI-HELPERS001
func TestUsageErrorf_MessageContainsCmdAndDetails(t *testing.T) {
	var errBuf bytes.Buffer
	usageErrorf(&errBuf, "check", "unsupported format %q", "xml")
	msg := errBuf.String()
	if !strings.Contains(msg, "gofusa check") {
		t.Errorf("expected 'gofusa check' in message; got: %s", msg)
	}
	if !strings.Contains(msg, "xml") {
		t.Errorf("expected format value in message; got: %s", msg)
	}
}

//fusa:test REQ-CLI-HELPERS001
func TestUsageErrorf_NoFormatArgs(t *testing.T) {
	var errBuf bytes.Buffer
	code := usageErrorf(&errBuf, "trace", "missing required argument")
	if code != 2 {
		t.Errorf("expected exit 2, got %d", code)
	}
	if !strings.Contains(errBuf.String(), "missing required argument") {
		t.Errorf("expected message in output; got: %s", errBuf.String())
	}
}

//fusa:test REQ-CLI-HELPERS001
func TestRuntimeErrorf_ReturnsExitRuntime(t *testing.T) {
	var errBuf bytes.Buffer
	code := runtimeErrorf(&errBuf, "release", "failed to write SBOM: %v", "disk full")
	if code != 3 {
		t.Errorf("runtimeErrorf returned %d, want 3 (ExitRuntime)", code)
	}
}

//fusa:test REQ-CLI-HELPERS001
func TestRuntimeErrorf_MessageContainsCmdAndDetails(t *testing.T) {
	var errBuf bytes.Buffer
	runtimeErrorf(&errBuf, "coverage", "could not parse %s", "cover.out")
	msg := errBuf.String()
	if !strings.Contains(msg, "gofusa coverage") {
		t.Errorf("expected 'gofusa coverage' in message; got: %s", msg)
	}
	if !strings.Contains(msg, "cover.out") {
		t.Errorf("expected filename in message; got: %s", msg)
	}
}

//fusa:test REQ-CLI-HELPERS001
func TestRuntimeErrorf_NoFormatArgs(t *testing.T) {
	var errBuf bytes.Buffer
	code := runtimeErrorf(&errBuf, "check", "internal error")
	if code != 3 {
		t.Errorf("expected exit 3, got %d", code)
	}
	if !strings.Contains(errBuf.String(), "internal error") {
		t.Errorf("expected message in output; got: %s", errBuf.String())
	}
}

// ─── parseFlags ───────────────────────────────────────────────────────────────

//fusa:test REQ-CLI-HELPERS001
func TestParseFlags_ValidArgs(t *testing.T) {
	fs := newCapFlagSet()
	code := parseFlags(fs, []string{"--format", "json"})
	if code != 0 {
		t.Errorf("parseFlags valid args returned %d, want 0", code)
	}
}

//fusa:test REQ-CLI-HELPERS001
func TestParseFlags_InvalidFlag(t *testing.T) {
	fs := newCapFlagSet()
	code := parseFlags(fs, []string{"--no-such-flag"})
	if code != 2 {
		t.Errorf("parseFlags invalid flag returned %d, want 2", code)
	}
}
