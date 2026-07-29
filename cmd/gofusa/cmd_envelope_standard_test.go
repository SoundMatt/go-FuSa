package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/SoundMatt/go-FuSa/config"
)

// ─── check/report envelope "standard" field (x-FuSa spec §2.4.1) ─────────────
//
// Regression coverage for: the JSON envelope's top-level "standard" field
// must be the canonical lowercase id (e.g. "iso26262"), never go-FuSa's
// internal uppercase/no-space Standard enum spelling (e.g. "ISO26262").

//fusa:test REQ-CLI005
func TestRunCheck_JSONFormat_CanonicalStandardID(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default("github.com/x/y", "y")
	cfg.Standard = config.StandardISO26262
	cfg.Project.Standard = config.StandardISO26262
	if err := config.Save(filepath.Join(dir, config.ConfigFile), cfg); err != nil {
		t.Fatalf("Save config: %v", err)
	}

	var out, errBuf bytes.Buffer
	code := runCheck([]string{"--dir", dir, "--format", "json"}, &out, &errBuf)
	if code != 0 && code != 1 {
		t.Fatalf("unexpected exit %d: %s", code, errBuf.String())
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("JSON parse: %v\n%s", err, out.String())
	}
	if doc["standard"] != "iso26262" {
		t.Errorf("check envelope standard = %v, want canonical id \"iso26262\" (not \"ISO26262\")", doc["standard"])
	}
}

//fusa:test REQ-CLI005
func TestRunReport_JSONFormat_CanonicalStandardID(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default("github.com/x/y", "y")
	cfg.Standard = config.StandardDO178C
	cfg.Project.Standard = config.StandardDO178C
	if err := config.Save(filepath.Join(dir, config.ConfigFile), cfg); err != nil {
		t.Fatalf("Save config: %v", err)
	}

	var out, errBuf bytes.Buffer
	code := runReport([]string{"--dir", dir, "--format", "json"}, &out, &errBuf)
	if code != 0 && code != 1 {
		t.Fatalf("unexpected exit %d: %s", code, errBuf.String())
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("JSON parse: %v\n%s", err, out.String())
	}
	if doc["standard"] != "do178c" {
		t.Errorf("report envelope standard = %v, want canonical id \"do178c\" (not \"DO178C\")", doc["standard"])
	}
}

//fusa:test REQ-CLI005
func TestRunCheck_JSONFormat_GenericStandardOmitted(t *testing.T) {
	dir := t.TempDir()
	// config.Default already uses StandardGeneric; no .fusa.json written so
	// config.Default("", ...) applies via ErrNoConfig fallback.
	var out, errBuf bytes.Buffer
	code := runCheck([]string{"--dir", dir, "--format", "json"}, &out, &errBuf)
	if code != 0 && code != 1 {
		t.Fatalf("unexpected exit %d: %s", code, errBuf.String())
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("JSON parse: %v\n%s", err, out.String())
	}
	if v, ok := doc["standard"]; ok && v != "" {
		t.Errorf("check envelope standard for generic project = %v, want omitted/empty", v)
	}
}
