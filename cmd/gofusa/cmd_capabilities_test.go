package main

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestCapabilities_StandardsSLSA(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCapabilities([]string{}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runCapabilities exit %d: %s", code, stderr.String())
	}
	var cap capabilities
	if err := json.Unmarshal(stdout.Bytes(), &cap); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	for _, s := range cap.Standards {
		if s == "slsa-v1.0" {
			t.Error("capabilities.Standards contains \"slsa-v1.0\", want canonical \"slsa\" (§2.4.1)")
		}
	}
	found := false
	for _, s := range cap.Standards {
		if s == "slsa" {
			found = true
			break
		}
	}
	if !found {
		t.Error("capabilities.Standards does not contain canonical \"slsa\"")
	}
}

func TestCapabilities_NoAbsoluteStandards(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCapabilities([]string{}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runCapabilities exit %d", code)
	}
	var cap capabilities
	if err := json.Unmarshal(stdout.Bytes(), &cap); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if len(cap.Standards) == 0 {
		t.Fatal("capabilities.Standards is empty")
	}
}
