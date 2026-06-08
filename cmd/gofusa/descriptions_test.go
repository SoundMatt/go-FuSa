package main

import (
	"testing"

	"github.com/SoundMatt/go-FuSa/engine"
)

// TestAllRules_DescriptionNonEmpty verifies that every registered rule returns
// a non-empty description string. The main package blank-imports all rule sets,
// so engine.Default holds the complete registry.
//
//fusa:test REQ-ENG001
func TestAllRules_DescriptionNonEmpty(t *testing.T) {
	rules := engine.Default.Rules()
	if len(rules) == 0 {
		t.Fatal("engine.Default has no rules — blank imports missing?")
	}
	for _, r := range rules {
		if r.Description() == "" {
			t.Errorf("rule %s: Description() returned empty string", r.ID())
		}
	}
}
