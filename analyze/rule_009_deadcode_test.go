package analyze_test

import (
	"testing"

	"github.com/SoundMatt/go-FuSa/testutil"
)

// ─── ANA009 ───────────────────────────────────────────────────────────────────

//fusa:test REQ-ANA009
func TestANA009_DeadCodeAfterReturn(t *testing.T) {
	src := `package main

func dead() int {
	return 1
	x := 2
	return x
}
`
	findings := runAnalyze(t, testutil.GoSource("main.go", src))
	if !hasRule(findings, "ANA009") {
		t.Error("ANA009: expected finding for code after return")
	}
}

func TestANA009_DeadCodeAfterPanic(t *testing.T) {
	src := `package main

func mustPanic() {
	panic("stop")
	_ = "unreachable"
}
`
	findings := runAnalyze(t, testutil.GoSource("main.go", src))
	if !hasRule(findings, "ANA009") {
		t.Error("ANA009: expected finding for code after panic")
	}
}

func TestANA009_DeadCodeAfterBreak(t *testing.T) {
	src := `package main

func loop() {
	for {
		break
		_ = "dead"
	}
}
`
	findings := runAnalyze(t, testutil.GoSource("main.go", src))
	if !hasRule(findings, "ANA009") {
		t.Error("ANA009: expected finding for code after break")
	}
}

func TestANA009_NoDeadCode(t *testing.T) {
	src := `package main

func normal() int {
	x := 1
	if x > 0 {
		return x
	}
	return 0
}
`
	findings := runAnalyze(t, testutil.GoSource("main.go", src))
	if hasRule(findings, "ANA009") {
		t.Error("ANA009: unexpected finding for normal code")
	}
}
