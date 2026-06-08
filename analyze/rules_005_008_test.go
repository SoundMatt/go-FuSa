package analyze_test

import (
	"testing"

	"github.com/SoundMatt/go-FuSa/testutil"
)

// ─── ANA005 ───────────────────────────────────────────────────────────────────

//fusa:test REQ-ANA005
func TestANA005_ContextDropped(t *testing.T) {
	src := `package main

import "context"

func do(ctx context.Context) {
	bg := context.Background()
	_ = bg
}
`
	findings := runAnalyze(t, testutil.GoSource("main.go", src))
	if !hasRule(findings, "ANA005") {
		t.Error("ANA005: expected finding when context.Background() used inside func with ctx param")
	}
}

func TestANA005_ContextTODODropped(t *testing.T) {
	src := `package main

import "context"

func do(ctx context.Context) {
	c := context.TODO()
	_ = c
}
`
	findings := runAnalyze(t, testutil.GoSource("main.go", src))
	if !hasRule(findings, "ANA005") {
		t.Error("ANA005: expected finding for context.TODO() inside ctx-accepting func")
	}
}

func TestANA005_ContextBackgroundAtTopLevel_NoFinding(t *testing.T) {
	src := `package main

import "context"

func main() {
	ctx := context.Background()
	_ = ctx
}
`
	findings := runAnalyze(t, testutil.GoSource("main.go", src))
	if hasRule(findings, "ANA005") {
		t.Error("ANA005: unexpected finding for context.Background() in func without ctx param")
	}
}

// ─── ANA006 ───────────────────────────────────────────────────────────────────

//fusa:test REQ-ANA006
func TestANA006_ErrorNotWrapped(t *testing.T) {
	src := `package main

import "fmt"

func do(err error) error {
	return fmt.Errorf("operation failed: %v", err)
}
`
	findings := runAnalyze(t, testutil.GoSource("main.go", src))
	if !hasRule(findings, "ANA006") {
		t.Error("ANA006: expected finding for fmt.Errorf without %w")
	}
}

func TestANA006_ErrorWrapped_NoFinding(t *testing.T) {
	src := `package main

import "fmt"

func do(err error) error {
	return fmt.Errorf("operation failed: %w", err)
}
`
	findings := runAnalyze(t, testutil.GoSource("main.go", src))
	if hasRule(findings, "ANA006") {
		t.Error("ANA006: unexpected finding for fmt.Errorf with %w")
	}
}

// ─── ANA007 ───────────────────────────────────────────────────────────────────

//fusa:test REQ-ANA007
func TestANA007_NilDerefRisk(t *testing.T) {
	src := `package main

import "os"

func bad() {
	f, err := os.Open("x")
	f.Close()
	_ = err
}
`
	findings := runAnalyze(t, testutil.GoSource("main.go", src))
	if !hasRule(findings, "ANA007") {
		t.Error("ANA007: expected finding for use of return value before error check")
	}
}

func TestANA007_ErrorChecked_NoFinding(t *testing.T) {
	src := `package main

import "os"

func good() {
	f, err := os.Open("x")
	if err != nil {
		return
	}
	_ = f
}
`
	findings := runAnalyze(t, testutil.GoSource("main.go", src))
	if hasRule(findings, "ANA007") {
		t.Error("ANA007: unexpected finding when error is checked before use")
	}
}

// ─── ANA008 ───────────────────────────────────────────────────────────────────

//fusa:test REQ-ANA008
func TestANA008_GoroutineSharedVar(t *testing.T) {
	src := `package main

var counter int

func inc() {
	go func() {
		counter++
	}()
}
`
	findings := runAnalyze(t, testutil.GoSource("main.go", src))
	if !hasRule(findings, "ANA008") {
		t.Error("ANA008: expected finding for goroutine accessing package-level variable")
	}
}

func TestANA008_LocalVar_NoFinding(t *testing.T) {
	src := `package main

func run() {
	local := 0
	go func() {
		_ = local
	}()
}
`
	findings := runAnalyze(t, testutil.GoSource("main.go", src))
	if hasRule(findings, "ANA008") {
		t.Error("ANA008: unexpected finding for goroutine accessing local variable")
	}
}
