package lint_test

import (
	"context"
	"testing"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/config"
	"github.com/SoundMatt/go-FuSa/engine"
	"github.com/SoundMatt/go-FuSa/testutil"

	_ "github.com/SoundMatt/go-FuSa/lint" // activate rules
)

func runLint(t *testing.T, files map[string]string) []fusa.Finding {
	t.Helper()
	dir := testutil.ProjectDir(t, files)
	cfg := config.Default("github.com/example/test", "test")
	result, err := engine.Default.Run(context.Background(), dir, cfg)
	if err != nil {
		t.Fatalf("engine.Run: %v", err)
	}
	return result.Findings
}

func hasRule(findings []fusa.Finding, ruleID string) bool {
	for _, f := range findings {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}

// ─── LINT001 ──────────────────────────────────────────────────────────────────

//fusa:test REQ-LINT001
func TestLINT001_DiscardedError(t *testing.T) {
	src := `package main

import "os"

func main() {
	f, _ := os.Open("file.txt")
	_ = f
}
`
	findings := runLint(t, testutil.GoSource("main.go", src))
	if !hasRule(findings, "LINT001") {
		t.Error("LINT001: expected finding for discarded error return")
	}
}

func TestLINT001_Clean(t *testing.T) {
	src := `package main

import "os"

func main() {
	f, err := os.Open("file.txt")
	if err != nil {
		return
	}
	_ = f
}
`
	findings := runLint(t, testutil.GoSource("main.go", src))
	if hasRule(findings, "LINT001") {
		t.Error("LINT001: unexpected finding for properly handled error")
	}
}

func TestLINT001_SingleReturn_NoFinding(t *testing.T) {
	// Single-return discard is acceptable (e.g. _ = someNonErrorVal)
	src := `package main

func compute() int { return 42 }

func main() {
	_ = compute()
}
`
	findings := runLint(t, testutil.GoSource("main.go", src))
	if hasRule(findings, "LINT001") {
		t.Error("LINT001: unexpected finding for single-return discard")
	}
}

// ─── LINT002 ──────────────────────────────────────────────────────────────────

//fusa:test REQ-LINT002
func TestLINT002_PanicDetected(t *testing.T) {
	src := `package main

func mustLoad() {
	panic("not implemented")
}
`
	findings := runLint(t, testutil.GoSource("main.go", src))
	if !hasRule(findings, "LINT002") {
		t.Error("LINT002: expected finding for panic() call")
	}
}

func TestLINT002_NoPanic(t *testing.T) {
	src := `package main

func load() error { return nil }
`
	findings := runLint(t, testutil.GoSource("main.go", src))
	if hasRule(findings, "LINT002") {
		t.Error("LINT002: unexpected finding in panic-free code")
	}
}

// ─── LINT003 ──────────────────────────────────────────────────────────────────

//fusa:test REQ-LINT003
func TestLINT003_RecoverInventoried(t *testing.T) {
	src := `package main

func safe(fn func()) {
	defer func() {
		if r := recover(); r != nil {
			_ = r
		}
	}()
	fn()
}
`
	findings := runLint(t, testutil.GoSource("main.go", src))
	if !hasRule(findings, "LINT003") {
		t.Error("LINT003: expected INFO finding for recover() inventory")
	}
}

func TestLINT003_NoRecover(t *testing.T) {
	src := `package main

func add(a, b int) int { return a + b }
`
	findings := runLint(t, testutil.GoSource("main.go", src))
	if hasRule(findings, "LINT003") {
		t.Error("LINT003: unexpected finding in recover-free code")
	}
}

// ─── LINT004 ──────────────────────────────────────────────────────────────────

//fusa:test REQ-LINT004
func TestLINT004_UnsafeInventoried(t *testing.T) {
	src := `package main

import "unsafe"

func size() uintptr {
	var x int
	return unsafe.Sizeof(x)
}
`
	findings := runLint(t, testutil.GoSource("main.go", src))
	if !hasRule(findings, "LINT004") {
		t.Error("LINT004: expected WARNING for unsafe import")
	}
}

func TestLINT004_NoUnsafe(t *testing.T) {
	src := `package main

func add(a, b int) int { return a + b }
`
	findings := runLint(t, testutil.GoSource("main.go", src))
	if hasRule(findings, "LINT004") {
		t.Error("LINT004: unexpected finding for safe code")
	}
}

// ─── LINT005 ──────────────────────────────────────────────────────────────────

//fusa:test REQ-LINT005
func TestLINT005_ReflectInventoried(t *testing.T) {
	src := `package main

import "reflect"

func typeName(v interface{}) string {
	return reflect.TypeOf(v).Name()
}
`
	findings := runLint(t, testutil.GoSource("main.go", src))
	if !hasRule(findings, "LINT005") {
		t.Error("LINT005: expected INFO for reflect import")
	}
}

func TestLINT005_NoReflect(t *testing.T) {
	src := `package main

func double(n int) int { return n * 2 }
`
	findings := runLint(t, testutil.GoSource("main.go", src))
	if hasRule(findings, "LINT005") {
		t.Error("LINT005: unexpected finding for reflect-free code")
	}
}

// ─── LINT006 ──────────────────────────────────────────────────────────────────

//fusa:test REQ-LINT006
func TestLINT006_GlobalVar(t *testing.T) {
	src := `package main

var counter int

func increment() { counter++ }
`
	findings := runLint(t, testutil.GoSource("main.go", src))
	if !hasRule(findings, "LINT006") {
		t.Error("LINT006: expected INFO for package-level var")
	}
}

func TestLINT006_Const_NoFinding(t *testing.T) {
	src := `package main

const maxRetries = 3

func retries() int { return maxRetries }
`
	findings := runLint(t, testutil.GoSource("main.go", src))
	if hasRule(findings, "LINT006") {
		t.Error("LINT006: unexpected finding for const declaration")
	}
}

func TestLINT006_LocalVar_NoFinding(t *testing.T) {
	src := `package main

func run() {
	var buf []byte
	_ = buf
}
`
	findings := runLint(t, testutil.GoSource("main.go", src))
	if hasRule(findings, "LINT006") {
		t.Error("LINT006: unexpected finding for local var")
	}
}

// ─── Fuzz ─────────────────────────────────────────────────────────────────────

func FuzzLintRules(f *testing.F) {
	f.Add("package main\nfunc main(){}\n")
	f.Add("package main\nimport \"os\"\nfunc f(){x,_:=os.Open(\"\");_=x}\n")
	f.Add("package main\nfunc f(){panic(\"x\")}\n")
	f.Add("package main\nimport \"unsafe\"\nvar _=unsafe.Sizeof(0)\n")
	f.Add("")
	f.Add("not valid go source")
	f.Fuzz(func(t *testing.T, src string) {
		dir := testutil.ProjectDir(t, testutil.GoSource("fuzz.go", src))
		cfg := config.Default("fuzztest", "fuzztest")
		_, _ = engine.Default.Run(context.Background(), dir, cfg) // must not panic
	})
}
