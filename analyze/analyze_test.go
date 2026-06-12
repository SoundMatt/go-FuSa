package analyze_test

import (
	"context"
	"testing"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/config"
	"github.com/SoundMatt/go-FuSa/engine"
	"github.com/SoundMatt/go-FuSa/testutil"

	_ "github.com/SoundMatt/go-FuSa/analyze" // activate rules
)

func runAnalyze(t *testing.T, files map[string]string) []fusa.Finding {
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

// ─── ANA001 ───────────────────────────────────────────────────────────────────

//fusa:test REQ-ANA001
func TestANA001_GoroutineNoSignal(t *testing.T) {
	src := `package main

func start() {
	go func() {
		for {
			// does work
		}
	}()
}
`
	findings := runAnalyze(t, testutil.GoSource("main.go", src))
	if !hasRule(findings, "ANA001") {
		t.Error("ANA001: expected finding for goroutine without signal")
	}
}

func TestANA001_GoroutineWithSelect_NoFinding(t *testing.T) {
	src := `package main

func start(done <-chan struct{}) {
	go func() {
		for {
			select {
			case <-done:
				return
			default:
			}
		}
	}()
}
`
	findings := runAnalyze(t, testutil.GoSource("main.go", src))
	if hasRule(findings, "ANA001") {
		t.Error("ANA001: unexpected finding for goroutine with select")
	}
}

func TestANA001_GoroutineWithCtxReference_NoFinding(t *testing.T) {
	src := `package main

import "context"

func start(ctx context.Context) {
	go func() {
		<-ctx.Done()
	}()
}
`
	findings := runAnalyze(t, testutil.GoSource("main.go", src))
	if hasRule(findings, "ANA001") {
		t.Error("ANA001: unexpected finding for goroutine referencing ctx")
	}
}

// ─── ANA002 ───────────────────────────────────────────────────────────────────

//fusa:test REQ-ANA002
func TestANA002_GoroutineInForLoop(t *testing.T) {
	src := `package main

func process(items []int) {
	for _, item := range items {
		item := item
		go func() { _ = item }()
	}
}
`
	findings := runAnalyze(t, testutil.GoSource("main.go", src))
	if !hasRule(findings, "ANA002") {
		t.Error("ANA002: expected finding for goroutine in range loop")
	}
}

func TestANA002_GoroutineOutsideLoop_NoFinding(t *testing.T) {
	src := `package main

func start() {
	go func() {}()
}
`
	findings := runAnalyze(t, testutil.GoSource("main.go", src))
	if hasRule(findings, "ANA002") {
		t.Error("ANA002: unexpected finding for goroutine outside loop")
	}
}

func TestANA002_GoroutineInInfiniteLoop(t *testing.T) {
	src := `package main

func spawnForever() {
	for {
		go func() {}()
	}
}
`
	findings := runAnalyze(t, testutil.GoSource("main.go", src))
	if !hasRule(findings, "ANA002") {
		t.Error("ANA002: expected finding for goroutine in infinite loop")
	}
}

// ─── ANA003 ───────────────────────────────────────────────────────────────────

//fusa:test REQ-ANA003
func TestANA003_SleepInGoroutine(t *testing.T) {
	src := `package main

import "time"

func poll() {
	go func() {
		for {
			time.Sleep(time.Second)
		}
	}()
}
`
	findings := runAnalyze(t, testutil.GoSource("main.go", src))
	if !hasRule(findings, "ANA003") {
		t.Error("ANA003: expected finding for time.Sleep in goroutine")
	}
}

func TestANA003_SleepOutsideGoroutine_NoFinding(t *testing.T) {
	src := `package main

import "time"

func wait() {
	time.Sleep(time.Second)
}
`
	findings := runAnalyze(t, testutil.GoSource("main.go", src))
	if hasRule(findings, "ANA003") {
		t.Error("ANA003: unexpected finding for time.Sleep outside goroutine")
	}
}

// ─── ANA004 ───────────────────────────────────────────────────────────────────

//fusa:test REQ-ANA004
func TestANA004_DeferInLoop(t *testing.T) {
	src := `package main

import "os"

func processFiles(paths []string) {
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		defer f.Close()
	}
}
`
	findings := runAnalyze(t, testutil.GoSource("main.go", src))
	if !hasRule(findings, "ANA004") {
		t.Error("ANA004: expected finding for defer in loop")
	}
}

func TestANA004_DeferOutsideLoop_NoFinding(t *testing.T) {
	src := `package main

import "os"

func readFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return nil
}
`
	findings := runAnalyze(t, testutil.GoSource("main.go", src))
	if hasRule(findings, "ANA004") {
		t.Error("ANA004: unexpected finding for defer outside loop")
	}
}

func TestANA004_DeferInForLoop(t *testing.T) {
	src := `package main

import "os"

func walk(n int) {
	for i := 0; i < n; i++ {
		f, err := os.Open("x")
		if err != nil {
			continue
		}
		defer f.Close()
	}
}
`
	findings := runAnalyze(t, testutil.GoSource("main.go", src))
	if !hasRule(findings, "ANA004") {
		t.Error("ANA004: expected finding for defer in for loop")
	}
}

// ─── endLine / endColumn (§4 MAY) ────────────────────────────────────────────

func TestAnalyze_EndLinePopulated_GoStmt(t *testing.T) {
	src := `package main
func fn() { go func() {}() }
`
	findings := runAnalyze(t, testutil.GoSource("main.go", src))
	for _, f := range findings {
		if f.RuleID == "ANA001" {
			if f.Location.EndLine == 0 {
				t.Errorf("ANA001: EndLine not populated (got 0)")
			}
			if f.Location.EndLine < f.Location.Line {
				t.Errorf("ANA001: EndLine %d < Line %d", f.Location.EndLine, f.Location.Line)
			}
			return
		}
	}
	t.Error("ANA001: no finding produced")
}

func TestAnalyze_EndLinePopulated_DeferInLoop(t *testing.T) {
	src := `package main
func fn() {
	for i := 0; i < 3; i++ {
		defer func() {}()
	}
}
`
	findings := runAnalyze(t, testutil.GoSource("main.go", src))
	for _, f := range findings {
		if f.RuleID == "ANA004" {
			if f.Location.EndLine == 0 {
				t.Errorf("ANA004: EndLine not populated (got 0)")
			}
			return
		}
	}
	t.Error("ANA004: no finding produced")
}

// ─── Descriptions ─────────────────────────────────────────────────────────────

func TestAnalyzeRuleDescriptions(t *testing.T) {
	for _, r := range engine.Default.Rules() {
		if len(r.ID()) >= 3 && r.ID()[:3] == "ANA" {
			if r.Description() == "" {
				t.Errorf("%s: Description() returned empty string", r.ID())
			}
		}
	}
}

// ─── Fuzz ─────────────────────────────────────────────────────────────────────

func FuzzAnalyzeRules(f *testing.F) {
	f.Add("package main\nfunc main(){}\n")
	f.Add("package main\nfunc fn(){go func(){for{}}()}\n")
	f.Add("package main\nimport \"time\"\nfunc fn(){go func(){time.Sleep(1)}()}\n")
	f.Add("")
	f.Add("not valid go source")
	f.Fuzz(func(t *testing.T, src string) {
		dir := testutil.ProjectDir(t, testutil.GoSource("fuzz.go", src))
		cfg := config.Default("fuzztest", "fuzztest")
		_, _ = engine.Default.Run(context.Background(), dir, cfg) // must not panic
	})
}
