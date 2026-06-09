package comp_test

import (
	"context"
	"go/ast"
	"testing"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/comp"
	"github.com/SoundMatt/go-FuSa/config"
	"github.com/SoundMatt/go-FuSa/engine"
	"github.com/SoundMatt/go-FuSa/testutil"

	_ "github.com/SoundMatt/go-FuSa/comp"
)

func runComp(t *testing.T, files map[string]string) []fusa.Finding {
	t.Helper()
	dir := testutil.ProjectDir(t, files)
	cfg := config.Default("github.com/example/test", "test")
	result, err := engine.Default.Run(context.Background(), dir, cfg)
	if err != nil {
		t.Fatalf("engine.Run: %v", err)
	}
	var findings []fusa.Finding
	for _, f := range result.Findings {
		if f.RuleID == "COMP001" {
			findings = append(findings, f)
		}
	}
	return findings
}

//fusa:test REQ-COMP001
func TestCOMP001_HighComplexity(t *testing.T) {
	// Function with 11 branches → complexity 12 > threshold 10
	src := `package main

func complex(x int) int {
	if x == 1 {
		return 1
	} else if x == 2 {
		return 2
	} else if x == 3 {
		return 3
	} else if x == 4 {
		return 4
	} else if x == 5 {
		return 5
	} else if x == 6 {
		return 6
	} else if x == 7 {
		return 7
	} else if x == 8 {
		return 8
	} else if x == 9 {
		return 9
	} else if x == 10 {
		return 10
	} else if x == 11 {
		return 11
	}
	return 0
}
`
	findings := runComp(t, testutil.GoSource("main.go", src))
	if len(findings) == 0 {
		t.Error("COMP001: expected finding for high-complexity function")
	}
}

func TestCOMP001_LowComplexity_NoFinding(t *testing.T) {
	src := `package main

func simple(x int) int {
	if x > 0 {
		return x
	}
	return -x
}
`
	findings := runComp(t, testutil.GoSource("main.go", src))
	if len(findings) != 0 {
		t.Errorf("COMP001: unexpected finding for simple function: %v", findings)
	}
}

func TestCOMP001_LogicalOps(t *testing.T) {
	// Logical operators count as branches
	src := `package main

func check(a, b, c, d, e, f, g, h, i, j, k bool) bool {
	return a && b && c && d && e && f && g && h && i && j && k
}
`
	findings := runComp(t, testutil.GoSource("main.go", src))
	if len(findings) == 0 {
		t.Error("COMP001: expected finding for function with many logical ops")
	}
}

func TestCOMP001_SwitchCases(t *testing.T) {
	// 12 cases → complexity 13
	src := `package main

func classify(x int) string {
	switch x {
	case 1: return "one"
	case 2: return "two"
	case 3: return "three"
	case 4: return "four"
	case 5: return "five"
	case 6: return "six"
	case 7: return "seven"
	case 8: return "eight"
	case 9: return "nine"
	case 10: return "ten"
	case 11: return "eleven"
	case 12: return "twelve"
	}
	return "other"
}
`
	findings := runComp(t, testutil.GoSource("main.go", src))
	if len(findings) == 0 {
		t.Error("COMP001: expected finding for function with many switch cases")
	}
}

func TestCOMP001_Description(t *testing.T) {
	for _, r := range engine.Default.Rules() {
		if r.ID() == "COMP001" {
			if r.Description() == "" {
				t.Error("COMP001: Description() returned empty string")
			}
			return
		}
	}
	t.Error("COMP001 rule not registered")
}

func TestComplexity_NilBody(t *testing.T) {
	fn := &ast.FuncDecl{Body: nil}
	if got := comp.Complexity(fn); got != 0 {
		t.Errorf("Complexity(nil body) = %d, want 0", got)
	}
}

func TestCOMP001_SelectStatement(t *testing.T) {
	// select with multiple non-default cases → coverage of *ast.CommClause
	src := `package main

import "time"

func poll(ch <-chan int, done <-chan struct{}, extra <-chan bool, q <-chan byte, r <-chan rune, s <-chan string, u <-chan uint, v <-chan int64, w <-chan float64, x <-chan int32) int {
	for {
		select {
		case v := <-ch:
			if v > 0 { return v }
		case <-done:
			return -1
		case <-extra:
			return -2
		case <-q:
			return -3
		case <-r:
			return -4
		case <-s:
			return -5
		case <-u:
			return -6
		case <-v:
			return -7
		case <-w:
			return -8
		case <-x:
			return -9
		case <-time.After(time.Second):
			return 0
		}
	}
}
`
	findings := runComp(t, testutil.GoSource("main.go", src))
	if len(findings) == 0 {
		t.Error("COMP001: expected finding for function with many select cases")
	}
}
