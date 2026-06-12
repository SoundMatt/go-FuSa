package comp_test

import (
	"testing"

	"github.com/SoundMatt/go-FuSa/comp"
	"github.com/SoundMatt/go-FuSa/testutil"
)

//fusa:test REQ-COMP-ASSESS001
func TestThresholdForDAL(t *testing.T) {
	cases := []struct {
		dal  string
		want int
	}{
		{"DAL-A", 4},
		{"DAL-B", 10},
		{"DAL-C", 15},
		{"DAL-D", 20},
		{"", comp.DefaultThreshold},
		{"unknown", comp.DefaultThreshold},
	}
	for _, c := range cases {
		if got := comp.ThresholdForDAL(c.dal); got != c.want {
			t.Errorf("ThresholdForDAL(%q) = %d, want %d", c.dal, got, c.want)
		}
	}
}

//fusa:test REQ-COMP-ASSESS002
func TestAssess_EmptyProject(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	results, err := comp.Assess(dir, comp.DefaultThreshold)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	for _, r := range results {
		if r.Exceeds {
			t.Errorf("expected no exceedances in minimal project, got %+v", r)
		}
	}
}

//fusa:test REQ-COMP-ASSESS002
func TestAssess_HighComplexity(t *testing.T) {
	src := `package main

func tooBig(x int) int {
	if x == 1 { return 1 }
	if x == 2 { return 2 }
	if x == 3 { return 3 }
	if x == 4 { return 4 }
	if x == 5 { return 5 }
	if x == 6 { return 6 }
	if x == 7 { return 7 }
	if x == 8 { return 8 }
	if x == 9 { return 9 }
	if x == 10 { return 10 }
	if x == 11 { return 11 }
	return 0
}
`
	dir := testutil.ProjectDir(t, testutil.GoSource("main.go", src))
	results, err := comp.Assess(dir, comp.DefaultThreshold)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	exceeded := 0
	for _, r := range results {
		if r.Exceeds {
			exceeded++
		}
	}
	if exceeded == 0 {
		t.Error("Assess: expected at least one function exceeding threshold")
	}
}

//fusa:test REQ-COMP-ASSESS002
func TestAssess_TestFilesSkipped(t *testing.T) {
	files := testutil.GoSource("main.go", "package main\nfunc ok() {}\n")
	files["big_test.go"] = `package main

import "testing"

func TestBigComplex(t *testing.T) {
	if 1==1 { t.Log("a") }
	if 2==2 { t.Log("b") }
	if 3==3 { t.Log("c") }
	if 4==4 { t.Log("d") }
	if 5==5 { t.Log("e") }
	if 6==6 { t.Log("f") }
	if 7==7 { t.Log("g") }
	if 8==8 { t.Log("h") }
	if 9==9 { t.Log("i") }
	if 10==10 { t.Log("j") }
	if 11==11 { t.Log("k") }
}
`
	dir := testutil.ProjectDir(t, files)
	results, err := comp.Assess(dir, comp.DefaultThreshold)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	for _, r := range results {
		if r.Exceeds {
			t.Errorf("Assess: test file function should be skipped, got %+v", r)
		}
	}
}

//fusa:test REQ-COMP-ASSESS002
func TestAssess_AllFunctionResultFields(t *testing.T) {
	src := "package main\n\nfunc simple() {}\n"
	dir := testutil.ProjectDir(t, testutil.GoSource("main.go", src))
	results, err := comp.Assess(dir, comp.DefaultThreshold)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	var found bool
	for _, r := range results {
		if r.Name == "simple" {
			found = true
			if r.File == "" {
				t.Error("FunctionResult.File should not be empty")
			}
			if r.Line == 0 {
				t.Error("FunctionResult.Line should not be zero")
			}
			if r.Threshold != comp.DefaultThreshold {
				t.Errorf("FunctionResult.Threshold = %d, want %d", r.Threshold, comp.DefaultThreshold)
			}
			if r.Exceeds {
				t.Error("simple function should not exceed threshold")
			}
		}
	}
	if !found {
		t.Error("Assess: expected to find 'simple' function")
	}
}
