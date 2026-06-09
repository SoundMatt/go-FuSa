package coverage_test

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/SoundMatt/go-FuSa/coverage"
)

const sampleProfile = `mode: atomic
example.com/foo/bar.go:10.15,12.3 1 5
example.com/foo/bar.go:14.10,16.3 2 0
example.com/foo/baz.go:5.10,7.3 3 3
`

func TestParse(t *testing.T) {
	blocks, err := coverage.Parse(strings.NewReader(sampleProfile))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(blocks) != 3 {
		t.Fatalf("want 3 blocks, got %d", len(blocks))
	}
	if blocks[0].File != "example.com/foo/bar.go" {
		t.Errorf("block[0].File = %q", blocks[0].File)
	}
	if blocks[0].Stmts != 1 {
		t.Errorf("block[0].Stmts = %d, want 1", blocks[0].Stmts)
	}
	if blocks[0].Count != 5 {
		t.Errorf("block[0].Count = %d, want 5", blocks[0].Count)
	}
	if blocks[1].Count != 0 {
		t.Errorf("block[1].Count = %d, want 0", blocks[1].Count)
	}
}

func TestParse_Empty(t *testing.T) {
	blocks, err := coverage.Parse(strings.NewReader("mode: set\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(blocks) != 0 {
		t.Errorf("expected 0 blocks, got %d", len(blocks))
	}
}

func TestAnalyse_StatementCoverage(t *testing.T) {
	blocks, _ := coverage.Parse(strings.NewReader(sampleProfile))
	rep := coverage.Analyse(blocks, coverage.DALB)
	if rep.DAL != coverage.DALB {
		t.Errorf("DAL = %v", rep.DAL)
	}
	// 1+3=4 stmts covered out of 1+2+3=6 total
	if rep.StmtTotal != 6 {
		t.Errorf("StmtTotal = %d, want 6", rep.StmtTotal)
	}
	if rep.StmtCovered != 4 {
		t.Errorf("StmtCovered = %d, want 4", rep.StmtCovered)
	}
	expected := float64(4) * 100 / float64(6)
	if rep.StmtPct < expected-0.1 || rep.StmtPct > expected+0.1 {
		t.Errorf("StmtPct = %.1f, want ~%.1f", rep.StmtPct, expected)
	}
}

func TestAnalyse_DALRequirements(t *testing.T) {
	blocks := []coverage.Block{{File: "f.go", StartLine: 1, EndLine: 5, Stmts: 10, Count: 10}}

	repA := coverage.Analyse(blocks, coverage.DALA)
	if !repA.MCDCRequired {
		t.Error("DAL-A: MCDCRequired should be true")
	}
	if !repA.DecisionRequired {
		t.Error("DAL-A: DecisionRequired should be true")
	}

	repB := coverage.Analyse(blocks, coverage.DALB)
	if repB.MCDCRequired {
		t.Error("DAL-B: MCDCRequired should be false")
	}
	if !repB.DecisionRequired {
		t.Error("DAL-B: DecisionRequired should be true")
	}

	repC := coverage.Analyse(blocks, coverage.DALC)
	if repC.MCDCRequired {
		t.Error("DAL-C: MCDCRequired should be false")
	}
	if repC.DecisionRequired {
		t.Error("DAL-C: DecisionRequired should be false")
	}
}

func TestAnalyse_Gaps(t *testing.T) {
	blocks, _ := coverage.Parse(strings.NewReader(sampleProfile))
	rep := coverage.Analyse(blocks, coverage.DALB)
	// bar.go has 1 block uncovered so it should appear in gaps
	found := false
	for _, g := range rep.Gaps {
		if strings.Contains(g, "bar.go") {
			found = true
		}
	}
	if !found {
		t.Error("expected bar.go gap, not found")
	}
}

func TestRender_Text(t *testing.T) {
	blocks, _ := coverage.Parse(strings.NewReader(sampleProfile))
	rep := coverage.Analyse(blocks, coverage.DALB)
	var buf bytes.Buffer
	if err := coverage.Render(&buf, rep, "text"); err != nil {
		t.Fatalf("Render text: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "DO-178C Structural Coverage Report") {
		t.Error("missing report header")
	}
	if !strings.Contains(out, "DAL-B") {
		t.Error("missing DAL")
	}
}

func TestRender_JSON(t *testing.T) {
	blocks, _ := coverage.Parse(strings.NewReader(sampleProfile))
	rep := coverage.Analyse(blocks, coverage.DALA)
	var buf bytes.Buffer
	if err := coverage.Render(&buf, rep, "json"); err != nil {
		t.Fatalf("Render json: %v", err)
	}
	if !strings.Contains(buf.String(), `"dal"`) {
		t.Error("missing dal field in JSON output")
	}
}

func TestRender_InvalidFormat(t *testing.T) {
	rep := coverage.Analyse(nil, coverage.DALB)
	if err := coverage.Render(&bytes.Buffer{}, rep, "csv"); err == nil {
		t.Error("expected error for unsupported format")
	}
}

func TestBuildFromFile_NotFound(t *testing.T) {
	_, err := coverage.BuildFromFile("/does/not/exist/coverage.out", coverage.DALB)
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestBuildFromFile_Valid(t *testing.T) {
	content := "mode: set\ngithub.com/x/pkg/file.go:10.2,12.5 3 1\n"
	f, err := os.CreateTemp("", "coverage*.out")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	if _, werr := f.WriteString(content); werr != nil {
		t.Fatal(werr)
	}
	f.Close()
	rep, err := coverage.BuildFromFile(f.Name(), coverage.DALB)
	if err != nil {
		t.Fatalf("BuildFromFile: %v", err)
	}
	if rep.StmtTotal == 0 {
		t.Error("expected stmts")
	}
}

func TestRunMutation_NoTool(t *testing.T) {
	// Without go-mutesting in PATH, should return a report with a note and no error.
	dir := t.TempDir()
	rep, err := coverage.RunMutation(dir, coverage.DALA)
	if err != nil {
		t.Fatalf("RunMutation: %v", err)
	}
	if rep == nil {
		t.Fatal("expected non-nil report")
	}
	// Either go-mutesting is not installed (most likely in CI) → Note set
	// or it is installed → results returned; either way no panic.
	if rep.Note != "" {
		if !strings.Contains(rep.Note, "go-mutesting") {
			t.Errorf("unexpected note: %s", rep.Note)
		}
	}
}
