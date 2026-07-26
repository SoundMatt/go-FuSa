package coverage_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/SoundMatt/go-FuSa/coverage"
)

// writeFakeGoMutesting writes a helper binary that prints canned go-mutesting
// output to stdout. It compiles a tiny Go program so the output is byte-exact
// on all platforms. Returns the directory containing the binary; the caller
// should restore PATH after use.
func writeFakeGoMutesting(t *testing.T, stdout string) string {
	t.Helper()
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "src")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Write a tiny main.go that just prints the canned output.
	mainSrc := fmt.Sprintf(`package main

import "fmt"

func main() {
	fmt.Print(%q)
}
`, stdout)
	if err := os.WriteFile(filepath.Join(srcDir, "main.go"), []byte(mainSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "go.mod"), []byte("module fakemutesting\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Determine binary name
	binName := "go-mutesting"
	if runtime.GOOS == "windows" {
		binName = "go-mutesting.exe"
	}
	outBin := filepath.Join(dir, binName)
	cmd := exec.CommandContext(context.Background(), "go", "build", "-o", outBin, ".")
	cmd.Dir = srcDir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to compile fake go-mutesting: %v\n%s", err, out)
	}
	return dir
}

const sampleProfile = `mode: atomic
example.com/foo/bar.go:10.15,12.3 1 5
example.com/foo/bar.go:14.10,16.3 2 0
example.com/foo/baz.go:5.10,7.3 3 3
`

//fusa:test REQ-COV001
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

//fusa:test REQ-COV001
func TestParse_Empty(t *testing.T) {
	blocks, err := coverage.Parse(strings.NewReader("mode: set\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(blocks) != 0 {
		t.Errorf("expected 0 blocks, got %d", len(blocks))
	}
}

//fusa:test REQ-COV002
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

//fusa:test REQ-COV003
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

//fusa:test REQ-COV003
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

//fusa:test REQ-COV002
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

//fusa:test REQ-COV002
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

//fusa:test REQ-COV002
func TestRender_InvalidFormat(t *testing.T) {
	rep := coverage.Analyse(nil, coverage.DALB)
	if err := coverage.Render(&bytes.Buffer{}, rep, "csv"); err == nil {
		t.Error("expected error for unsupported format")
	}
}

//fusa:test REQ-COV001
func TestBuildFromFile_NotFound(t *testing.T) {
	_, err := coverage.BuildFromFile("/does/not/exist/coverage.out", coverage.DALB)
	if err == nil {
		t.Error("expected error for missing file")
	}
}

//fusa:test REQ-COV001
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

//fusa:test REQ-COV003
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

// ─── runGoMutesting / pkgPath / getOrCreate via fake binary ──────────────────

// fakeMutestingOutput is what a real go-mutesting produces when it kills all
// mutants plus a score summary line.
const fakeMutestingOutput = `PASS "pkg/foo/bar.go" with mutation "..."
PASS "pkg/foo/bar.go" with mutation "another"
FAIL "pkg/baz/baz.go" with mutation "..."
The mutation score is 0.67 (2/3)
`

//fusa:test REQ-COV003
func TestRunMutation_WithFakeBinary_ScoreParsed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script fake binary not supported on Windows")
	}
	binDir := writeFakeGoMutesting(t, fakeMutestingOutput)
	// Prepend our fake binary dir to PATH
	origPath := os.Getenv("PATH")
	t.Cleanup(func() { _ = os.Setenv("PATH", origPath) })
	if err := os.Setenv("PATH", binDir+string(os.PathListSeparator)+origPath); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	rep, err := coverage.RunMutation(dir, coverage.DALB)
	if err != nil {
		t.Fatalf("RunMutation: %v", err)
	}
	if rep == nil {
		t.Fatal("expected non-nil report")
	}
	// Score line says 0.67 → 67%
	if rep.Score < 60 || rep.Score > 70 {
		t.Errorf("Score = %.1f, want ~67", rep.Score)
	}
	// 2 killed, 1 survived
	if rep.Killed != 2 {
		t.Errorf("Killed = %d, want 2", rep.Killed)
	}
	if rep.Mutants != 3 {
		t.Errorf("Mutants = %d, want 3", rep.Mutants)
	}
	if rep.Survived != 1 {
		t.Errorf("Survived = %d, want 1", rep.Survived)
	}
}

//fusa:test REQ-COV003
func TestRunMutation_WithFakeBinary_PerPackageResults(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script fake binary not supported on Windows")
	}
	binDir := writeFakeGoMutesting(t, fakeMutestingOutput)
	origPath := os.Getenv("PATH")
	t.Cleanup(func() { _ = os.Setenv("PATH", origPath) })
	if err := os.Setenv("PATH", binDir+string(os.PathListSeparator)+origPath); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	rep, err := coverage.RunMutation(dir, coverage.DALC)
	if err != nil {
		t.Fatalf("RunMutation: %v", err)
	}
	// Should have 2 per-package results: pkg/foo and pkg/baz
	if len(rep.Results) == 0 {
		t.Fatalf("expected per-package results, got none")
	}
	foundFoo := false
	foundBaz := false
	for _, r := range rep.Results {
		if strings.Contains(r.Package, "foo") {
			foundFoo = true
			if r.Killed != 2 {
				t.Errorf("pkg/foo Killed = %d, want 2", r.Killed)
			}
		}
		if strings.Contains(r.Package, "baz") {
			foundBaz = true
			if r.Killed != 0 {
				t.Errorf("pkg/baz Killed = %d, want 0", r.Killed)
			}
		}
	}
	if !foundFoo {
		t.Error("expected pkg/foo in results")
	}
	if !foundBaz {
		t.Error("expected pkg/baz in results")
	}
}

//fusa:test REQ-COV003
func TestRunMutation_WithFakeBinary_HighScore_MCDCEvidence(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script fake binary not supported on Windows")
	}
	// Score > 80% → MCDCEvidence should say it's sufficient
	highScoreOutput := `PASS "pkg/a/a.go" with mutation "m1"
PASS "pkg/a/a.go" with mutation "m2"
PASS "pkg/a/a.go" with mutation "m3"
PASS "pkg/a/a.go" with mutation "m4"
PASS "pkg/a/a.go" with mutation "m5"
The mutation score is 0.83 (5/6)
`
	binDir := writeFakeGoMutesting(t, highScoreOutput)
	origPath := os.Getenv("PATH")
	t.Cleanup(func() { _ = os.Setenv("PATH", origPath) })
	if err := os.Setenv("PATH", binDir+string(os.PathListSeparator)+origPath); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	rep, err := coverage.RunMutation(dir, coverage.DALA)
	if err != nil {
		t.Fatalf("RunMutation: %v", err)
	}
	if !strings.Contains(rep.MCDCEvidence, "80%") {
		t.Errorf("expected MC/DC evidence message for high score; got: %s", rep.MCDCEvidence)
	}
}

//fusa:test REQ-COV003
func TestRunMutation_WithFakeBinary_EmptyOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script fake binary not supported on Windows")
	}
	binDir := writeFakeGoMutesting(t, "")
	origPath := os.Getenv("PATH")
	t.Cleanup(func() { _ = os.Setenv("PATH", origPath) })
	if err := os.Setenv("PATH", binDir+string(os.PathListSeparator)+origPath); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	rep, err := coverage.RunMutation(dir, coverage.DALB)
	if err != nil {
		t.Fatalf("RunMutation: %v", err)
	}
	if rep.Mutants != 0 {
		t.Errorf("empty output: Mutants = %d, want 0", rep.Mutants)
	}
}

// ─── MC/DC ────────────────────────────────────────────────────────────────────

//fusa:test REQ-COV015
func TestParseMCDC_AllCovered(t *testing.T) {
	input := `{"data":[{"functions":[{"name":"Foo","mcdc_records":[{"conditions":[{"covered_true_count":3,"covered_false_count":2}]}]}]}]}`
	rep, err := coverage.ParseMCDC([]byte(input), coverage.DALA, "test", 100)
	if err != nil {
		t.Fatalf("ParseMCDC: %v", err)
	}
	if !rep.Passed {
		t.Errorf("ParseMCDC: expected Passed=true, got false; note: %s", rep.Note)
	}
	if rep.TotalConditions != 1 || rep.CoveredConditions != 1 {
		t.Errorf("ParseMCDC: TotalConditions=%d CoveredConditions=%d, want 1 1",
			rep.TotalConditions, rep.CoveredConditions)
	}
	if rep.CoveragePct != 100 {
		t.Errorf("ParseMCDC: CoveragePct=%.1f, want 100.0", rep.CoveragePct)
	}
}

//fusa:test REQ-COV015
func TestParseMCDC_UncoveredCondition(t *testing.T) {
	// covered_false_count=0 → condition not MC/DC covered.
	input := `{"data":[{"functions":[{"name":"Bar","mcdc_records":[{"conditions":[{"covered_true_count":5,"covered_false_count":0}]}]}]}]}`
	rep, err := coverage.ParseMCDC([]byte(input), coverage.DALA, "test", 100)
	if err != nil {
		t.Fatalf("ParseMCDC: %v", err)
	}
	if rep.Passed {
		t.Error("ParseMCDC: expected Passed=false for uncovered condition")
	}
	if rep.CoveredConditions != 0 || rep.TotalConditions != 1 {
		t.Errorf("ParseMCDC: covered=%d total=%d, want 0 1",
			rep.CoveredConditions, rep.TotalConditions)
	}
	if !strings.Contains(rep.Note, "MC/DC gate failed") {
		t.Errorf("ParseMCDC: Note should mention gate failure, got: %q", rep.Note)
	}
}

//fusa:test REQ-COV015
func TestParseMCDC_NoRecords(t *testing.T) {
	// Function exists but has no mcdc_records.
	input := `{"data":[{"functions":[{"name":"Baz","mcdc_records":[]}]}]}`
	rep, err := coverage.ParseMCDC([]byte(input), coverage.DALB, "test", 100)
	if err != nil {
		t.Fatalf("ParseMCDC: %v", err)
	}
	if !rep.Passed {
		t.Error("ParseMCDC: expected Passed=true when no records")
	}
	if rep.Note == "" {
		t.Error("ParseMCDC: Note should explain no records found")
	}
}

//fusa:test REQ-COV015
func TestMCDCCondition_IsCovered(t *testing.T) {
	tests := []struct {
		trueCount  int
		falseCount int
		want       bool
	}{
		{1, 1, true},
		{3, 2, true},
		{0, 5, false},
		{5, 0, false},
		{0, 0, false},
	}
	for _, tc := range tests {
		cond := coverage.MCDCCondition{CoveredTrueCount: tc.trueCount, CoveredFalseCount: tc.falseCount}
		if got := cond.IsCovered(); got != tc.want {
			t.Errorf("IsCovered(true=%d,false=%d) = %v, want %v",
				tc.trueCount, tc.falseCount, got, tc.want)
		}
	}
}

//fusa:test REQ-COV015
func TestParseMCDCFile_NotFound(t *testing.T) {
	_, err := coverage.ParseMCDCFile("/nonexistent/mcdc.json", coverage.DALA, 100)
	if err == nil {
		t.Error("expected error for missing file")
	}
}

//fusa:test REQ-COV015
func TestParseMCDCFile_ValidFile(t *testing.T) {
	content := `{"data":[{"functions":[{"name":"Qux","mcdc_records":[{"conditions":[{"covered_true_count":2,"covered_false_count":1}]}]}]}]}`
	path := filepath.Join(t.TempDir(), "mcdc.json")
	if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
	rep, err := coverage.ParseMCDCFile(path, coverage.DALA, 100)
	if err != nil {
		t.Fatalf("ParseMCDCFile: %v", err)
	}
	if !rep.Passed {
		t.Errorf("ParseMCDCFile: expected Passed=true, got false; note: %s", rep.Note)
	}
	if rep.SourceFile != path {
		t.Errorf("SourceFile = %q, want %q", rep.SourceFile, path)
	}
}

//fusa:test REQ-COV015
func TestParseMCDC_ThresholdPartialCoverage(t *testing.T) {
	// Two conditions: one covered, one not. Threshold=50 → should pass.
	input := `{"data":[{"functions":[{"name":"Multi","mcdc_records":[{"conditions":[{"covered_true_count":1,"covered_false_count":1},{"covered_true_count":0,"covered_false_count":1}]}]}]}]}`
	rep, err := coverage.ParseMCDC([]byte(input), coverage.DALA, "test", 50)
	if err != nil {
		t.Fatalf("ParseMCDC: %v", err)
	}
	if rep.CoveragePct != 50 {
		t.Errorf("CoveragePct = %.1f, want 50.0", rep.CoveragePct)
	}
	if !rep.Passed {
		t.Errorf("expected Passed=true at 50%% with threshold 50, note: %s", rep.Note)
	}
}

// TestRenderText_DAL_D exercises the req() helper's "no" branch: DAL-D has no
// required coverage metrics, so all req(false) calls return "no".
func TestRenderText_DALD_ReqHelperNoBranch(t *testing.T) {
	blocks := []coverage.Block{{File: "main.go", StartLine: 1, EndLine: 5, Stmts: 3, Count: 3}}
	rep := coverage.Analyse(blocks, coverage.DALD)
	var buf bytes.Buffer
	if err := coverage.Render(&buf, rep, "text"); err != nil {
		t.Fatalf("Render DAL-D: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "DAL-D") {
		t.Errorf("expected DAL-D in output; got: %s", out)
	}
	// DAL-D has no required metrics; "no" appears for statement and decision coverage.
	if !strings.Contains(out, "no") {
		t.Errorf("expected 'no' for non-required metrics at DAL-D; got: %s", out)
	}
}

//fusa:test REQ-COV015
func TestRenderText_MCDCReport(t *testing.T) {
	blocks := []coverage.Block{{File: "foo.go", StartLine: 1, EndLine: 10, Stmts: 5, Count: 5}}
	rep := coverage.Analyse(blocks, coverage.DALA)
	rep.MCDCReport = &coverage.MCDCReport{
		DAL:               coverage.DALA,
		Threshold:         100,
		TotalConditions:   2,
		CoveredConditions: 1,
		CoveragePct:       50,
		Passed:            false,
		Note:              "MC/DC gate failed: 50.0% covered (threshold 100%)",
	}
	var buf bytes.Buffer
	if err := coverage.Render(&buf, rep, "text"); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(buf.String(), "MC/DC coverage") {
		t.Error("text output should include MC/DC coverage line")
	}
	if !strings.Contains(buf.String(), "FAIL") {
		t.Error("text output should indicate FAIL for failed MC/DC gate")
	}
}
