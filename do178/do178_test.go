package do178_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/SoundMatt/go-FuSa/do178"
)

// negativeCount matches a negative integer preceded by a space, e.g. " -1",
// as would appear in a malformed "Summary: ... -1 GAP ..." line.
var negativeCount = regexp.MustCompile(` -\d`)

//fusa:test REQ-DO178-001
func TestAssess_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	rep, err := do178.Assess(dir, "myproject", do178.DALB)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if rep.Project != "myproject" {
		t.Errorf("Project = %q", rep.Project)
	}
	if rep.DAL != do178.DALB {
		t.Errorf("DAL = %v", rep.DAL)
	}
	if len(rep.Objectives) == 0 {
		t.Error("expected objectives")
	}
	// All DAL-B objectives with evidence files should be GAP in empty dir
	if rep.Gap == 0 {
		t.Error("expected some GAP objectives in empty dir")
	}
}

//fusa:test REQ-DO178-001
func TestAssess_WithEvidence(t *testing.T) {
	dir := t.TempDir()
	// Create evidence files to convert some GAPs to PASSes
	for _, f := range []string{"SAFETY_PLAN.md", "SVP.md", "SCMP.md", "SQAP.md", ".fusa-reqs.json"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o644); err != nil {
			t.Fatalf("write %s: %v", f, err)
		}
	}
	rep, err := do178.Assess(dir, "proj", do178.DALB)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if rep.Pass == 0 {
		t.Error("expected some PASS objectives with evidence files present")
	}
}

// Regression for #45: a freshly-scaffolded project (`gofusa template`
// defaults to docs/safety/) must not report the plan documents as gaps
// just because they aren't sitting at the project root, and the A-3.1
// "all 4 plans present" manual-review check must also find them there.
//
//fusa:test REQ-DO178-001
//fusa:test REQ-DOC001
func TestAssess_DocsSafetyScaffoldPath(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "docs", "safety"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	for _, f := range []string{"SAFETY_PLAN.md", "SVP.md", "SCMP.md", "SQAP.md"} {
		if err := os.WriteFile(filepath.Join(dir, "docs", "safety", f), []byte("x"), 0o644); err != nil {
			t.Fatalf("write %s: %v", f, err)
		}
	}
	rep, err := do178.Assess(dir, "proj", do178.DALB)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	for _, obj := range rep.Objectives {
		if obj.Gap != "" && (strings.Contains(obj.Gap, "SAFETY_PLAN.md") ||
			strings.Contains(obj.Gap, "SVP.md") || strings.Contains(obj.Gap, "SCMP.md") ||
			strings.Contains(obj.Gap, "SQAP.md")) {
			t.Errorf("plan doc under docs/safety/ still reported as gap: %s", obj.Gap)
		}
		if obj.ID == "A-3.1" && obj.Status != do178.StatusManual {
			t.Errorf("A-3.1 status = %v, want Manual (all 4 plans present under docs/safety/)", obj.Status)
		}
	}
}

//fusa:test REQ-DO178-001
func TestAssess_DALE_AllNA(t *testing.T) {
	dir := t.TempDir()
	rep, err := do178.Assess(dir, "proj", do178.DALE)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	// DAL-E means none of the standard objectives apply
	if rep.Gap > 0 {
		t.Errorf("DAL-E should have no GAPs, got %d", rep.Gap)
	}
}

//fusa:test REQ-DO178-001
func TestAssess_DALA_MCDCOBJ(t *testing.T) {
	dir := t.TempDir()
	rep, err := do178.Assess(dir, "proj", do178.DALA)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	// A-7.5 (MC/DC) should be MANUAL at DAL-A
	found := false
	for _, obj := range rep.Objectives {
		if obj.ID == "A-7.5" {
			if obj.Status != do178.StatusManual {
				t.Errorf("A-7.5 status = %v, want MANUAL", obj.Status)
			}
			found = true
		}
	}
	if !found {
		t.Error("A-7.5 objective not found at DAL-A")
	}
}

//fusa:test REQ-DO178-001
func TestObjectiveNotApply_DALE(t *testing.T) {
	dir := t.TempDir()
	rep, err := do178.Assess(dir, "proj", do178.DALE)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	for _, obj := range rep.Objectives {
		if obj.Status != do178.StatusNA {
			t.Errorf("DAL-E: objective %s has status %v, want N/A", obj.ID, obj.Status)
		}
	}
}

//fusa:test REQ-DO178-003
func TestRender_Text(t *testing.T) {
	dir := t.TempDir()
	rep, _ := do178.Assess(dir, "proj", do178.DALB)
	var buf bytes.Buffer
	if err := do178.Render(&buf, rep, "text"); err != nil {
		t.Fatalf("Render text: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "DO-178C Gap Report") {
		t.Error("missing report header")
	}
	if !strings.Contains(out, "DAL-B") {
		t.Error("missing DAL in text output")
	}
}

//fusa:test REQ-DO178-003
func TestRender_JSON(t *testing.T) {
	dir := t.TempDir()
	rep, _ := do178.Assess(dir, "proj", do178.DALB)
	var buf bytes.Buffer
	if err := do178.Render(&buf, rep, "json"); err != nil {
		t.Fatalf("Render json: %v", err)
	}
	if !strings.Contains(buf.String(), `"standard"`) {
		t.Error("missing standard field in JSON")
	}
	// §2.4.1: standard MUST be the canonical lowercase id, never a display
	// string like "DO-178C DAL-B".
	var doc map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("JSON parse: %v", err)
	}
	if doc["standard"] != "do178c" {
		t.Errorf("standard = %v, want canonical id \"do178c\"", doc["standard"])
	}
}

//fusa:test REQ-DO178-003
func TestRender_InvalidFormat(t *testing.T) {
	rep := &do178.Report{}
	if err := do178.Render(&bytes.Buffer{}, rep, "html"); err == nil {
		t.Error("expected error for unsupported format")
	}
}

//fusa:test REQ-DO178-002
func TestDALConstants(t *testing.T) {
	if do178.DALA != "DAL-A" {
		t.Errorf("DALA = %q", do178.DALA)
	}
	if do178.DALE != "DAL-E" {
		t.Errorf("DALE = %q", do178.DALE)
	}
}

//fusa:test REQ-DO178-002
func TestStatusConstants(t *testing.T) {
	if do178.StatusPass != "PASS" {
		t.Errorf("StatusPass = %q", do178.StatusPass)
	}
	if do178.StatusGap != "GAP" {
		t.Errorf("StatusGap = %q", do178.StatusGap)
	}
	if do178.StatusManual != "MANUAL" {
		t.Errorf("StatusManual = %q", do178.StatusManual)
	}
	if do178.StatusNA != "N/A" {
		t.Errorf("StatusNA = %q", do178.StatusNA)
	}
}

//fusa:test REQ-DO178-001
func TestGapIncludes_SBOMFile(t *testing.T) {
	dir := t.TempDir()
	rep, _ := do178.Assess(dir, "proj", do178.DALB)
	// A-10.1 requires sbom.json, which won't exist in temp dir
	for _, obj := range rep.Objectives {
		if obj.ID == "A-10.1" {
			if obj.Status != do178.StatusGap {
				t.Errorf("A-10.1 should be GAP without sbom.json, got %v", obj.Status)
			}
			if !strings.Contains(obj.Gap, "sbom.json") {
				t.Errorf("A-10.1 gap message missing sbom.json: %q", obj.Gap)
			}
			return
		}
	}
	t.Error("A-10.1 not found in objectives")
}

//fusa:test REQ-DO178-001
func TestNestedFile_CI(t *testing.T) {
	dir := t.TempDir()
	// Create nested .github/workflows/ci.yml
	wfDir := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wfDir, "ci.yml"), []byte("ci"), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, _ := do178.Assess(dir, "proj", do178.DALB)
	for _, obj := range rep.Objectives {
		if obj.ID == "A-9.2" {
			if obj.Status != do178.StatusPass {
				t.Errorf("A-9.2 should be PASS with ci.yml present, got %v", obj.Status)
			}
			return
		}
	}
	t.Error("A-9.2 not found")
}

// ─── v0.22 objective changes ──────────────────────────────────────────────────

func writeReqsJSON(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, ".fusa-reqs.json"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func objectiveStatus(t *testing.T, rep *do178.Report, id string) do178.ObjectiveStatus {
	t.Helper()
	for _, obj := range rep.Objectives {
		if obj.ID == id {
			return obj.Status
		}
	}
	t.Fatalf("objective %s not found", id)
	return ""
}

func TestA22_GAP_WhenNoReqsFile(t *testing.T) {
	dir := t.TempDir()
	rep, err := do178.Assess(dir, "proj", do178.DALB)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if s := objectiveStatus(t, rep, "A-2.2"); s != do178.StatusGap {
		t.Errorf("A-2.2 without reqs file should be GAP, got %v", s)
	}
}

func TestA22_GAP_WhenNoLLRItems(t *testing.T) {
	dir := t.TempDir()
	writeReqsJSON(t, dir, `{"requirements":[{"id":"REQ-001","title":"HLR only","level":"HLR"}]}`)
	rep, err := do178.Assess(dir, "proj", do178.DALB)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if s := objectiveStatus(t, rep, "A-2.2"); s != do178.StatusGap {
		t.Errorf("A-2.2 with no LLR items should be GAP, got %v", s)
	}
}

func TestA22_PASS_WhenLLRItemPresent(t *testing.T) {
	dir := t.TempDir()
	writeReqsJSON(t, dir, `{"requirements":[{"id":"REQ-001","title":"LLR req","level":"LLR"}]}`)
	rep, err := do178.Assess(dir, "proj", do178.DALA)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if s := objectiveStatus(t, rep, "A-2.2"); s != do178.StatusPass {
		t.Errorf("A-2.2 with LLR item should PASS, got %v", s)
	}
}

func TestA63_GAP_WhenNoCouplingReport(t *testing.T) {
	dir := t.TempDir()
	rep, err := do178.Assess(dir, "proj", do178.DALA)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if s := objectiveStatus(t, rep, "A-6.3"); s != do178.StatusGap {
		t.Errorf("A-6.3 without coupling-report.json should be GAP, got %v", s)
	}
}

func TestA63_PASS_WhenCouplingReportPresent(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "coupling-report.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := do178.Assess(dir, "proj", do178.DALA)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if s := objectiveStatus(t, rep, "A-6.3"); s != do178.StatusPass {
		t.Errorf("A-6.3 with coupling-report.json should PASS, got %v", s)
	}
}

func TestA62_GAP_WhenNoCheckReport(t *testing.T) {
	dir := t.TempDir()
	rep, err := do178.Assess(dir, "proj", do178.DALA)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if s := objectiveStatus(t, rep, "A-6.2"); s != do178.StatusGap {
		t.Errorf("A-6.2 without check-report.json should be GAP, got %v", s)
	}
}

// Regression for #86: gofusa do178's text-mode summary line printed a
// nonsensical negative GAP count on projects where both the A-2.4
// (.fusa.json present) and A-3.1 (all 4 plan docs present) refinements in
// checkSourceCode fired. Those objectives are already assessed as
// StatusManual — and counted in rep.Manual — by Assess itself (their
// allObjectives entry has an empty evidence file); checkSourceCode used to
// also bump rep.Manual and (for A-2.4) unconditionally decrement rep.Gap,
// double-counting Manual and driving Gap negative. The counters must match
// what's actually enumerated in rep.Objectives, and Gap must never go
// negative.
//
//fusa:test REQ-DO178-001
//fusa:test REQ-DO178-003
func TestSummaryCounters_MatchObjectives_Issue86(t *testing.T) {
	dir := t.TempDir()
	// Trigger the A-2.4 refinement: .fusa.json present.
	if err := os.WriteFile(filepath.Join(dir, ".fusa.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Trigger the A-3.1 refinement: all 4 plan docs present.
	for _, f := range []string{"SAFETY_PLAN.md", "SVP.md", "SCMP.md", "SQAP.md"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o644); err != nil {
			t.Fatalf("write %s: %v", f, err)
		}
	}

	rep, err := do178.Assess(dir, "proj", do178.DALB)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}

	var wantPass, wantFail, wantGap, wantManual, wantNA int
	for _, obj := range rep.Objectives {
		switch obj.Status {
		case do178.StatusPass:
			wantPass++
		case do178.StatusFail:
			wantFail++
		case do178.StatusGap:
			wantGap++
		case do178.StatusManual:
			wantManual++
		case do178.StatusNA:
			wantNA++
		}
	}

	if rep.Gap < 0 {
		t.Errorf("rep.Gap = %d, must never be negative", rep.Gap)
	}
	if rep.Pass != wantPass || rep.Fail != wantFail || rep.Gap != wantGap ||
		rep.Manual != wantManual || rep.NA != wantNA {
		t.Errorf("summary counters (pass=%d fail=%d gap=%d manual=%d na=%d) "+
			"don't match enumerated objectives (pass=%d fail=%d gap=%d manual=%d na=%d)",
			rep.Pass, rep.Fail, rep.Gap, rep.Manual, rep.NA,
			wantPass, wantFail, wantGap, wantManual, wantNA)
	}

	// The text renderer's header line must agree with these same counters
	// (and, transitively, with what it enumerates below the header).
	var buf bytes.Buffer
	if err := do178.Render(&buf, rep, "text"); err != nil {
		t.Fatalf("Render text: %v", err)
	}
	out := buf.String()
	var summaryLine string
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "Summary:") {
			summaryLine = line
			break
		}
	}
	if summaryLine == "" {
		t.Fatal("no Summary: line found in text output")
	}
	if negativeCount.MatchString(summaryLine) {
		t.Errorf("text summary line contains a negative count: %q", summaryLine)
	}
	gotGap := strings.Count(out, "] GAP ")
	if gotGap != rep.Gap {
		t.Errorf("text output enumerates %d GAP lines but summary says rep.Gap=%d", gotGap, rep.Gap)
	}
	gotManual := strings.Count(out, "] MANUAL ")
	if gotManual != rep.Manual {
		t.Errorf("text output enumerates %d MANUAL lines but summary says rep.Manual=%d", gotManual, rep.Manual)
	}
}

// Regression for #86, exact repro: with every applicable file-based
// objective satisfied at DAL-D (so the true GAP count is 0), the buggy
// checkSourceCode fixup for A-2.4 alone drove rep.Gap to -1, matching the
// "-1 GAP" reported against go-LIN. Fixed code must report exactly 0 GAP.
//
//fusa:test REQ-DO178-001
//fusa:test REQ-DO178-003
func TestSummary_NoNegativeGap_AllEvidencePresent_Issue86(t *testing.T) {
	dir := t.TempDir()
	// .fusa.json triggers the A-2.4 refinement.
	if err := os.WriteFile(filepath.Join(dir, ".fusa.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Every file-based-evidence objective applicable at DAL-D, satisfied —
	// so the real GAP count is zero.
	wfDir := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"SAFETY_PLAN.md":      "x",
		"SVP.md":              "x",
		"SCMP.md":             "x",
		"SQAP.md":             "x",
		".fusa-reqs.json":     `{"requirements":[]}`,
		"boundary.mermaid":    "graph TD",
		"provenance.json":     "{}",
		".fusa-evidence.json": "{}",
		"sbom.json":           "{}",
		"sci.json":            "{}",
		".fusa-problems.json": "{}",
		"sas.md":              "x",
	}
	for f, content := range files {
		if err := os.WriteFile(filepath.Join(dir, f), []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", f, err)
		}
	}
	if err := os.WriteFile(filepath.Join(wfDir, "ci.yml"), []byte("ci"), 0o644); err != nil {
		t.Fatal(err)
	}

	rep, err := do178.Assess(dir, "proj", do178.DALD)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}

	var actualGaps []string
	for _, obj := range rep.Objectives {
		if obj.Status == do178.StatusGap {
			actualGaps = append(actualGaps, obj.ID)
		}
	}
	if len(actualGaps) != 0 {
		t.Fatalf("expected zero real GAP objectives with all evidence present, got %v", actualGaps)
	}
	if rep.Gap != 0 {
		t.Errorf("rep.Gap = %d, want 0 (must never be negative, and must match the zero GAP objectives enumerated)", rep.Gap)
	}

	var buf bytes.Buffer
	if err := do178.Render(&buf, rep, "text"); err != nil {
		t.Fatalf("Render text: %v", err)
	}
	if !strings.Contains(buf.String(), "0 GAP") {
		t.Errorf("expected summary line to report 0 GAP, got:\n%s", strings.SplitN(buf.String(), "\n\n", 2)[0])
	}
}

//fusa:test REQ-DO178-001
func TestA62_PASS_WhenCheckReportPresent(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "check-report.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := do178.Assess(dir, "proj", do178.DALA)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if s := objectiveStatus(t, rep, "A-6.2"); s != do178.StatusPass {
		t.Errorf("A-6.2 with check-report.json should PASS, got %v", s)
	}
}
