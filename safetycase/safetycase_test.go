package safetycase_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/config"
	"github.com/SoundMatt/go-FuSa/engine"
	"github.com/SoundMatt/go-FuSa/safetycase"
	"github.com/SoundMatt/go-FuSa/testutil"
)

// ─── helpers ──────────────────────────────────────────────────────────────────

func fullEvidenceProject(t *testing.T) string {
	t.Helper()
	dir := testutil.ProjectDir(t, testutil.MinimalProject())

	// check-report.json
	checkJSON := `{"summary":{"total":3,"errors":0,"warnings":2,"infos":1},"findings":[]}`
	write(t, dir, "check-report.json", checkJSON)

	// .fusa-reqs.json
	reqsJSON := `{"requirements":[{"id":"REQ-001","title":"t1"},{"id":"REQ-002","title":"t2"}]}`
	write(t, dir, ".fusa-reqs.json", reqsJSON)

	// .fusa-evidence.json
	verifyJSON := `{"generatedAt":"2026-01-01T00:00:00Z","projectRoot":".","goVersion":"go1.22","results":[],"summary":{"total":10,"passed":10,"failed":0,"skipped":0}}`
	write(t, dir, ".fusa-evidence.json", verifyJSON)

	// qualify-report.json
	qualifyJSON := `{"total":44,"passed":44,"failed":0,"results":[],"hash":"x"}`
	write(t, dir, "qualify-report.json", qualifyJSON)

	// sbom.json + provenance.json
	write(t, dir, "sbom.json", `{"@context":"https://spdx.org/rdf/3.0.1/spdx-context.jsonld","@graph":[]}`)
	write(t, dir, "provenance.json", `{"format":"go-FuSa Provenance v1"}`)

	return dir
}

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

// ─── Build ────────────────────────────────────────────────────────────────────

//fusa:test REQ-SC001
func TestBuild_AllPresent(t *testing.T) {
	dir := fullEvidenceProject(t)
	sc, err := safetycase.Build(dir, "generic")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if sc.Module == "" {
		t.Error("Module should be set")
	}
	if sc.Standard != "generic" {
		t.Errorf("Standard = %q, want generic", sc.Standard)
	}
	if len(sc.Evidence) == 0 {
		t.Error("Evidence should not be empty")
	}
	for _, it := range sc.Evidence {
		if it.Status != safetycase.StatusPresent {
			t.Errorf("evidence %q: status = %q, want present", it.ID, it.Status)
		}
	}
}

//fusa:test REQ-SC002
func TestBuild_GapsWhenAbsent(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	sc, err := safetycase.Build(dir, "generic")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(sc.Gaps) == 0 {
		t.Error("expected gaps when no evidence files are present")
	}
	// All 6 evidence items should be absent
	if len(sc.Gaps) != 6 {
		t.Errorf("expected 6 gaps, got %d: %v", len(sc.Gaps), sc.Gaps)
	}
}

func TestBuild_DefaultStandard(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	sc, err := safetycase.Build(dir, "")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if sc.Standard != "generic" {
		t.Errorf("Standard = %q, want generic", sc.Standard)
	}
}

func TestBuild_Standards(t *testing.T) {
	for _, std := range []string{"iso26262", "iec61508", "iso21434", "generic"} {
		dir := testutil.ProjectDir(t, testutil.MinimalProject())
		sc, err := safetycase.Build(dir, std)
		if err != nil {
			t.Fatalf("Build(%s): %v", std, err)
		}
		if len(sc.Mappings) == 0 {
			t.Errorf("Build(%s): expected compliance mappings", std)
		}
	}
}

func TestBuild_CheckDetail(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	write(t, dir, "check-report.json", `{"summary":{"total":5,"errors":0,"warnings":3,"infos":2}}`)
	sc, err := safetycase.Build(dir, "generic")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	for _, it := range sc.Evidence {
		if it.ID == "check" {
			if it.Status != safetycase.StatusPresent {
				t.Error("check: expected present")
			}
			if !strings.Contains(it.Detail, "5 findings") {
				t.Errorf("check detail = %q, expected '5 findings'", it.Detail)
			}
			return
		}
	}
	t.Error("check evidence item not found")
}

func TestBuild_VerifyDetail(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	write(t, dir, ".fusa-evidence.json", `{"summary":{"total":20,"passed":18,"failed":2,"skipped":0}}`)
	sc, err := safetycase.Build(dir, "generic")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	for _, it := range sc.Evidence {
		if it.ID == "verify" {
			if !strings.Contains(it.Detail, "18/20") {
				t.Errorf("verify detail = %q, expected '18/20'", it.Detail)
			}
			return
		}
	}
	t.Error("verify evidence item not found")
}

func TestBuild_QualifyDetail(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	write(t, dir, "qualify-report.json", `{"total":44,"passed":44,"failed":0}`)
	sc, err := safetycase.Build(dir, "generic")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	for _, it := range sc.Evidence {
		if it.ID == "qualify" {
			if !strings.Contains(it.Detail, "44/44") {
				t.Errorf("qualify detail = %q, expected '44/44'", it.Detail)
			}
			return
		}
	}
	t.Error("qualify evidence item not found")
}

func TestBuild_TraceDetail(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	write(t, dir, ".fusa-reqs.json", `{"requirements":[{"id":"REQ-001"},{"id":"REQ-002"},{"id":"REQ-003"}]}`)
	sc, err := safetycase.Build(dir, "generic")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	for _, it := range sc.Evidence {
		if it.ID == "trace" {
			if !strings.Contains(it.Detail, "3 requirements") {
				t.Errorf("trace detail = %q, expected '3 requirements'", it.Detail)
			}
			return
		}
	}
	t.Error("trace evidence item not found")
}

// ─── Render ───────────────────────────────────────────────────────────────────

//fusa:test REQ-SC003
func TestRender_JSON(t *testing.T) {
	dir := fullEvidenceProject(t)
	sc, err := safetycase.Build(dir, "generic")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	var buf bytes.Buffer
	if err := safetycase.Render(&buf, sc, "json"); err != nil {
		t.Fatalf("Render json: %v", err)
	}
	var parsed safetycase.SafetyCase
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("Render json: invalid JSON: %v", err)
	}
	if len(parsed.Evidence) == 0 {
		t.Error("Render json: expected evidence items")
	}
}

func TestRender_JSONDefault(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	sc, err := safetycase.Build(dir, "generic")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	var buf bytes.Buffer
	if err := safetycase.Render(&buf, sc, ""); err != nil {
		t.Fatalf("Render default: %v", err)
	}
	if !strings.Contains(buf.String(), `"format"`) {
		t.Error("Render default: expected JSON output")
	}
}

func TestRender_Text(t *testing.T) {
	dir := fullEvidenceProject(t)
	sc, err := safetycase.Build(dir, "iec61508")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	var buf bytes.Buffer
	if err := safetycase.Render(&buf, sc, "text"); err != nil {
		t.Fatalf("Render text: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Safety Case") {
		t.Error("Render text: missing 'Safety Case'")
	}
	if !strings.Contains(out, "Compliance Mapping") {
		t.Error("Render text: missing 'Compliance Mapping'")
	}
	if !strings.Contains(out, "Sn1") {
		t.Error("Render text: missing 'Sn1' evidence node")
	}
}

func TestRender_Text_WithGaps(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	sc, err := safetycase.Build(dir, "generic")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	var buf bytes.Buffer
	if err := safetycase.Render(&buf, sc, "text"); err != nil {
		t.Fatalf("Render text: %v", err)
	}
	if !strings.Contains(buf.String(), "Gaps") {
		t.Error("Render text: expected Gaps section")
	}
}

//fusa:test REQ-SC004
func TestRender_Mermaid(t *testing.T) {
	dir := fullEvidenceProject(t)
	sc, err := safetycase.Build(dir, "generic")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	var buf bytes.Buffer
	if err := safetycase.Render(&buf, sc, "mermaid"); err != nil {
		t.Fatalf("Render mermaid: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "flowchart TD") {
		t.Error("Render mermaid: missing 'flowchart TD'")
	}
	if !strings.Contains(out, "G1") {
		t.Error("Render mermaid: missing G1 goal node")
	}
	if !strings.Contains(out, "S1") {
		t.Error("Render mermaid: missing S1 strategy node")
	}
	if !strings.Contains(out, "Sn1") {
		t.Error("Render mermaid: missing Sn1 solution node")
	}
	if !strings.Contains(out, "G1 --> S1") {
		t.Error("Render mermaid: missing G1->S1 edge")
	}
}

func TestRender_Mermaid_AbsentNodesStyled(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	sc, err := safetycase.Build(dir, "generic")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	var buf bytes.Buffer
	if err := safetycase.Render(&buf, sc, "mermaid"); err != nil {
		t.Fatalf("Render mermaid: %v", err)
	}
	if !strings.Contains(buf.String(), "fill:#fee2e2") {
		t.Error("Render mermaid: absent nodes should be styled red")
	}
}

func TestRender_UnknownFormat(t *testing.T) {
	sc := &safetycase.SafetyCase{}
	var buf bytes.Buffer
	if err := safetycase.Render(&buf, sc, "xml"); err == nil {
		t.Error("Render: expected error for unknown format")
	}
}

// ─── Compliance mappings ──────────────────────────────────────────────────────

//fusa:test REQ-SC005
func TestBuild_ISO26262Mappings(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	sc, err := safetycase.Build(dir, "iso26262")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	var hasQualify bool
	for _, m := range sc.Mappings {
		for _, id := range m.EvidenceIDs {
			if id == "qualify" {
				hasQualify = true
			}
		}
	}
	if !hasQualify {
		t.Error("ISO 26262 mapping should reference qualify evidence")
	}
}

func TestBuild_IEC61508Mappings(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	sc, err := safetycase.Build(dir, "iec61508")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(sc.Mappings) == 0 {
		t.Error("IEC 61508 should have compliance mappings")
	}
}

func TestBuild_ISO21434Mappings(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	sc, err := safetycase.Build(dir, "iso21434")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(sc.Mappings) == 0 {
		t.Error("ISO 21434 should have compliance mappings")
	}
}

// ─── Engine rule ──────────────────────────────────────────────────────────────

func runEngine(t *testing.T, files map[string]string) []fusa.Finding {
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

//fusa:test REQ-SAFETYCASE001
func TestSAFETYCASE001_Absent(t *testing.T) {
	findings := runEngine(t, testutil.MinimalProject())
	if !hasRule(findings, "SAFETYCASE001") {
		t.Error("SAFETYCASE001: expected INFO finding when safety-case.json absent")
	}
}

func TestSAFETYCASE001_Present(t *testing.T) {
	files := testutil.MinimalProject()
	files[safetycase.SafeCaseFile] = `{"format":"go-FuSa Safety Case v1"}`
	findings := runEngine(t, files)
	if hasRule(findings, "SAFETYCASE001") {
		t.Error("SAFETYCASE001: unexpected finding when safety-case.json present")
	}
}

func TestSAFETYCASE001_Description(t *testing.T) {
	for _, r := range engine.Default.Rules() {
		if r.ID() == "SAFETYCASE001" {
			if r.Description() == "" {
				t.Error("SAFETYCASE001: empty description")
			}
			return
		}
	}
	t.Error("SAFETYCASE001 not registered")
}

// ─── Fuzz ─────────────────────────────────────────────────────────────────────

func FuzzBuild(f *testing.F) {
	f.Add("generic")
	f.Add("iso26262")
	f.Add("iec61508")
	f.Add("iso21434")
	f.Add("")
	f.Add("unknown-standard")
	f.Fuzz(func(t *testing.T, standard string) {
		dir := t.TempDir()
		_, _ = safetycase.Build(dir, standard) // must not panic
	})
}
