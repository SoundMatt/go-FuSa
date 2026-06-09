package vuln_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/config"
	"github.com/SoundMatt/go-FuSa/engine"
	"github.com/SoundMatt/go-FuSa/testutil"
	"github.com/SoundMatt/go-FuSa/vuln"
)

// ─── mock OSV server ──────────────────────────────────────────────────────────

// newOSVServer returns a test server that mirrors real OSV querybatch responses.
// For each query entry it checks whether the module is in the given vuln map.
func newOSVServer(t *testing.T, vulnMap map[string][]struct{ ID, Summary string }) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Queries []struct {
				Version string `json:"version"`
				Package struct {
					Name string `json:"name"`
				} `json:"package"`
			} `json:"queries"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		type osvVuln struct {
			ID      string   `json:"id"`
			Summary string   `json:"summary,omitempty"`
			Aliases []string `json:"aliases,omitempty"`
		}
		type osvResult struct {
			Vulns []osvVuln `json:"vulns,omitempty"`
		}
		type osvResp struct {
			Results []osvResult `json:"results"`
		}

		resp := osvResp{}
		for _, q := range req.Queries {
			if hits, ok := vulnMap[q.Package.Name]; ok {
				var vs []osvVuln
				for _, h := range hits {
					vs = append(vs, osvVuln{ID: h.ID, Summary: h.Summary, Aliases: []string{"CVE-2024-9999"}})
				}
				resp.Results = append(resp.Results, osvResult{Vulns: vs})
			} else {
				resp.Results = append(resp.Results, osvResult{})
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

// ─── ParseGoMod ──────────────────────────────────────────────────────────────

//fusa:test REQ-VULN001
func TestParseGoMod_ParsesDeps(t *testing.T) {
	gomod := `module github.com/example/test

go 1.22

require (
	github.com/foo/bar v1.2.3
	golang.org/x/text v0.5.0 // indirect
)

require github.com/single/dep v0.1.0
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0o640); err != nil {
		t.Fatal(err)
	}
	deps, err := vuln.ParseGoMod(filepath.Join(dir, "go.mod"))
	if err != nil {
		t.Fatalf("ParseGoMod: %v", err)
	}
	if len(deps) != 3 {
		t.Errorf("expected 3 deps, got %d: %v", len(deps), deps)
	}
	found := false
	for _, d := range deps {
		if d.Module == "github.com/foo/bar" && d.Version == "v1.2.3" {
			found = true
		}
	}
	if !found {
		t.Error("expected github.com/foo/bar v1.2.3")
	}
}

func TestParseGoMod_MissingFile(t *testing.T) {
	deps, err := vuln.ParseGoMod("/nonexistent/go.mod")
	if err != nil {
		t.Fatalf("ParseGoMod missing file: expected nil error, got %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("ParseGoMod missing file: expected 0 deps, got %d", len(deps))
	}
}

func TestParseGoMod_NoDeps(t *testing.T) {
	gomod := "module github.com/example/test\n\ngo 1.22\n"
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0o640)
	deps, err := vuln.ParseGoMod(filepath.Join(dir, "go.mod"))
	if err != nil {
		t.Fatalf("ParseGoMod: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("expected 0 deps, got %d", len(deps))
	}
}

// ─── Scan ─────────────────────────────────────────────────────────────────────

//fusa:test REQ-VULN002
func TestScan_VulnerableModule(t *testing.T) {
	srv := newOSVServer(t, map[string][]struct{ ID, Summary string }{
		"github.com/foo/bar": {{"GO-2024-0001", "Arbitrary code execution"}},
	})
	defer srv.Close()

	files := testutil.MinimalProject()
	files["go.mod"] = "module github.com/example/test\n\ngo 1.22\n\nrequire github.com/foo/bar v1.2.3\n"
	dir := testutil.ProjectDir(t, files)

	r, err := vuln.ScanWithURL(dir, srv.URL)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(r.Findings) == 0 {
		t.Error("expected at least one vulnerability finding")
	}
	if r.Findings[0].ID != "GO-2024-0001" {
		t.Errorf("expected GO-2024-0001, got %q", r.Findings[0].ID)
	}
	if r.Scanned != 1 {
		t.Errorf("Scanned = %d, want 1", r.Scanned)
	}
}

//fusa:test REQ-VULN002
func TestScan_NoVulnerabilities(t *testing.T) {
	srv := newOSVServer(t, map[string][]struct{ ID, Summary string }{})
	defer srv.Close()

	files := testutil.MinimalProject()
	files["go.mod"] = "module github.com/example/test\n\ngo 1.22\n\nrequire github.com/safe/pkg v1.0.0\n"
	dir := testutil.ProjectDir(t, files)

	r, err := vuln.ScanWithURL(dir, srv.URL)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(r.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(r.Findings))
	}
}

//fusa:test REQ-VULN004
func TestScan_ServerError_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	// Must have at least one dep so the HTTP call is actually made.
	files := testutil.MinimalProject()
	files["go.mod"] = "module github.com/example/test\n\ngo 1.22\n\nrequire github.com/foo/bar v1.0.0\n"
	dir := testutil.ProjectDir(t, files)
	_, err := vuln.ScanWithURL(dir, srv.URL)
	if err == nil {
		t.Error("expected error for HTTP 500 response")
	}
}

func TestScan_NoDeps(t *testing.T) {
	srv := newOSVServer(t, map[string][]struct{ ID, Summary string }{})
	defer srv.Close()

	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	r, err := vuln.ScanWithURL(dir, srv.URL)
	if err != nil {
		t.Fatalf("Scan no deps: %v", err)
	}
	if len(r.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(r.Findings))
	}
}

func TestScan_ModuleNameSet(t *testing.T) {
	srv := newOSVServer(t, map[string][]struct{ ID, Summary string }{})
	defer srv.Close()

	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	r, err := vuln.ScanWithURL(dir, srv.URL)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if r.Module == "" {
		t.Error("Module should be set from go.mod")
	}
}

func TestScan_MultipleVulns(t *testing.T) {
	srv := newOSVServer(t, map[string][]struct{ ID, Summary string }{
		"github.com/foo/bar": {
			{"GO-2024-0001", "SQL injection"},
			{"GO-2024-0002", "XSS"},
		},
	})
	defer srv.Close()

	files := testutil.MinimalProject()
	files["go.mod"] = "module github.com/example/test\n\ngo 1.22\n\nrequire github.com/foo/bar v1.0.0\n"
	dir := testutil.ProjectDir(t, files)

	r, err := vuln.ScanWithURL(dir, srv.URL)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(r.Findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(r.Findings))
	}
}

func TestScan_AliasesPresent(t *testing.T) {
	srv := newOSVServer(t, map[string][]struct{ ID, Summary string }{
		"github.com/foo/bar": {{"GO-2024-0001", "Remote code execution"}},
	})
	defer srv.Close()

	files := testutil.MinimalProject()
	files["go.mod"] = "module github.com/example/test\n\ngo 1.22\n\nrequire github.com/foo/bar v1.0.0\n"
	dir := testutil.ProjectDir(t, files)

	r, err := vuln.ScanWithURL(dir, srv.URL)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(r.Findings) == 0 {
		t.Fatal("expected findings")
	}
	if len(r.Findings[0].Aliases) == 0 {
		t.Error("expected CVE aliases in finding")
	}
}

// ─── Render ───────────────────────────────────────────────────────────────────

//fusa:test REQ-VULN005
func TestRender_JSON(t *testing.T) {
	r := &vuln.Report{
		Format:  "go-FuSa Vulnerability Report v1",
		Module:  "github.com/example/test",
		Scanned: 5,
		Findings: []vuln.Finding{
			{Module: "github.com/foo/bar", Version: "v1.0.0", ID: "GO-2024-0001", Summary: "test"},
		},
	}
	var buf bytes.Buffer
	if err := vuln.Render(&buf, r, "json"); err != nil {
		t.Fatalf("Render json: %v", err)
	}
	var parsed vuln.Report
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("Render json: invalid JSON: %v", err)
	}
	if len(parsed.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(parsed.Findings))
	}
}

func TestRender_JSONDefault(t *testing.T) {
	r := &vuln.Report{Format: "go-FuSa Vulnerability Report v1"}
	var buf bytes.Buffer
	if err := vuln.Render(&buf, r, ""); err != nil {
		t.Fatalf("Render default: %v", err)
	}
	if !strings.Contains(buf.String(), `"format"`) {
		t.Error("Render default: expected JSON output")
	}
}

func TestRender_Text_NoVulns(t *testing.T) {
	r := &vuln.Report{Module: "github.com/example/test", Scanned: 3}
	var buf bytes.Buffer
	if err := vuln.Render(&buf, r, "text"); err != nil {
		t.Fatalf("Render text: %v", err)
	}
	if !strings.Contains(buf.String(), "No known vulnerabilities") {
		t.Error("expected 'No known vulnerabilities' in text output")
	}
}

func TestRender_Text_WithVulns(t *testing.T) {
	r := &vuln.Report{
		Module:  "github.com/example/test",
		Scanned: 3,
		Findings: []vuln.Finding{
			{Module: "github.com/foo/bar", Version: "v1.0.0", ID: "GO-2024-0001", Summary: "test vuln", Aliases: []string{"CVE-2024-1234"}},
		},
	}
	var buf bytes.Buffer
	if err := vuln.Render(&buf, r, "text"); err != nil {
		t.Fatalf("Render text: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "GO-2024-0001") {
		t.Error("expected GO-2024-0001 in text output")
	}
	if !strings.Contains(out, "CVE-2024-1234") {
		t.Error("expected CVE-2024-1234 alias in text output")
	}
}

func TestRender_UnknownFormat(t *testing.T) {
	r := &vuln.Report{}
	var buf bytes.Buffer
	if err := vuln.Render(&buf, r, "xml"); err == nil {
		t.Error("expected error for unknown format")
	}
}

// ─── engine rule ─────────────────────────────────────────────────────────────

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

//fusa:test REQ-VULN003
func TestVULN001_Absent(t *testing.T) {
	findings := runEngine(t, testutil.MinimalProject())
	if !hasRule(findings, "VULN001") {
		t.Error("VULN001: expected INFO finding when vuln.json absent")
	}
}

func TestVULN001_Present(t *testing.T) {
	files := testutil.MinimalProject()
	files[vuln.VulnFile] = `{"format":"go-FuSa Vulnerability Report v1","findings":[]}`
	findings := runEngine(t, files)
	if hasRule(findings, "VULN001") {
		t.Error("VULN001: unexpected finding when vuln.json present")
	}
}

func TestVULN001_Description(t *testing.T) {
	for _, r := range engine.Default.Rules() {
		if r.ID() == "VULN001" {
			if r.Description() == "" {
				t.Error("VULN001: empty description")
			}
			if !strings.Contains(r.Description(), "21434") {
				t.Error("VULN001: description should reference ISO 21434")
			}
			return
		}
	}
	t.Error("VULN001 not registered")
}

// ─── ScanWithGovulncheck ──────────────────────────────────────────────────────

//fusa:test REQ-VULN006
func TestScanWithGovulncheck_FallbackNoDeps(t *testing.T) {
	// With no deps, ScanWithGovulncheck falls back to Scan which returns early
	// without making network requests, regardless of govulncheck presence.
	files := testutil.MinimalProject()
	// go.mod with no dependencies
	files["go.mod"] = "module example.com/test\n\ngo 1.22\n"
	dir := testutil.ProjectDir(t, files)

	report, err := vuln.ScanWithGovulncheck(dir)
	if err != nil {
		t.Fatalf("ScanWithGovulncheck: %v", err)
	}
	if report == nil {
		t.Fatal("ScanWithGovulncheck: nil report")
	}
	// No deps → no findings.
	if len(report.Findings) != 0 {
		t.Errorf("ScanWithGovulncheck with no deps: want 0 findings, got %d", len(report.Findings))
	}
}

// ─── Fuzz ─────────────────────────────────────────────────────────────────────

func FuzzParseGoMod(f *testing.F) {
	f.Add("module foo\n\ngo 1.22\n\nrequire bar v1.0.0\n")
	f.Add("module foo\n\nrequire (\n  bar v1.0.0\n)\n")
	f.Add("")
	f.Add("not a valid go.mod")
	f.Fuzz(func(t *testing.T, content string) {
		dir := t.TempDir()
		path := filepath.Join(dir, "go.mod")
		_ = os.WriteFile(path, []byte(content), 0o640)
		_, _ = vuln.ParseGoMod(path) // must not panic
	})
}

// ─── runGovulncheck via fake binary ──────────────────────────────────────────

func TestRunGovulncheck_FakeBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake shell binary not supported on Windows")
	}
	// Create a fake govulncheck that emits one finding
	binDir := t.TempDir()
	script := `#!/bin/sh
echo '{"finding":{"osv":"GO-2024-0001","trace":[{"module":"github.com/example/dep","version":"v1.0.0","function":"main.Run"}],"fixed_version":"v1.0.1"}}'
`
	binPath := filepath.Join(binDir, "govulncheck")
	if err := os.WriteFile(binPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	// Prepend to PATH
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+origPath)

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/test\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	rep, err := vuln.ScanWithGovulncheck(dir)
	if err != nil {
		t.Fatalf("ScanWithGovulncheck: %v", err)
	}
	if len(rep.Findings) == 0 {
		t.Error("expected at least one finding from fake govulncheck")
	}
}
