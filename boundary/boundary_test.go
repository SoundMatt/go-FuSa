package boundary_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/boundary"
	"github.com/SoundMatt/go-FuSa/config"
	"github.com/SoundMatt/go-FuSa/engine"
	"github.com/SoundMatt/go-FuSa/testutil"
)

// ─── fixtures ─────────────────────────────────────────────────────────────────

const pkgA = `package pkga

import "github.com/example/test/pkgb"

// DoA is an exported function.
func DoA() { pkgb.DoB() }
`

const pkgB = `package pkgb

// DoB is an exported function.
func DoB() {}

// SomeType is an exported type.
type SomeType struct{}
`

func twoPackageProject() map[string]string {
	files := testutil.MinimalProject()
	files["pkga/a.go"] = pkgA
	files["pkgb/b.go"] = pkgB
	return files
}

// ─── Scan ─────────────────────────────────────────────────────────────────────

//fusa:test REQ-BOUNDARY001
func TestScan_BuildsPackageGraph(t *testing.T) {
	dir := testutil.ProjectDir(t, twoPackageProject())
	d, err := boundary.Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(d.Nodes) < 2 {
		t.Errorf("expected at least 2 nodes, got %d", len(d.Nodes))
	}
	if d.Module == "" {
		t.Error("Module should be set from go.mod")
	}
}

//fusa:test REQ-BOUNDARY001
func TestScan_BuildsEdges(t *testing.T) {
	dir := testutil.ProjectDir(t, twoPackageProject())
	d, err := boundary.Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(d.Edges) == 0 {
		t.Error("expected at least one edge (pkga -> pkgb)")
	}
}

//fusa:test REQ-BOUNDARY002
func TestScan_ExtractsExports(t *testing.T) {
	dir := testutil.ProjectDir(t, twoPackageProject())
	d, err := boundary.Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for _, n := range d.Nodes {
		if n.Package == "pkgb" {
			if len(n.Exports) == 0 {
				t.Error("pkgb: expected exports (DoB, SomeType)")
			}
			return
		}
	}
	t.Error("pkgb node not found")
}

func TestScan_EmptyProject(t *testing.T) {
	dir := testutil.ProjectDir(t, testutil.MinimalProject())
	d, err := boundary.Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	// go.mod only — no Go source files in dirs beyond root .github
	_ = d
}

func TestScan_SkipsVendor(t *testing.T) {
	files := twoPackageProject()
	files["vendor/ext/ext.go"] = `package ext

func VendorFunc() {}
`
	dir := testutil.ProjectDir(t, files)
	d, err := boundary.Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for _, n := range d.Nodes {
		if n.Package == "ext" || strings.Contains(n.ImportPath, "vendor") {
			t.Error("vendor directory should be skipped")
		}
	}
}

func TestScan_SkipsTestFiles(t *testing.T) {
	files := twoPackageProject()
	files["pkgb/b_test.go"] = `package pkgb_test

func TestOnly() {}
`
	dir := testutil.ProjectDir(t, files)
	d, err := boundary.Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for _, n := range d.Nodes {
		for _, exp := range n.Exports {
			if exp == "TestOnly()" {
				t.Error("exports from _test.go should be skipped")
			}
		}
	}
}

func TestScan_TrustLevel(t *testing.T) {
	dir := testutil.ProjectDir(t, twoPackageProject())
	d, err := boundary.Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for _, n := range d.Nodes {
		if n.TrustLevel != boundary.TrustInternal {
			t.Errorf("node %q: TrustLevel = %q, want internal", n.Package, n.TrustLevel)
		}
	}
}

func TestScan_NodeIDsUnique(t *testing.T) {
	dir := testutil.ProjectDir(t, twoPackageProject())
	d, err := boundary.Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	seen := make(map[string]bool)
	for _, n := range d.Nodes {
		if seen[n.ID] {
			t.Errorf("duplicate node ID: %q", n.ID)
		}
		seen[n.ID] = true
	}
}

// ─── Render ───────────────────────────────────────────────────────────────────

//fusa:test REQ-BOUNDARY003
func TestRender_Mermaid(t *testing.T) {
	dir := testutil.ProjectDir(t, twoPackageProject())
	d, err := boundary.Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	var buf bytes.Buffer
	if err := boundary.Render(&buf, d, "mermaid"); err != nil {
		t.Fatalf("Render mermaid: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "flowchart LR") {
		t.Error("Render mermaid: missing 'flowchart LR'")
	}
	if !strings.Contains(out, "-->") {
		t.Error("Render mermaid: missing edges (-->)")
	}
}

func TestRender_MermaidDefault(t *testing.T) {
	d := &boundary.Diagram{Module: "example"}
	var buf bytes.Buffer
	if err := boundary.Render(&buf, d, ""); err != nil {
		t.Fatalf("Render default: %v", err)
	}
	if !strings.Contains(buf.String(), "flowchart") {
		t.Error("Render default: expected mermaid output")
	}
}

//fusa:test REQ-BOUNDARY004
func TestRender_DOT(t *testing.T) {
	dir := testutil.ProjectDir(t, twoPackageProject())
	d, err := boundary.Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	var buf bytes.Buffer
	if err := boundary.Render(&buf, d, "dot"); err != nil {
		t.Fatalf("Render dot: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "digraph") {
		t.Error("Render dot: missing 'digraph'")
	}
	if !strings.Contains(out, "rankdir=LR") {
		t.Error("Render dot: missing 'rankdir=LR'")
	}
	if !strings.Contains(out, "->") {
		t.Error("Render dot: missing edges (->)")
	}
}

func TestRender_DOT_WellFormed(t *testing.T) {
	dir := testutil.ProjectDir(t, twoPackageProject())
	d, err := boundary.Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	var buf bytes.Buffer
	if err := boundary.Render(&buf, d, "dot"); err != nil {
		t.Fatalf("Render dot: %v", err)
	}
	out := buf.String()
	if !strings.HasSuffix(strings.TrimSpace(out), "}") {
		t.Error("Render dot: expected closing brace")
	}
}

func TestRender_UnknownFormat(t *testing.T) {
	d := &boundary.Diagram{}
	var buf bytes.Buffer
	if err := boundary.Render(&buf, d, "svg"); err == nil {
		t.Error("Render: expected error for unknown format")
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

//fusa:test REQ-BOUNDARY005
func TestBOUNDARY001_Absent(t *testing.T) {
	findings := runEngine(t, testutil.MinimalProject())
	if !hasRule(findings, "BOUNDARY001") {
		t.Error("BOUNDARY001: expected INFO finding when boundary.mermaid absent")
	}
}

func TestBOUNDARY001_Present(t *testing.T) {
	files := testutil.MinimalProject()
	files[boundary.BoundaryFile] = `flowchart LR`
	findings := runEngine(t, files)
	if hasRule(findings, "BOUNDARY001") {
		t.Error("BOUNDARY001: unexpected finding when boundary.mermaid present")
	}
}

func TestBOUNDARY001_Description(t *testing.T) {
	for _, r := range engine.Default.Rules() {
		if r.ID() == "BOUNDARY001" {
			if r.Description() == "" {
				t.Error("BOUNDARY001: empty description")
			}
			return
		}
	}
	t.Error("BOUNDARY001 not registered")
}

// ─── Fuzz ─────────────────────────────────────────────────────────────────────

func FuzzScan(f *testing.F) {
	f.Add("package mypkg\nimport \"fmt\"\nfunc Hello() { fmt.Println(\"hi\") }\n")
	f.Add("package bad {{{\n")
	f.Add("")
	f.Fuzz(func(t *testing.T, src string) {
		dir := t.TempDir()
		_, _ = boundary.Scan(dir) // must not panic on empty dir
		_ = src
	})
}
