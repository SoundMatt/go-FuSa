// Package boundary derives component boundary diagrams from Go package
// structure (v0.12).
//
// Scan walks a project root, parses import relationships and exported
// declarations using go/ast, and returns a [Diagram] describing the
// package dependency graph within the module.
//
// Render writes the resulting [Diagram] in "mermaid" (default) or "dot"
// (Graphviz) format to any [io.Writer].
//
// Activate the engine rule by importing this package for its side effects:
//
//	import _ "github.com/SoundMatt/go-FuSa/boundary"
package boundary

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/config"
	"github.com/SoundMatt/go-FuSa/engine"
)

// BoundaryFile and BoundaryDOTFile are the default output filenames.
const (
	BoundaryFile    = "boundary.mermaid"
	BoundaryDOTFile = "boundary.dot"
)

// TrustLevel classifies a package as internal (within the module) or external.
type TrustLevel string

const (
	TrustInternal TrustLevel = "internal"
	TrustExternal TrustLevel = "external"
)

// Node represents a Go package in the boundary diagram.
//
//fusa:req REQ-BOUNDARY001
type Node struct {
	ID         string     `json:"id"`          // sanitised node identifier
	Package    string     `json:"package"`     // last path segment (package name)
	ImportPath string     `json:"import_path"` // full module-relative import path
	TrustLevel TrustLevel `json:"trust_level"`
	Exports    []string   `json:"exports,omitempty"` // exported type and func names
}

// Edge represents an import relationship between two packages.
//
//fusa:req REQ-BOUNDARY001
type Edge struct {
	From string `json:"from"` // node ID of importing package
	To   string `json:"to"`   // node ID of imported package
}

// Diagram is the complete boundary diagram for a project.
type Diagram struct {
	Format      string    `json:"format"`
	GeneratedAt time.Time `json:"generated_at"`
	Module      string    `json:"module"`
	Nodes       []Node    `json:"nodes"`
	Edges       []Edge    `json:"edges"`
}

// Scan walks projectRoot, parses package structure and imports, and returns a
// boundary diagram. Only packages within the module are included as nodes;
// external imports are referenced only if they appear as edge targets.
// Vendor, testdata, and hidden directories are skipped.
//
//fusa:req REQ-BOUNDARY001
//fusa:req REQ-BOUNDARY002
func Scan(projectRoot string) (*Diagram, error) {
	module := readModule(projectRoot)
	diagram := &Diagram{
		Format:      "go-FuSa Boundary v1",
		GeneratedAt: time.Now().UTC(),
		Module:      module,
	}

	pkgs := make(map[string]*pkgInfo) // keyed by import path

	err := filepath.WalkDir(projectRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		base := d.Name()
		if base == "vendor" || base == "testdata" || (base != "." && strings.HasPrefix(base, ".")) {
			return filepath.SkipDir
		}

		info, scanErr := scanPkg(path, projectRoot, module)
		if scanErr != nil || info == nil {
			return nil
		}
		pkgs[info.node.ImportPath] = info
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("boundary: scan %s: %w", projectRoot, err)
	}

	// Build nodes sorted by import path
	nodeIDs := make(map[string]string) // import path → node ID
	var nodePaths []string
	for ip := range pkgs {
		nodePaths = append(nodePaths, ip)
	}
	sort.Strings(nodePaths)

	for _, ip := range nodePaths {
		info := pkgs[ip]
		nodeIDs[ip] = info.node.ID
		diagram.Nodes = append(diagram.Nodes, info.node)
	}

	// Build edges (only between module-internal packages)
	edgeSet := make(map[string]bool)
	for _, ip := range nodePaths {
		info := pkgs[ip]
		fromID := nodeIDs[ip]
		for _, imp := range info.imports {
			toID, ok := nodeIDs[imp]
			if !ok {
				continue // external or stdlib
			}
			key := fromID + "->" + toID
			if edgeSet[key] {
				continue
			}
			edgeSet[key] = true
			diagram.Edges = append(diagram.Edges, Edge{From: fromID, To: toID})
		}
	}

	// Sort edges for deterministic output
	sort.Slice(diagram.Edges, func(i, j int) bool {
		if diagram.Edges[i].From != diagram.Edges[j].From {
			return diagram.Edges[i].From < diagram.Edges[j].From
		}
		return diagram.Edges[i].To < diagram.Edges[j].To
	})

	return diagram, nil
}

type pkgInfo struct {
	node    Node
	imports []string
}

func scanPkg(dir, projectRoot, module string) (*pkgInfo, error) {
	infos, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var goFiles []string
	for _, info := range infos {
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".go") && !strings.HasSuffix(info.Name(), "_test.go") {
			goFiles = append(goFiles, filepath.Join(dir, info.Name()))
		}
	}
	if len(goFiles) == 0 {
		return nil, nil
	}

	importPath := packageImportPath(dir, projectRoot, module)
	nodeID := sanitizeID(importPath)

	var pkgName string
	var allImports []string
	var exports []string
	importSet := make(map[string]bool)

	for _, path := range goFiles {
		fset := token.NewFileSet()
		f, parseErr := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if parseErr != nil {
			continue
		}
		if pkgName == "" {
			pkgName = f.Name.Name
		}
		for _, imp := range f.Imports {
			ip := strings.Trim(imp.Path.Value, `"`)
			if !importSet[ip] {
				importSet[ip] = true
				allImports = append(allImports, ip)
			}
		}
		exports = append(exports, collectExports(f)...)
	}
	if pkgName == "" {
		return nil, nil
	}

	sort.Strings(allImports)
	sort.Strings(exports)
	// Deduplicate exports across files
	exports = dedupe(exports)

	pkgDisplay := pkgName
	if pkgName == "main" {
		pkgDisplay = importPath
	}

	return &pkgInfo{
		node: Node{
			ID:         nodeID,
			Package:    pkgDisplay,
			ImportPath: importPath,
			TrustLevel: TrustInternal,
			Exports:    exports,
		},
		imports: allImports,
	}, nil
}

func collectExports(f *ast.File) []string {
	var names []string
	for _, decl := range f.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			if d.Name.IsExported() {
				names = append(names, d.Name.Name+"()")
			}
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				switch s := spec.(type) {
				case *ast.TypeSpec:
					if s.Name.IsExported() {
						names = append(names, s.Name.Name)
					}
				case *ast.ValueSpec:
					for _, n := range s.Names {
						if n.IsExported() {
							names = append(names, n.Name)
						}
					}
				}
			}
		}
	}
	return names
}

// Render writes d to w in the given format: "mermaid" (default) or "dot".
//
//fusa:req REQ-BOUNDARY003
//fusa:req REQ-BOUNDARY004
func Render(w io.Writer, d *Diagram, format string) error {
	switch format {
	case "mermaid", "":
		return renderMermaid(w, d)
	case "dot":
		return renderDOT(w, d)
	default:
		return fmt.Errorf("boundary: unknown format %q (want mermaid or dot)", format)
	}
}

func renderMermaid(w io.Writer, d *Diagram) error {
	fmt.Fprintf(w, "%%{init: {\"theme\": \"default\"}}%%\n")
	fmt.Fprintf(w, "flowchart LR\n")
	fmt.Fprintf(w, "    %% Module: %s\n", d.Module)
	fmt.Fprintf(w, "    %% Generated: %s\n\n", d.GeneratedAt.Format(time.RFC3339))

	for _, n := range d.Nodes {
		fmt.Fprintf(w, "    %s[\"%s\"]\n", n.ID, n.Package)
	}
	if len(d.Nodes) > 0 && len(d.Edges) > 0 {
		fmt.Fprintf(w, "\n")
	}
	for _, e := range d.Edges {
		fmt.Fprintf(w, "    %s --> %s\n", e.From, e.To)
	}
	return nil
}

func renderDOT(w io.Writer, d *Diagram) error {
	fmt.Fprintf(w, "// Module: %s\n", d.Module)
	fmt.Fprintf(w, "// Generated: %s\n", d.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(w, "digraph {\n")
	fmt.Fprintf(w, "    rankdir=LR\n")
	fmt.Fprintf(w, "    node [shape=box style=rounded fontname=Helvetica]\n\n")
	for _, n := range d.Nodes {
		fmt.Fprintf(w, "    %q [label=%q]\n", n.ID, n.Package)
	}
	if len(d.Nodes) > 0 && len(d.Edges) > 0 {
		fmt.Fprintf(w, "\n")
	}
	for _, e := range d.Edges {
		fmt.Fprintf(w, "    %q -> %q\n", e.From, e.To)
	}
	fmt.Fprintf(w, "}\n")
	return nil
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func packageImportPath(dir, projectRoot, module string) string {
	rel, err := filepath.Rel(projectRoot, dir)
	if err != nil || rel == "." {
		return module
	}
	// Convert OS path separators to forward slashes
	rel = filepath.ToSlash(rel)
	if module == "" {
		return rel
	}
	return module + "/" + rel
}

func sanitizeID(importPath string) string {
	r := strings.NewReplacer("/", "_", "-", "_", ".", "_")
	id := r.Replace(importPath)
	// Strip the module prefix from the ID to keep it short
	return id
}

func readModule(root string) string {
	data, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "module "))
		}
	}
	return ""
}

func dedupe(s []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// ─── engine rule ─────────────────────────────────────────────────────────────

func init() {
	engine.Default.MustRegister(&boundary001Rule{})
}

type boundary001Rule struct{}

func (r *boundary001Rule) ID() string { return "BOUNDARY001" }
func (r *boundary001Rule) Description() string {
	return "boundary.mermaid absent — run 'gofusa boundary' to generate a component boundary diagram"
}

//fusa:req REQ-BOUNDARY005
func (r *boundary001Rule) Run(_ context.Context, projectRoot string, cfg *config.Config) ([]fusa.Finding, error) {
	if _, err := os.Stat(filepath.Join(projectRoot, BoundaryFile)); err == nil {
		return nil, nil
	}
	return []fusa.Finding{{
		RuleID:      "BOUNDARY001",
		Severity:    fusa.SeverityInfo,
		Message:     "boundary.mermaid not found — run 'gofusa boundary' to generate the component boundary diagram",
		Location:    fusa.Location{File: BoundaryFile},
		Remediation: "Run: gofusa boundary",
	}}, nil
}
