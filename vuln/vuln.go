// Package vuln scans a Go project's dependencies for known vulnerabilities
// using the OSV (Open Source Vulnerabilities) database (v0.13).
// v0.15 adds ScanWithGovulncheck which uses call-graph analysis when
// govulncheck is available, reducing false positives significantly.
//
// Scan reads go.mod, posts a batch query to api.osv.dev, and returns a
// [Report] with one [Finding] per vulnerable (module, version) pair.
//
// Render writes the Report in "json" or "text" format.
//
// Activate the engine rule by importing this package for its side effects:
//
//	import _ "github.com/SoundMatt/go-FuSa/vuln"
package vuln

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/config"
	"github.com/SoundMatt/go-FuSa/engine"
)

// VulnFile is the default output filename.
const VulnFile = "vuln.json"

// DefaultDBURL is the OSV batch-query endpoint.
const DefaultDBURL = "https://api.osv.dev/v1/querybatch"

// Finding is a single vulnerability match for a module dependency.
//
//fusa:req REQ-VULN003
type Finding struct {
	Module    string   `json:"module"`
	Version   string   `json:"version"`
	ID        string   `json:"id"`                // GO-XXXX-YYYY or GHSA-…
	Aliases   []string `json:"aliases,omitempty"` // CVE-…
	Summary   string   `json:"summary,omitempty"`
	CallGraph []string `json:"call_graph,omitempty"` // populated by govulncheck; shows reachable call path
}

// Report is the complete vulnerability scan result for a project.
type Report struct {
	Format      string    `json:"format"`
	GeneratedAt time.Time `json:"generated_at"`
	Module      string    `json:"module"`
	Scanned     int       `json:"scanned"`
	Findings    []Finding `json:"findings"`
}

// Dep is a (module, version) pair parsed from go.mod.
type Dep struct {
	Module  string
	Version string
}

// Scan reads go.mod from projectRoot, queries DefaultDBURL, and returns a Report.
// If the database is unreachable an error is returned; callers should handle
// it gracefully (e.g. warn and continue).
//
//fusa:req REQ-VULN001
//fusa:req REQ-VULN002
func Scan(projectRoot string) (*Report, error) {
	return ScanWithURL(projectRoot, DefaultDBURL)
}

// ScanWithURL is like Scan but uses a custom database URL (useful for tests).
//
//fusa:req REQ-VULN004
func ScanWithURL(projectRoot, dbURL string) (*Report, error) {
	module := readModule(projectRoot)
	deps, err := ParseGoMod(filepath.Join(projectRoot, "go.mod"))
	if err != nil {
		return nil, fmt.Errorf("vuln: parse go.mod: %w", err)
	}

	report := &Report{
		Format:      "go-FuSa Vulnerability Report v1",
		GeneratedAt: time.Now().UTC(),
		Module:      module,
		Scanned:     len(deps),
	}

	if len(deps) == 0 {
		return report, nil
	}

	findings, err := queryOSV(deps, dbURL)
	if err != nil {
		return nil, fmt.Errorf("vuln: query OSV: %w", err)
	}
	report.Findings = findings
	return report, nil
}

// ParseGoMod extracts (module, version) pairs from a go.mod file.
//
//fusa:req REQ-VULN001
func ParseGoMod(path string) ([]Dep, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var deps []Dep
	seen := make(map[string]bool)
	inRequire := false

	for _, rawLine := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(rawLine)

		// Strip inline comments
		if idx := strings.Index(line, "//"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}

		if line == "require (" {
			inRequire = true
			continue
		}
		if inRequire && line == ")" {
			inRequire = false
			continue
		}

		var module, version string
		if inRequire {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				module, version = parts[0], parts[1]
			}
		} else if strings.HasPrefix(line, "require ") {
			parts := strings.Fields(strings.TrimPrefix(line, "require "))
			if len(parts) >= 2 {
				module, version = parts[0], parts[1]
			}
		}

		if module != "" && version != "" && !seen[module] {
			seen[module] = true
			deps = append(deps, Dep{Module: module, Version: version})
		}
	}

	sort.Slice(deps, func(i, j int) bool { return deps[i].Module < deps[j].Module })
	return deps, nil
}

// Render writes r to w in the given format: "json" (default) or "text".
//
//fusa:req REQ-VULN005
func Render(w io.Writer, r *Report, format string) error {
	switch format {
	case "json", "":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	case "text":
		return renderText(w, r)
	default:
		return fmt.Errorf("vuln: unknown format %q (want json or text)", format)
	}
}

func renderText(w io.Writer, r *Report) error {
	fmt.Fprintf(w, "Vulnerability Report — %s\n", r.Module)
	fmt.Fprintf(w, "Generated: %s\n", r.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(w, "Scanned:   %d dependencies\n\n", r.Scanned)

	if len(r.Findings) == 0 {
		fmt.Fprintf(w, "No known vulnerabilities found.\n")
		return nil
	}

	fmt.Fprintf(w, "%d vulnerability finding(s):\n\n", len(r.Findings))
	for _, f := range r.Findings {
		aliases := ""
		if len(f.Aliases) > 0 {
			aliases = " (" + strings.Join(f.Aliases, ", ") + ")"
		}
		fmt.Fprintf(w, "  [%s]%s\n    Module:  %s@%s\n", f.ID, aliases, f.Module, f.Version)
		if f.Summary != "" {
			fmt.Fprintf(w, "    Summary: %s\n", f.Summary)
		}
		fmt.Fprintf(w, "\n")
	}
	return nil
}

// ─── OSV query ───────────────────────────────────────────────────────────────

type osvQuery struct {
	Queries []osvQueryEntry `json:"queries"`
}

type osvQueryEntry struct {
	Version string     `json:"version"`
	Package osvPackage `json:"package"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvBatchResponse struct {
	Results []osvQueryResult `json:"results"`
}

type osvQueryResult struct {
	Vulns []osvVuln `json:"vulns,omitempty"`
}

type osvVuln struct {
	ID      string   `json:"id"`
	Summary string   `json:"summary,omitempty"`
	Aliases []string `json:"aliases,omitempty"`
}

func queryOSV(deps []Dep, dbURL string) ([]Finding, error) {
	q := osvQuery{}
	for _, d := range deps {
		q.Queries = append(q.Queries, osvQueryEntry{
			Version: d.Version,
			Package: osvPackage{Name: d.Module, Ecosystem: "Go"},
		})
	}

	body, err := json.Marshal(q)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Post(dbURL, "application/json", bytes.NewReader(body)) //nolint:noctx
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV returned HTTP %d", resp.StatusCode)
	}

	var result osvBatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	var findings []Finding
	for i, r := range result.Results {
		if i >= len(deps) {
			break
		}
		for _, v := range r.Vulns {
			findings = append(findings, Finding{
				Module:  deps[i].Module,
				Version: deps[i].Version,
				ID:      v.ID,
				Aliases: v.Aliases,
				Summary: v.Summary,
			})
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Module != findings[j].Module {
			return findings[i].Module < findings[j].Module
		}
		return findings[i].ID < findings[j].ID
	})

	return findings, nil
}

// ─── helpers ─────────────────────────────────────────────────────────────────

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

// ─── engine rule ─────────────────────────────────────────────────────────────

func init() {
	engine.Default.MustRegister(&vuln001Rule{})
}

type vuln001Rule struct{}

func (r *vuln001Rule) ID() string { return "VULN001" }
func (r *vuln001Rule) Description() string {
	return "vuln.json absent — run 'gofusa vuln' to scan dependencies for known vulnerabilities (ISO 21434 §8.5)"
}

//fusa:req REQ-VULN003
func (r *vuln001Rule) Run(_ context.Context, projectRoot string, cfg *config.Config) ([]fusa.Finding, error) {
	if _, err := os.Stat(filepath.Join(projectRoot, VulnFile)); err == nil {
		return nil, nil
	}
	return []fusa.Finding{{
		RuleID:      "VULN001",
		Severity:    fusa.SeverityInfo,
		Message:     "vuln.json not found — run 'gofusa vuln' to scan dependencies for known vulnerabilities",
		Location:    fusa.Location{File: VulnFile},
		Remediation: "Run: gofusa vuln",
	}}, nil
}

// ─── govulncheck integration ──────────────────────────────────────────────────

// ScanWithGovulncheck runs govulncheck if it is in PATH, providing call-graph
// analysis that filters out unreachable vulnerabilities. Falls back to the OSV
// API scan when govulncheck is not installed.
//
// Install: go install golang.org/x/vuln/cmd/govulncheck@latest
//
//fusa:req REQ-VULN006
func ScanWithGovulncheck(projectRoot string) (*Report, error) {
	gvc, err := exec.LookPath("govulncheck")
	if err != nil {
		// govulncheck not installed — fall back to OSV API scan.
		return Scan(projectRoot)
	}
	return runGovulncheck(projectRoot, gvc)
}

// govulncheckFinding is one JSON message line from govulncheck -json.
type govulncheckMsg struct {
	Finding *struct {
		OSV   string `json:"osv"`
		Trace []struct {
			Module   string `json:"module"`
			Version  string `json:"version"`
			Function string `json:"function,omitempty"`
		} `json:"trace"`
		FixedVersion string `json:"fixed_version,omitempty"`
	} `json:"finding,omitempty"`
}

func runGovulncheck(root, binPath string) (*Report, error) {
	cmd := exec.CommandContext(context.Background(), binPath, "-json", "./...") //nolint:gosec,CYBER005 // binPath from LookPath
	cmd.Dir = root
	// govulncheck exits non-zero when vulnerabilities are found; capture stdout regardless.
	out, _ := cmd.Output()

	report := &Report{
		Format:      "go-FuSa Vuln v1 (govulncheck)",
		GeneratedAt: time.Now().UTC(),
	}
	report.Module = moduleFromRoot(root)

	seen := make(map[string]bool)
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		var msg govulncheckMsg
		if err := json.Unmarshal(sc.Bytes(), &msg); err != nil || msg.Finding == nil {
			continue
		}
		f := msg.Finding
		if len(f.Trace) == 0 {
			continue
		}
		mod := f.Trace[0].Module
		ver := f.Trace[0].Version
		key := f.OSV + "/" + mod + "@" + ver
		if seen[key] {
			continue
		}
		seen[key] = true

		var trace []string
		for _, t := range f.Trace {
			if t.Function != "" {
				trace = append(trace, t.Function)
			}
		}

		report.Findings = append(report.Findings, Finding{
			Module:    mod,
			Version:   ver,
			ID:        f.OSV,
			Summary:   "Fixed in " + f.FixedVersion,
			CallGraph: trace,
		})
	}

	report.Scanned = countModDeps(root)
	sort.Slice(report.Findings, func(i, j int) bool {
		return report.Findings[i].ID < report.Findings[j].ID
	})
	return report, nil
}

func countModDeps(root string) int {
	data, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return 0
	}
	n := 0
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "require ") || (strings.Contains(line, " v") && !strings.HasPrefix(line, "module") && !strings.HasPrefix(line, "go ") && !strings.HasPrefix(line, "//")) {
			n++
		}
	}
	return n
}

func moduleFromRoot(root string) string {
	data, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return root
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "module "))
		}
	}
	return root
}
