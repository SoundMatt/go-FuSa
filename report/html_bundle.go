package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	fusa "github.com/SoundMatt/go-FuSa"
)

// RenderEvidenceHTML writes a self-contained HTML evidence bundle to w.
// It reads up to 16 evidence files from projectRoot and renders them as
// navigable sections. Missing files are shown as "not present" cards.
//
//fusa:req REQ-HTML004
func RenderEvidenceHTML(w io.Writer, projectRoot string) error {
	projectName := filepath.Base(projectRoot)
	modName := moduleFromRoot(projectRoot)
	if modName != "" {
		parts := strings.Split(modName, "/")
		projectName = parts[len(parts)-1]
	}

	type fileSpec struct {
		path    string
		label   string
	}

	// Evidence file inventory grouped by section
	type sectionSpec struct {
		name  string
		files []fileSpec
	}
	sections := []sectionSpec{
		{"Findings", []fileSpec{
			{"check-report.json", "Check Report"},
			{"cyber-report.json", "Cyber Report"},
		}},
		{"Traceability", []fileSpec{
			{".fusa-reqs.json", "Requirements Manifest"},
		}},
		{"Coverage", []fileSpec{
			{"coverage-report.json", "Coverage Report"},
		}},
		{"SBOM", []fileSpec{
			{"sbom.json", "SBOM (SPDX 3.0.1)"},
		}},
		{"Vulnerability Scan", []fileSpec{
			{"vuln.json", "Vulnerability Report"},
		}},
		{"SCI", []fileSpec{
			{"sci.json", "Software Configuration Index"},
			{"provenance.json", "Build Provenance"},
		}},
		{"Problem Reports", []fileSpec{
			{".fusa-problems.json", "Problem Reports"},
			{".fusa-dispositions.json", "Dispositions"},
		}},
		{"Qualification", []fileSpec{
			{"qualify-report.json", "Tool Qualification"},
			{"safety-case.json", "Safety Case"},
		}},
	}

	// Gather presence & metrics
	type renderFile struct {
		Label   string
		Path    string
		Present bool
		SizeKB  string
	}
	type renderSection struct {
		Name    string
		ID      string
		Files   []renderFile
		Metrics string
	}

	var renderSections []renderSection
	totalPresent := 0
	totalFiles := 0

	for _, sec := range sections {
		rs := renderSection{
			Name: sec.name,
			ID:   strings.ToLower(strings.ReplaceAll(sec.name, " ", "-")),
		}
		for _, fspec := range sec.files {
			totalFiles++
			rf := renderFile{Label: fspec.label, Path: fspec.path}
			abs := filepath.Join(projectRoot, filepath.FromSlash(fspec.path))
			if info, err := os.Stat(abs); err == nil {
				rf.Present = true
				rf.SizeKB = fmt.Sprintf("%.1f KB", float64(info.Size())/1024)
				totalPresent++
			}
			rs.Files = append(rs.Files, rf)
		}
		rs.Metrics = sectionMetrics(sec.name, projectRoot)
		renderSections = append(renderSections, rs)
	}

	// Overall badge
	badgeClass, badgeText := overallBadge(projectRoot)

	navItems := []string{"Overview"}
	for _, sec := range sections {
		navItems = append(navItems, sec.name)
	}

	// Write HTML
	fmt.Fprintf(w, "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n")
	fmt.Fprintf(w, "<meta charset=\"UTF-8\">\n")
	fmt.Fprintf(w, "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n")
	fmt.Fprintf(w, "<title>go-FuSa Evidence Bundle — %s</title>\n", projectName)
	fmt.Fprintf(w, "<style>\n%s\n</style>\n</head>\n<body>\n", evidenceBundleCSS)
	fmt.Fprintf(w, "<div class=\"layout\">\n")

	// Sidebar nav
	fmt.Fprintf(w, "<nav class=\"sidebar\">\n")
	fmt.Fprintf(w, "<div class=\"sidebar-title\">go-FuSa Evidence</div>\n")
	for _, item := range navItems {
		id := strings.ToLower(strings.ReplaceAll(item, " ", "-"))
		fmt.Fprintf(w, "<a href=\"#%s\" class=\"nav-item\">%s</a>\n", id, item)
	}
	fmt.Fprintf(w, "</nav>\n")

	// Main content
	fmt.Fprintf(w, "<main class=\"content\">\n")

	// Header
	fmt.Fprintf(w, "<div class=\"header\">\n")
	fmt.Fprintf(w, "<h1>Evidence Bundle: %s</h1>\n", projectName)
	fmt.Fprintf(w, "<div class=\"meta\">Generated: %s &nbsp;·&nbsp; go-FuSa v%s</div>\n",
		time.Now().UTC().Format("2006-01-02 15:04 UTC"), fusa.Version)
	fmt.Fprintf(w, "</div>\n")

	// Overview section
	fmt.Fprintf(w, "<section id=\"overview\">\n")
	fmt.Fprintf(w, "<h2>Overview</h2>\n")
	fmt.Fprintf(w, "<div class=\"overview-row\">\n")
	fmt.Fprintf(w, "<span class=\"badge %s\">%s</span>\n", badgeClass, badgeText)
	fmt.Fprintf(w, "<span class=\"stat\">%d / %d evidence files present</span>\n", totalPresent, totalFiles)
	fmt.Fprintf(w, "</div>\n")
	fmt.Fprintf(w, "</section>\n")

	// Evidence sections
	for _, rs := range renderSections {
		fmt.Fprintf(w, "<section id=\"%s\">\n", rs.ID)
		fmt.Fprintf(w, "<h2>%s</h2>\n", rs.Name)
		if rs.Metrics != "" {
			fmt.Fprintf(w, "<div class=\"section-metrics\">%s</div>\n", rs.Metrics)
		}
		fmt.Fprintf(w, "<table>\n")
		fmt.Fprintf(w, "<thead><tr><th>File</th><th>Status</th><th>Size</th></tr></thead>\n")
		fmt.Fprintf(w, "<tbody>\n")
		for _, rf := range rs.Files {
			statusClass := "absent"
			statusText := "Not present"
			size := "—"
			if rf.Present {
				statusClass = "present"
				statusText = "Present"
				size = rf.SizeKB
			}
			fmt.Fprintf(w, "<tr><td><code>%s</code><br><small>%s</small></td>", rf.Path, rf.Label)
			fmt.Fprintf(w, "<td><span class=\"status %s\">%s</span></td>", statusClass, statusText)
			fmt.Fprintf(w, "<td>%s</td></tr>\n", size)
		}
		fmt.Fprintf(w, "</tbody>\n</table>\n</section>\n")
	}

	fmt.Fprintf(w, "</main>\n</div>\n")
	fmt.Fprintf(w, "<footer>Generated by <a href=\"https://github.com/SoundMatt/go-FuSa\">go-FuSa</a> v%s</footer>\n", fusa.Version)
	fmt.Fprintf(w, "</body>\n</html>\n")
	return nil
}

// overallBadge determines the top-level PASS/WARN/FAIL badge from check-report.json.
func overallBadge(projectRoot string) (class, text string) {
	data, err := os.ReadFile(filepath.Join(projectRoot, "check-report.json"))
	if err != nil {
		return "warn", "WARN"
	}
	var findings []struct {
		Severity string `json:"severity"`
	}
	if json.Unmarshal(data, &findings) != nil {
		// try nested
		var obj struct {
			Findings []struct {
				Severity string `json:"severity"`
			} `json:"findings"`
		}
		if json.Unmarshal(data, &obj) == nil {
			findings = obj.Findings
		}
	}
	errors := 0
	warnings := 0
	for _, f := range findings {
		switch f.Severity {
		case "ERROR":
			errors++
		case "WARNING":
			warnings++
		}
	}
	if errors > 0 {
		return "fail", "FAIL"
	}
	if warnings > 0 {
		return "warn", "WARN"
	}
	return "pass", "PASS"
}

// sectionMetrics returns a human-readable metric string for a section.
func sectionMetrics(section, projectRoot string) string {
	switch section {
	case "Findings":
		data, err := os.ReadFile(filepath.Join(projectRoot, "check-report.json"))
		if err != nil {
			return ""
		}
		var findings []struct {
			Severity string `json:"severity"`
		}
		if json.Unmarshal(data, &findings) != nil {
			var obj struct {
				Findings []struct {
					Severity string `json:"severity"`
				} `json:"findings"`
			}
			if json.Unmarshal(data, &obj) == nil {
				findings = obj.Findings
			}
		}
		errors, warnings, infos := 0, 0, 0
		for _, f := range findings {
			switch f.Severity {
			case "ERROR":
				errors++
			case "WARNING":
				warnings++
			case "INFO":
				infos++
			}
		}
		return fmt.Sprintf("%d errors, %d warnings, %d info", errors, warnings, infos)
	case "Traceability":
		data, err := os.ReadFile(filepath.Join(projectRoot, ".fusa-reqs.json"))
		if err != nil {
			return ""
		}
		var f struct {
			Requirements []struct{ ID string } `json:"requirements"`
		}
		if json.Unmarshal(data, &f) != nil {
			return ""
		}
		return fmt.Sprintf("%d requirements defined", len(f.Requirements))
	case "Coverage":
		data, err := os.ReadFile(filepath.Join(projectRoot, "coverage-report.json"))
		if err != nil {
			return ""
		}
		var f struct {
			StmtPct float64 `json:"stmtPct"`
		}
		if json.Unmarshal(data, &f) != nil {
			return ""
		}
		return fmt.Sprintf("Statement coverage: %.1f%%", f.StmtPct)
	case "Vulnerability Scan":
		data, err := os.ReadFile(filepath.Join(projectRoot, "vuln.json"))
		if err != nil {
			return ""
		}
		var f struct {
			Findings []interface{} `json:"findings"`
		}
		if json.Unmarshal(data, &f) != nil {
			return ""
		}
		return fmt.Sprintf("%d vulnerability findings", len(f.Findings))
	}
	return ""
}

const evidenceBundleCSS = `
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;font-size:14px;background:#f8fafc;color:#1e293b;line-height:1.5}
.layout{display:flex;min-height:100vh}
.sidebar{width:220px;background:#1e293b;color:#e2e8f0;padding:20px 0;position:fixed;top:0;left:0;height:100vh;overflow-y:auto}
.sidebar-title{font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:1px;padding:8px 20px 16px;color:#94a3b8}
.nav-item{display:block;padding:8px 20px;color:#cbd5e1;text-decoration:none;font-size:13px}
.nav-item:hover{background:#334155;color:#fff}
.content{margin-left:220px;flex:1;padding:24px;max-width:900px}
.header{margin-bottom:24px;padding:20px;background:#fff;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.header h1{font-size:20px;font-weight:700;margin-bottom:4px}
.meta{color:#64748b;font-size:13px}
section{background:#fff;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,.08);margin-bottom:20px;overflow:hidden}
section h2{font-size:15px;font-weight:600;padding:14px 20px;border-bottom:1px solid #f1f5f9;background:#f8fafc}
.section-metrics{padding:10px 20px;background:#f0f9ff;border-bottom:1px solid #e0f2fe;font-size:13px;color:#0369a1}
.overview-row{display:flex;align-items:center;gap:16px;padding:16px 20px}
.stat{font-size:14px;color:#64748b}
.badge{display:inline-block;padding:6px 16px;border-radius:99px;font-weight:700;font-size:14px}
.badge.pass{background:#dcfce7;color:#166534}
.badge.warn{background:#fef9c3;color:#854d0e}
.badge.fail{background:#fee2e2;color:#991b1b}
table{width:100%;border-collapse:collapse}
thead tr{background:#f8fafc}
th,td{text-align:left;padding:10px 20px;border-bottom:1px solid #f1f5f9;font-size:13px}
th{font-weight:600;color:#64748b;font-size:12px;text-transform:uppercase;letter-spacing:.5px}
.status{display:inline-block;padding:2px 10px;border-radius:4px;font-size:12px;font-weight:600}
.status.present{background:#dcfce7;color:#166534}
.status.absent{background:#fee2e2;color:#991b1b}
footer{text-align:center;font-size:12px;color:#94a3b8;padding:16px;margin-left:220px}
footer a{color:#64748b}
code{background:#f1f5f9;padding:1px 4px;border-radius:3px;font-size:12px}
small{color:#94a3b8;font-size:11px}
`
