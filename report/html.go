package report

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	fusa "github.com/SoundMatt/go-FuSa"
)

// htmlData is the template model for the HTML report.
type htmlData struct {
	ProjectName string
	Module      string
	GeneratedAt string
	Result      string
	ResultClass string
	Summary     Summary
	Findings    []htmlFinding
	Evidence    []htmlEvidence
	ReqCount    int
	TestedCount int
	Version     string
}

type htmlFinding struct {
	RuleID      string
	SevClass    string
	Severity    string
	Message     string
	Location    string
	Remediation string
}

type htmlEvidence struct {
	Label       string
	StatusClass string
	Icon        string
	Detail      string
}

// RenderHTML writes r to w as a self-contained HTML page.
//
//fusa:req REQ-HTML001
//fusa:req REQ-HTML003
func RenderHTML(w io.Writer, r *Report) error {
	module := moduleFromRoot(r.ProjectRoot)
	name := filepath.Base(r.ProjectRoot)
	if module != "" {
		parts := strings.Split(module, "/")
		name = parts[len(parts)-1]
	}

	result := "PASS"
	resultClass := "pass"
	if r.Summary.Errors > 0 {
		result = "FAIL"
		resultClass = "fail"
	} else if r.Summary.Warnings > 0 {
		result = "WARN"
		resultClass = "warn"
	}

	var findings []htmlFinding
	for _, f := range r.Findings {
		loc := f.Location.File
		if f.Location.Line > 0 {
			loc = fmt.Sprintf("%s:%d", loc, f.Location.Line)
		}
		findings = append(findings, htmlFinding{
			RuleID:      f.RuleID,
			SevClass:    strings.ToLower(string(f.Severity)),
			Severity:    string(f.Severity),
			Message:     f.Message,
			Location:    loc,
			Remediation: f.Remediation,
		})
	}

	evidence := collectEvidenceStatus(r.ProjectRoot)
	reqCount, testedCount := countRequirements(r.ProjectRoot)

	data := htmlData{
		ProjectName: name,
		Module:      module,
		GeneratedAt: r.GeneratedAt.Format(time.RFC3339),
		Result:      result,
		ResultClass: resultClass,
		Summary:     r.Summary,
		Findings:    findings,
		Evidence:    evidence,
		ReqCount:    reqCount,
		TestedCount: testedCount,
		Version:     fusa.Version,
	}

	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("report: html template: %w", err)
	}
	return tmpl.Execute(w, data)
}

// ─── evidence collection ─────────────────────────────────────────────────────

//fusa:req REQ-HTML002
func collectEvidenceStatus(root string) []htmlEvidence {
	type spec struct {
		label string
		file  string
		hint  string
	}
	specs := []spec{
		{"Safety checks", "check-report.json", "gofusa check"},
		{"Traceability", ".fusa-reqs.json", "gofusa trace"},
		{"Test evidence", ".fusa-evidence.json", "gofusa verify"},
		{"Tool qualification", "qualify-report.json", "gofusa qualify"},
		{"SBOM (SPDX 3.0.1)", "sbom.json", "gofusa release"},
		{"Build provenance", "provenance.json", "gofusa release"},
		{"dFMEA table", "fmea.json", "gofusa fmea"},
		{"Boundary diagram", "boundary.mermaid", "gofusa boundary"},
		{"Safety case", "safety-case.json", "gofusa safety-case"},
		{"Vulnerability scan", "vuln.json", "gofusa vuln"},
		{"Audit pack", "audit-pack.zip", "gofusa audit-pack"},
	}

	var items []htmlEvidence
	for _, s := range specs {
		if _, err := os.Stat(filepath.Join(root, s.file)); err == nil {
			items = append(items, htmlEvidence{
				Label:       s.label,
				StatusClass: "present",
				Icon:        "✓",
				Detail:      s.file,
			})
		} else {
			items = append(items, htmlEvidence{
				Label:       s.label,
				StatusClass: "absent",
				Icon:        "✗",
				Detail:      "Run: " + s.hint,
			})
		}
	}
	return items
}

func countRequirements(root string) (total, tested int) {
	data, err := os.ReadFile(filepath.Join(root, ".fusa-reqs.json"))
	if err != nil {
		return 0, 0
	}
	var f struct {
		Requirements []struct {
			ID string `json:"id"`
		} `json:"requirements"`
	}
	if json.Unmarshal(data, &f) != nil {
		return 0, 0
	}
	return len(f.Requirements), 0
}

func moduleFromRoot(root string) string {
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

// ─── HTML template ───────────────────────────────────────────────────────────

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>go-FuSa Safety Report — {{.ProjectName}}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;font-size:14px;background:#f8fafc;color:#1e293b;line-height:1.5}
.container{max-width:1100px;margin:0 auto;padding:24px}
header{display:flex;align-items:center;gap:16px;margin-bottom:24px;padding:20px 24px;background:#fff;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,.08)}
header h1{font-size:20px;font-weight:700}
.meta{color:#64748b;font-size:13px;flex:1}
.badge{display:inline-block;padding:4px 12px;border-radius:99px;font-weight:700;font-size:13px;letter-spacing:.5px}
.badge.pass{background:#dcfce7;color:#166534}
.badge.warn{background:#fef9c3;color:#854d0e}
.badge.fail{background:#fee2e2;color:#991b1b}
section{background:#fff;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,.08);margin-bottom:20px;overflow:hidden}
section h2{font-size:15px;font-weight:600;padding:14px 20px;border-bottom:1px solid #f1f5f9;background:#f8fafc}
.summary-bar{display:flex;gap:24px;padding:16px 20px}
.stat{text-align:center}
.stat .num{font-size:24px;font-weight:700}
.stat .label{font-size:12px;color:#64748b;text-transform:uppercase;letter-spacing:.5px}
.num.error{color:#ef4444}
.num.warning{color:#f97316}
.num.info{color:#3b82f6}
.num.ok{color:#22c55e}
.evidence-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:12px;padding:16px 20px}
.card{border-radius:6px;padding:12px;border:1px solid #e2e8f0}
.card.present{border-color:#86efac;background:#f0fdf4}
.card.absent{border-color:#fca5a5;background:#fef2f2}
.card .icon{font-size:18px;display:block;margin-bottom:4px}
.card .clabel{font-size:12px;font-weight:600;display:block;margin-bottom:2px}
.card .detail{font-size:11px;color:#64748b;display:block}
table{width:100%;border-collapse:collapse}
thead tr{background:#f8fafc}
th,td{text-align:left;padding:10px 16px;border-bottom:1px solid #f1f5f9;font-size:13px}
th{font-weight:600;color:#64748b;font-size:12px;text-transform:uppercase;letter-spacing:.5px}
tr.error td:first-child{border-left:3px solid #ef4444}
tr.warning td:first-child{border-left:3px solid #f97316}
tr.info td:first-child{border-left:3px solid #3b82f6}
.sev{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600}
.sev.error{background:#fee2e2;color:#991b1b}
.sev.warning{background:#ffedd5;color:#9a3412}
.sev.info{background:#dbeafe;color:#1e40af}
.req-bar{display:flex;gap:24px;padding:16px 20px}
footer{text-align:center;font-size:12px;color:#94a3b8;padding:16px}
footer a{color:#64748b}
</style>
</head>
<body>
<div class="container">
<header>
  <div>
    <h1>Safety Compliance Report</h1>
    <div class="meta">{{.Module}} &nbsp;·&nbsp; {{.GeneratedAt}}</div>
  </div>
  <span class="badge {{.ResultClass}}">{{.Result}}</span>
</header>

<section>
  <h2>Summary</h2>
  <div class="summary-bar">
    <div class="stat"><div class="num {{if gt .Summary.Errors 0}}error{{else}}ok{{end}}">{{.Summary.Errors}}</div><div class="label">Errors</div></div>
    <div class="stat"><div class="num {{if gt .Summary.Warnings 0}}warning{{else}}ok{{end}}">{{.Summary.Warnings}}</div><div class="label">Warnings</div></div>
    <div class="stat"><div class="num info">{{.Summary.Infos}}</div><div class="label">Info</div></div>
    <div class="stat"><div class="num">{{.Summary.Total}}</div><div class="label">Total</div></div>
    <div class="stat"><div class="num">{{.ReqCount}}</div><div class="label">Requirements</div></div>
  </div>
</section>

<section>
  <h2>Evidence Status</h2>
  <div class="evidence-grid">
    {{range .Evidence}}
    <div class="card {{.StatusClass}}">
      <span class="icon">{{.Icon}}</span>
      <span class="clabel">{{.Label}}</span>
      <span class="detail">{{.Detail}}</span>
    </div>
    {{end}}
  </div>
</section>

<section>
  <h2>Findings ({{len .Findings}})</h2>
  {{if .Findings}}
  <table>
    <thead><tr><th>Rule</th><th>Severity</th><th>Message</th><th>Location</th><th>Remediation</th></tr></thead>
    <tbody>
      {{range .Findings}}
      <tr class="{{.SevClass}}">
        <td><code>{{.RuleID}}</code></td>
        <td><span class="sev {{.SevClass}}">{{.Severity}}</span></td>
        <td>{{.Message}}</td>
        <td><code>{{.Location}}</code></td>
        <td>{{.Remediation}}</td>
      </tr>
      {{end}}
    </tbody>
  </table>
  {{else}}
  <p style="padding:16px 20px;color:#64748b">No findings.</p>
  {{end}}
</section>

<footer>
  Generated by <a href="https://github.com/SoundMatt/go-FuSa">go-FuSa</a> v{{.Version}}
</footer>
</div>
</body>
</html>
`
