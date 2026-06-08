// Package tara generates a Threat Analysis and Risk Assessment (TARA) table
// per ISO 21434 Chapter 9 (v0.15).
//
// Scan takes the CYBER findings produced by the cyber package and maps each
// finding to a STRIDE threat category, attack vector, likelihood, impact, and
// IEC 62443 Security Level. The result is a structured [Report] that can be
// rendered as JSON or a Markdown table for inclusion in a safety case.
//
// Usage:
//
//	findings, _ := cyber.Scan(ctx, root, cfg)
//	report, _  := tara.Scan(root, findings)
//	tara.Render(os.Stdout, report, "markdown")
//
// Activate the engine rule by importing this package for its side effects:
//
//	import _ "github.com/SoundMatt/go-FuSa/tara"
package tara

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/config"
	"github.com/SoundMatt/go-FuSa/engine"
)

// TARAFile is the default JSON output filename.
const TARAFile = "tara.json"

// TARAMarkdownFile is the default Markdown output filename.
const TARAMarkdownFile = "tara.md"

// ThreatEntry is one row in the TARA table.
//
//fusa:req REQ-TARA001
type ThreatEntry struct {
	ID             string   `json:"id"`
	Asset          string   `json:"asset"`
	Threat         string   `json:"threat"`
	STRIDE         []string `json:"stride"` // S/T/R/I/D/E categories
	CWE            string   `json:"cwe"`
	Standard       string   `json:"standard,omitempty"`
	AttackVector   string   `json:"attack_vector"`  // Network/Adjacent/Local/Physical
	Likelihood     string   `json:"likelihood"`     // High/Medium/Low
	Impact         string   `json:"impact"`         // High/Medium/Low
	SecurityLevel  int      `json:"security_level"` // IEC 62443 SL (1–4)
	CurrentControl string   `json:"current_control"`
	ResidualRisk   string   `json:"residual_risk"`
	CyberRuleID    string   `json:"cyber_rule_id"`
	SourceFile     string   `json:"source_file,omitempty"`
	SourceLine     int      `json:"source_line,omitempty"`
}

// Report is the full TARA output.
//
//fusa:req REQ-TARA002
type Report struct {
	Format      string        `json:"format"`
	GeneratedAt time.Time     `json:"generated_at"`
	Module      string        `json:"module"`
	Entries     []ThreatEntry `json:"entries"`
}

// Scan builds a TARA from CYBER findings produced by cyber.Scan.
//
//fusa:req REQ-TARA003
func Scan(projectRoot string, cyberFindings []fusa.Finding) (*Report, error) {
	report := &Report{
		Format:      "go-FuSa TARA v1",
		GeneratedAt: time.Now().UTC(),
		Module:      readModule(projectRoot),
	}

	for i, f := range cyberFindings {
		meta, ok := ruleMeta[f.RuleID]
		if !ok {
			meta = threatMeta{
				threat:     "Security weakness: " + f.Message,
				stride:     []string{"T"},
				cwe:        "CWE-0",
				vector:     "Local",
				likelihood: "Low",
				impact:     "Low",
				sl:         1,
				control:    "Review finding",
				residual:   "Unknown",
			}
		}

		entry := ThreatEntry{
			ID:             fmt.Sprintf("TARA-%03d", i+1),
			Asset:          assetFromFinding(f),
			Threat:         meta.threat,
			STRIDE:         meta.stride,
			CWE:            meta.cwe,
			Standard:       meta.standard,
			AttackVector:   meta.vector,
			Likelihood:     severityToLikelihood(f.Severity, meta.likelihood),
			Impact:         meta.impact,
			SecurityLevel:  meta.sl,
			CurrentControl: meta.control,
			ResidualRisk:   meta.residual,
			CyberRuleID:    f.RuleID,
			SourceFile:     f.Location.File,
			SourceLine:     f.Location.Line,
		}
		report.Entries = append(report.Entries, entry)
	}

	sort.Slice(report.Entries, func(i, j int) bool {
		return report.Entries[i].ID < report.Entries[j].ID
	})
	return report, nil
}

// Render writes the TARA report to w in the given format: "json" or "markdown".
//
//fusa:req REQ-TARA004
func Render(w io.Writer, r *Report, format string) error {
	switch format {
	case "json", "":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	case "markdown", "md":
		return renderMarkdown(w, r)
	default:
		return fmt.Errorf("tara: unknown format %q (want json or markdown)", format)
	}
}

func renderMarkdown(w io.Writer, r *Report) error {
	fmt.Fprintf(w, "# Threat Analysis and Risk Assessment (TARA)\n\n")
	fmt.Fprintf(w, "**Module:** %s  \n", r.Module)
	fmt.Fprintf(w, "**Generated:** %s  \n", r.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(w, "**Standard:** ISO 21434 Chapter 9  \n\n")
	fmt.Fprintf(w, "| ID | Asset | Threat | STRIDE | CWE | Vector | Likelihood | Impact | SL | Control | Residual Risk |\n")
	fmt.Fprintf(w, "|---|---|---|---|---|---|---|---|---|---|---|\n")
	for _, e := range r.Entries {
		fmt.Fprintf(w, "| %s | %s | %s | %s | %s | %s | %s | %s | %d | %s | %s |\n",
			e.ID,
			e.Asset,
			e.Threat,
			strings.Join(e.STRIDE, "/"),
			e.CWE,
			e.AttackVector,
			e.Likelihood,
			e.Impact,
			e.SecurityLevel,
			e.CurrentControl,
			e.ResidualRisk,
		)
	}
	return nil
}

// ─── rule metadata ────────────────────────────────────────────────────────────

type threatMeta struct {
	threat     string
	stride     []string
	cwe        string
	standard   string
	vector     string
	likelihood string
	impact     string
	sl         int
	control    string
	residual   string
}

// ruleMeta maps CYBER rule IDs to STRIDE/CWE/risk metadata per ISO 21434.
var ruleMeta = map[string]threatMeta{
	"CYBER001": {
		threat: "Weak hash (MD5/SHA-1) enables integrity bypass",
		stride: []string{"T", "I"}, cwe: "CWE-327", standard: "ISO 21434 §8.5",
		vector: "Network", likelihood: "Medium", impact: "High", sl: 2,
		control: "Replace with SHA-256 or stronger", residual: "Low after remediation",
	},
	"CYBER002": {
		threat: "Weak cipher (DES/RC4) enables confidentiality breach",
		stride: []string{"I"}, cwe: "CWE-327", standard: "MISRA Dir 4.8",
		vector: "Network", likelihood: "Medium", impact: "High", sl: 2,
		control: "Replace with AES-GCM or ChaCha20-Poly1305", residual: "Low after remediation",
	},
	"CYBER003": {
		threat: "Predictable random values enable authentication bypass or token forgery",
		stride: []string{"S", "T"}, cwe: "CWE-330", standard: "CERT MSC50",
		vector: "Network", likelihood: "Medium", impact: "Medium", sl: 2,
		control: "Use crypto/rand", residual: "Low after remediation",
	},
	"CYBER004": {
		threat: "Unsafe pointer usage causes undefined behaviour or memory corruption",
		stride: []string{"E"}, cwe: "CWE-242", standard: "MISRA Rule 11.3",
		vector: "Local", likelihood: "Low", impact: "High", sl: 3,
		control: "Remove unsafe usage; use safe Go idioms", residual: "Medium — requires code redesign",
	},
	"CYBER005": {
		threat: "Command injection from variable input enables arbitrary command execution",
		stride: []string{"E", "R"}, cwe: "CWE-78",
		vector: "Network", likelihood: "High", impact: "High", sl: 3,
		control: "Use exec.Command with fixed command and sanitised args", residual: "Low after remediation",
	},
	"CYBER006": {
		threat: "Hardcoded credential enables unauthorised access",
		stride: []string{"S", "E"}, cwe: "CWE-798",
		vector: "Local", likelihood: "High", impact: "High", sl: 2,
		control: "Remove hardcoded credential; load from environment or secret manager", residual: "Low after remediation",
	},
	"CYBER007": {
		threat: "TLS certificate bypass enables man-in-the-middle and data interception",
		stride: []string{"I", "T"}, cwe: "CWE-295", standard: "ISO 21434 §10.4",
		vector: "Network", likelihood: "High", impact: "High", sl: 3,
		control: "Set InsecureSkipVerify: false; use a trusted CA bundle", residual: "Low after remediation",
	},
	"CYBER008": {
		threat: "HTTP server with no timeouts enables resource exhaustion denial of service",
		stride: []string{"D"}, cwe: "CWE-400",
		vector: "Network", likelihood: "Medium", impact: "Medium", sl: 2,
		control: "Set ReadTimeout, WriteTimeout, IdleTimeout on http.Server", residual: "Low after remediation",
	},
	"CYBER009": {
		threat: "Integer narrowing conversion causes silent data truncation",
		stride: []string{"T", "D"}, cwe: "CWE-190", standard: "MISRA Rule 10.3",
		vector: "Local", likelihood: "Low", impact: "Medium", sl: 1,
		control: "Add range check before conversion", residual: "Low after remediation",
	},
	"CYBER010": {
		threat: "String concatenation in OS path / DB query enables path traversal or SQL injection",
		stride: []string{"T", "E"}, cwe: "CWE-22 / CWE-89",
		vector: "Network", likelihood: "High", impact: "High", sl: 3,
		control: "Use filepath.Join + Clean; use parameterised queries", residual: "Low after remediation",
	},
	"CYBER011": {
		threat: "SSRF — server fetches attacker-controlled URL",
		stride: []string{"S", "I"}, cwe: "CWE-918",
		vector: "Network", likelihood: "Medium", impact: "High", sl: 3,
		control: "Validate/whitelist URLs before HTTP client call", residual: "Low after remediation",
	},
	"CYBER012": {
		threat: "Profiling endpoint exposed leaks heap, goroutine, and CPU data",
		stride: []string{"I"}, cwe: "CWE-200",
		vector: "Network", likelihood: "Medium", impact: "Medium", sl: 2,
		control: "Remove net/http/pprof import from production builds", residual: "Low after remediation",
	},
	"CYBER013": {
		threat: "Zip slip allows attacker-controlled archive entry to overwrite arbitrary files",
		stride: []string{"T", "E"}, cwe: "CWE-23",
		vector: "Network", likelihood: "High", impact: "High", sl: 3,
		control: "Sanitise archive entry Names with filepath.Clean; reject '..' components", residual: "Low after remediation",
	},
	"CYBER014": {
		threat: "Low TLS minimum version allows negotiation of deprecated cipher suites",
		stride: []string{"I"}, cwe: "CWE-326",
		vector: "Network", likelihood: "Low", impact: "High", sl: 2,
		control: "Set MinVersion: tls.VersionTLS12 or higher", residual: "Low after remediation",
	},
	"CYBER015": {
		threat: "SQL injection via fmt.Sprintf enables data exfiltration or schema modification",
		stride: []string{"T", "I"}, cwe: "CWE-89",
		vector: "Network", likelihood: "High", impact: "High", sl: 3,
		control: "Use parameterised queries", residual: "Low after remediation",
	},
	"CYBER016": {
		threat: "World-readable/writable directory allows unauthorised file access",
		stride: []string{"E", "I"}, cwe: "CWE-732",
		vector: "Local", likelihood: "Medium", impact: "Medium", sl: 2,
		control: "Create directory with mode 0750 or stricter", residual: "Low after remediation",
	},
	"CYBER017": {
		threat: "World-readable/writable file allows unauthorised data access or tampering",
		stride: []string{"I", "T"}, cwe: "CWE-732",
		vector: "Local", likelihood: "Medium", impact: "Medium", sl: 2,
		control: "Create file with mode 0640 or stricter", residual: "Low after remediation",
	},
	"CYBER018": {
		threat: "Path traversal via HTTP request allows reading arbitrary server files",
		stride: []string{"T", "I"}, cwe: "CWE-22",
		vector: "Network", likelihood: "High", impact: "High", sl: 3,
		control: "Sanitise path with filepath.Clean; restrict to allowed root", residual: "Low after remediation",
	},
	"CYBER019": {
		threat: "TOCTOU race allows attacker to substitute file between check and use",
		stride: []string{"E", "T"}, cwe: "CWE-362",
		vector: "Local", likelihood: "Low", impact: "Medium", sl: 2,
		control: "Open file directly; handle ENOENT/EEXIST atomically", residual: "Low after remediation",
	},
	"CYBER020": {
		threat: "Predictable temp file path enables symlink attack or race condition",
		stride: []string{"I", "T"}, cwe: "CWE-377",
		vector: "Local", likelihood: "Medium", impact: "Medium", sl: 2,
		control: "Replace with os.CreateTemp for unpredictable temp file names", residual: "Low after remediation",
	},
}

func assetFromFinding(f fusa.Finding) string {
	if f.Location.File != "" {
		return filepath.Base(f.Location.File)
	}
	return f.RuleID
}

func severityToLikelihood(sev fusa.Severity, defaultVal string) string {
	switch sev {
	case fusa.SeverityError:
		return "High"
	case fusa.SeverityWarning:
		return "Medium"
	case fusa.SeverityInfo:
		return "Low"
	}
	return defaultVal
}

func readModule(root string) string {
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

// ─── engine rule ──────────────────────────────────────────────────────────────

func init() {
	engine.Default.MustRegister(&taraPresentRule{})
}

type taraPresentRule struct{}

func (r *taraPresentRule) ID() string { return "TARA001" }
func (r *taraPresentRule) Description() string {
	return "TARA001: Project should have a tara.json Threat Analysis and Risk Assessment per ISO 21434 Chapter 9."
}

//fusa:req REQ-TARA005
func (r *taraPresentRule) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	if _, err := os.Stat(filepath.Join(projectRoot, TARAFile)); err == nil {
		return nil, nil
	}
	return []fusa.Finding{{
		RuleID:      r.ID(),
		Severity:    fusa.SeverityInfo,
		Message:     "no tara.json found — run 'gofusa tara' to generate the Threat Analysis and Risk Assessment",
		Location:    fusa.Location{File: TARAFile},
		Remediation: "run 'gofusa tara' to generate tara.json and tara.md from CYBER findings",
	}}, nil
}
