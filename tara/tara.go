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
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/config"
	"github.com/SoundMatt/go-FuSa/engine"
	"github.com/SoundMatt/go-FuSa/trace"
)

// TARAFile is the default JSON output filename.
const TARAFile = "tara.json"

// TARAMarkdownFile is the default Markdown output filename.
const TARAMarkdownFile = "tara.md"

// SFOPImpact is ISO 21434's own Safety/Financial/Operational/Privacy impact
// framework (Clause 15.7) — a threat against an asset can rate differently
// on each axis, so a single generic severity is not sufficient (x-FuSa spec
// §9.2). Each field is "critical" | "major" | "moderate" | "negligible" —
// the x-FuSa family's own closed enum (§9.2 MUST), deliberately distinct
// from attackFeasibility's high/medium/low/very-low vocabulary even though
// both are nominally "how bad/how likely" scales.
//
//fusa:req REQ-TARA006
type SFOPImpact struct {
	Safety      string `json:"safety"`
	Financial   string `json:"financial"`
	Operational string `json:"operational"`
	Privacy     string `json:"privacy"`
}

// Location identifies the source of a code-derived threat (§9.2 SHOULD).
type Location struct {
	File string `json:"file,omitempty"`
	Line int    `json:"line,omitempty"`
}

// ThreatEntry is one row in the TARA table.
//
//fusa:req REQ-TARA001
type ThreatEntry struct {
	ID       string   `json:"id"`
	Asset    string   `json:"asset"`
	Threat   string   `json:"threat"`
	STRIDE   []string `json:"stride"` // S/T/R/I/D/E categories
	CWE      string   `json:"cwe,omitempty"`
	Standard string   `json:"standard,omitempty"`

	AttackVector      string     `json:"attackVector"`      // Network/Adjacent/Local/Physical
	AttackFeasibility string     `json:"attackFeasibility"` // high|medium|low|very-low (ISO 21434 attack-potential rating)
	Impact            SFOPImpact `json:"impact"`            // SFOP categories (ISO 21434 Clause 15.7); each axis critical|major|moderate|negligible (§9.2 closed enum)
	Risk              string     `json:"risk"`              // critical|high|medium|low (§9.2 closed enum) — derived from attackFeasibility × the highest SFOP impact via riskTable
	Treatment         string     `json:"treatment"`         // mitigate|accept|transfer|avoid

	SecurityLevel  int      `json:"securityLevel"` // IEC 62443 SL (1–4) — supplementary, not part of the §9.2 schema
	Mitigations    []string `json:"mitigations,omitempty"`
	CurrentControl string   `json:"currentControl,omitempty"` // supplementary, superseded by Mitigations
	ResidualRisk   string   `json:"residualRisk,omitempty"`   // supplementary, not part of the §9.2 schema

	Location    Location `json:"location,omitempty"`
	CyberRuleID string   `json:"cyberRuleId,omitempty"`

	SourceFile string `json:"sourceFile,omitempty"` // supplementary duplicate of Location.File, kept for back-compat
	SourceLine int    `json:"sourceLine,omitempty"` // supplementary duplicate of Location.Line, kept for back-compat
}

// Summary is the x-FuSa spec §9.2 `tara.json` summary block.
//
//fusa:req REQ-TARA007
type Summary struct {
	AssetsAnalyzed       int     `json:"assetsAnalyzed"`
	AssetsInProject      int     `json:"assetsInProject"`
	CoveragePct          float64 `json:"coveragePct"`
	AssetInventoryMethod string  `json:"assetInventoryMethod,omitempty"`
}

// Report is the full TARA output.
//
//fusa:req REQ-TARA002
type Report struct {
	// §3.1 common header.
	SchemaVersion string    `json:"schemaVersion"`
	Kind          string    `json:"kind"`
	Tool          string    `json:"tool"`
	ToolVersion   string    `json:"toolVersion"`
	Language      string    `json:"language"`
	GeneratedAt   time.Time `json:"generatedAt"`

	Format string `json:"format,omitempty"` // supplementary/legacy, not part of the §3.1 header
	Module string `json:"module,omitempty"`

	Entries []ThreatEntry `json:"threats"` // canonical key is "threats", NOT "entries"/"scenarios" (§9.2)
	Summary Summary       `json:"summary"`

	// Attestation is the optional §1.6.2 independent-review assertion that
	// can suppress a FUSA-STUB002 (blanket-fallback) finding on this file.
	Attestation *fusa.Attestation `json:"attestation,omitempty"`
}

// Scan builds a TARA from CYBER findings produced by cyber.Scan.
//
//fusa:req REQ-TARA003
func Scan(projectRoot string, cyberFindings []fusa.Finding) (*Report, error) {
	report := &Report{
		SchemaVersion: fusa.SchemaVersion(),
		Kind:          "tara-report",
		Tool:          "go-FuSa",
		ToolVersion:   fusa.Version,
		Language:      "go",
		GeneratedAt:   time.Now().UTC(),
		Format:        "go-FuSa TARA v1",
		Module:        readModule(projectRoot),
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

		feasibility := severityToLikelihood(f.Severity, meta.likelihood)
		impact := deriveSFOP(meta)

		entry := ThreatEntry{
			ID:                fmt.Sprintf("TARA-%03d", i+1),
			Asset:             assetFromFinding(f),
			Threat:            meta.threat,
			STRIDE:            meta.stride,
			CWE:               meta.cwe,
			Standard:          meta.standard,
			AttackVector:      meta.vector,
			AttackFeasibility: strings.ToLower(feasibility),
			Impact:            impact,
			Risk:              deriveRisk(feasibility, impact),
			Treatment:         "mitigate", // every rule in ruleMeta supplies a concrete corrective control
			SecurityLevel:     meta.sl,
			Mitigations:       []string{meta.control},
			CurrentControl:    meta.control,
			ResidualRisk:      meta.residual,
			Location:          Location{File: f.Location.File, Line: f.Location.Line},
			CyberRuleID:       f.RuleID,
			SourceFile:        f.Location.File,
			SourceLine:        f.Location.Line,
		}
		report.Entries = append(report.Entries, entry)
	}

	sort.Slice(report.Entries, func(i, j int) bool {
		return report.Entries[i].ID < report.Entries[j].ID
	})

	report.Summary = buildSummary(report, projectRoot)
	return report, nil
}

// sfopRank orders the x-FuSa spec §9.2 closed SFOP impact vocabulary
// (critical > major > moderate > negligible) — deliberately distinct from
// attackFeasibility's own high/medium/low/very-low vocabulary (§9.2 MUST:
// the two are separate scales for separate questions, likelihood vs.
// damage, and MUST NOT be conflated). An unrecognised value ranks as the
// lowest tier rather than silently escalating.
func sfopRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 3
	case "major":
		return 2
	case "moderate":
		return 1
	}
	return 0 // "negligible", or any unrecognised value
}

func sfopFromRank(r int) string {
	switch r {
	case 3:
		return "critical"
	case 2:
		return "major"
	case 1:
		return "moderate"
	default:
		return "negligible"
	}
}

// riskTable implements the x-FuSa spec §9.2 SHOULD risk combination table:
// the highest-ranked of the four SFOP impact axes × attackFeasibility →
// risk. ISO/SAE 21434 Clause 15.3 deliberately leaves risk determination to
// each organisation, so this is the x-FuSa family's own canonical
// convention (documented in the spec) rather than a normative external
// table — every value is taken verbatim from the spec's published table so
// cross-tool risk values stay comparable.
var riskTable = map[[2]string]string{
	{"critical", "high"}:       "critical",
	{"critical", "medium"}:     "critical",
	{"critical", "low"}:        "high",
	{"critical", "very-low"}:   "medium",
	{"major", "high"}:          "high",
	{"major", "medium"}:        "high",
	{"major", "low"}:           "medium",
	{"major", "very-low"}:      "medium",
	{"moderate", "high"}:       "medium",
	{"moderate", "medium"}:     "medium",
	{"moderate", "low"}:        "low",
	{"moderate", "very-low"}:   "low",
	{"negligible", "high"}:     "low",
	{"negligible", "medium"}:   "low",
	{"negligible", "low"}:      "low",
	{"negligible", "very-low"}: "low",
}

// deriveRisk computes the §9.2 `risk` field via riskTable: the highest of
// the four SFOP impact axes × attackFeasibility. feasibility is matched
// case-insensitively against high/medium/low/very-low; an unrecognised
// value is treated as "low" (fail-safe — never silently escalating risk
// for a feasibility value the tool doesn't understand).
//
//fusa:req REQ-TARA012
func deriveRisk(feasibility string, impact SFOPImpact) string {
	maxRank := sfopRank(impact.Safety)
	for _, v := range []string{impact.Financial, impact.Operational, impact.Privacy} {
		if r := sfopRank(v); r > maxRank {
			maxRank = r
		}
	}
	highest := sfopFromRank(maxRank)

	feas := strings.ToLower(feasibility)
	switch feas {
	case "high", "medium", "low", "very-low":
	default:
		feas = "low"
	}
	if risk, ok := riskTable[[2]string{highest, feas}]; ok {
		return risk
	}
	return "low"
}

// legacyImpactToSFOP maps threatMeta's pre-existing high/medium/low impact
// rating (and IEC 62443 security level, as a proxy for how severe a "high"
// really is) onto the x-FuSa spec §9.2 closed SFOP vocabulary
// (critical/major/moderate/negligible) — a "high" rating on an SL3 rule
// (the most severe class in ruleMeta) escalates to "critical"; every other
// "high" is "major", preserving four genuinely distinct tiers rather than
// collapsing "high" onto a single value regardless of severity.
func legacyImpactToSFOP(level string, sl int) string {
	switch strings.ToLower(level) {
	case "high":
		if sl >= 3 {
			return "critical"
		}
		return "major"
	case "medium":
		return "moderate"
	default:
		return "negligible"
	}
}

// deriveSFOP maps a threatMeta's STRIDE categories and generic impact rating
// onto the four ISO 21434 Clause 15.7 SFOP axes, using the §9.2 closed
// critical/major/moderate/negligible vocabulary. This is a coarse, honestly
// heuristic mapping (not a per-asset SFOP analysis) — Safety inherits the
// rule's own tuned impact rating (escalated via legacyImpactToSFOP);
// Operational/Privacy are elevated when the STRIDE categories most
// associated with them (Denial of Service / Info Disclosure) are present;
// Financial is elevated for higher IEC 62443 security levels, as a proxy
// for remediation/incident cost.
//
//fusa:req REQ-TARA006
func deriveSFOP(m threatMeta) SFOPImpact {
	impact := SFOPImpact{
		Safety:      legacyImpactToSFOP(m.impact, m.sl),
		Financial:   "negligible",
		Operational: "negligible",
		Privacy:     "negligible",
	}
	for _, s := range m.stride {
		switch s {
		case "D":
			impact.Operational = "moderate"
		case "I":
			impact.Privacy = "moderate"
		}
	}
	if m.sl >= 3 {
		impact.Financial = "moderate"
	}
	return impact
}

// buildSummary computes the §9.2 coverage metrics. AssetsAnalyzed is the
// number of distinct source files carrying at least one identified threat;
// AssetsInProject is CountProjectFiles's independent count of every
// candidate source file in the project. See Summary.AssetInventoryMethod
// for the documented methodology.
func buildSummary(report *Report, projectRoot string) Summary {
	distinct := make(map[string]struct{}, len(report.Entries))
	for _, e := range report.Entries {
		if e.SourceFile != "" {
			distinct[e.SourceFile] = struct{}{}
		}
	}
	s := Summary{AssetsAnalyzed: len(distinct)}

	total, err := CountProjectFiles(projectRoot)
	if err != nil || total < s.AssetsAnalyzed {
		total = s.AssetsAnalyzed
	}
	s.AssetsInProject = total
	if total > 0 {
		s.CoveragePct = float64(s.AssetsAnalyzed) * 100 / float64(total)
	} else {
		s.CoveragePct = 100
	}
	// x-FuSa spec §9.2 MUST: coveragePct must never exceed 100. The fallback
	// above already guarantees total >= AssetsAnalyzed (so this can't
	// currently trigger), but a defensive clamp is cheap insurance against a
	// future change to the fallback logic silently reintroducing the
	// overflow the spec calls out.
	//
	//fusa:req REQ-TARA011
	if s.CoveragePct > 100 {
		s.CoveragePct = 100
	}
	s.AssetInventoryMethod = "every non-test .go source file in the project (excluding vendor/testdata/dot-directories) " +
		"is treated as one candidate asset (CountProjectFiles); assetsAnalyzed counts the distinct files that ended up " +
		"with at least one CYBER-derived threat entry — this is file-level granularity, not a deeper per-symbol or " +
		"per-data-flow asset model"
	return s
}

// CountProjectFiles returns the total count of non-test .go source files
// under root (excluding vendor/, testdata/, and dot-directories) — the §9.2
// tara `coveragePct` denominator (assetsInProject). See buildSummary and
// Summary.AssetInventoryMethod for the file-level-granularity caveat. The
// test-tree/dot-directory exclusion reuses trace.IsExcludedDir (x-FuSa spec
// §1.6 rule 4 SHOULD) rather than an independently-drifting copy of the
// same three-way vendor/testdata/dot-dir check.
//
//fusa:req REQ-TARA008
func CountProjectFiles(root string) (int, error) {
	total := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if path != root && trace.IsExcludedDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go") {
			total++
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("tara: count project files: %w", err)
	}
	return total, nil
}

// LoadReport reads a persisted TARA report from path (typically tara.json).
//
//fusa:req REQ-TARA009
func LoadReport(path string) (*Report, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r Report
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("%w: %s: %s", fusa.ErrInvalidConfig, path, err)
	}
	return &r, nil
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
	fmt.Fprintf(w, "**Standard:** ISO/SAE 21434:2021 Clause 15  \n")
	fmt.Fprintf(w, "**Coverage:** %d / %d assets (%.1f%%)\n\n", r.Summary.AssetsAnalyzed, r.Summary.AssetsInProject, r.Summary.CoveragePct)
	fmt.Fprintf(w, "| ID | Asset | Threat | STRIDE | CWE | Vector | Feasibility | Impact (S/F/O/P) | Risk | Treatment | SL | Mitigation |\n")
	fmt.Fprintf(w, "|---|---|---|---|---|---|---|---|---|---|---|---|\n")
	for _, e := range r.Entries {
		fmt.Fprintf(w, "| %s | %s | %s | %s | %s | %s | %s | %s/%s/%s/%s | %s | %s | %d | %s |\n",
			e.ID,
			e.Asset,
			e.Threat,
			strings.Join(e.STRIDE, "/"),
			e.CWE,
			e.AttackVector,
			e.AttackFeasibility,
			e.Impact.Safety, e.Impact.Financial, e.Impact.Operational, e.Impact.Privacy,
			e.Risk,
			e.Treatment,
			e.SecurityLevel,
			strings.Join(e.Mitigations, "; "),
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
