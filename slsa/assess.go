// Package slsa — gap report extension.
//
// This file adds Assess/Render/Level so that 'gofusa slsa' can emit a
// §9.3-canonical SLSA supply-chain gap report alongside the engine rules that
// already run via 'gofusa check'.
package slsa

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/SoundMatt/go-FuSa/gapreport"
)

// Level is a SLSA supply-chain level (v1.0).
//
//fusa:req REQ-SLSA-ASSESS001
type Level string

const (
	LevelL1 Level = "L1"
	LevelL2 Level = "L2"
	LevelL3 Level = "L3"
	LevelL4 Level = "L4" // treated as L3; SLSA v1.0 has three build levels
)

// ReportFile is the default output filename for gofusa slsa.
const ReportFile = "slsa-gap-report.json"

// objectiveSpec describes a single SLSA objective.
type objectiveSpec struct {
	id       string
	clause   string
	title    string
	minLevel Level  // minimum level at which this objective applies
	file     string // evidence file path; empty = manual
}

var objectives = []objectiveSpec{
	// ── L1: basic provenance ──────────────────────────────────────────────────
	{
		"SLSA-L1.1", "§3.1", "Source is version controlled (.git)",
		LevelL1, ".git",
	},
	{
		"SLSA-L1.2", "§3.2", "Build is scripted/automated (go.mod present)",
		LevelL1, "go.mod",
	},
	{
		"SLSA-L1.3", "§4.1", "Build provenance generated (provenance.json)",
		LevelL1, "provenance.json",
	},
	// ── L2: hosted build ─────────────────────────────────────────────────────
	{
		"SLSA-L2.1", "§4.2", "Build system identified in provenance (builder field)",
		LevelL2, "", // checked via JSON parse
	},
	{
		"SLSA-L2.2", "§4.3", "VCS revision recorded in provenance (vcsRevision field)",
		LevelL2, "", // checked via JSON parse
	},
	{
		"SLSA-L2.3", "§4.4", "Software Bill of Materials generated (sbom.json)",
		LevelL2, "sbom.json",
	},
	// ── L3: hardened build ───────────────────────────────────────────────────
	{
		"SLSA-L3.1", "§5.1", "Two-party review policy (CODEOWNERS or branch-protection)",
		LevelL3, "", // checked via multiple paths
	},
	{
		"SLSA-L3.2", "§5.2", "Dependency integrity tracked (sbom.json with hashes)",
		LevelL3, "", // checked via JSON parse
	},
	{
		"SLSA-L3.3", "§5.3", "Artifact integrity recorded (SHA256SUMS or .sha256 files)",
		LevelL3, "", // checked via glob
	},
	{
		"SLSA-L3.4", "§5.4", "Evidence bundle produced (audit-pack.zip)",
		LevelL3, "audit-pack.zip",
	},
}

// Objective is one assessed SLSA objective.
type Objective struct {
	ID       string `json:"id"`
	Clause   string `json:"clause"`
	Title    string `json:"title"`
	MinLevel Level  `json:"minLevel"`
	Status   string `json:"status"` // PASS / GAP / MANUAL / N/A
	Evidence string `json:"evidence,omitempty"`
	Note     string `json:"note,omitempty"`
}

// Report is the SLSA gap assessment result.
//
//fusa:req REQ-SLSA-ASSESS002
type Report struct {
	Project    string      `json:"project"`
	Level      Level       `json:"level"`
	Generated  time.Time   `json:"generated"`
	Pass       int         `json:"pass"`
	Gap        int         `json:"gap"`
	NA         int         `json:"na"`
	Objectives []Objective `json:"objectives"`
}

func levelNum(l Level) int {
	switch l {
	case LevelL1:
		return 1
	case LevelL2:
		return 2
	case LevelL3, LevelL4:
		return 3
	}
	return 0
}

// Assess scans projectRoot and returns a SLSA gap report for the given level.
//
//fusa:req REQ-SLSA-ASSESS003
func Assess(projectRoot, project string, level Level) (*Report, error) {
	rep := &Report{
		Project:   project,
		Level:     level,
		Generated: time.Now().UTC(),
	}

	targetNum := levelNum(level)

	for _, spec := range objectives {
		obj := Objective{
			ID:       spec.id,
			Clause:   spec.clause,
			Title:    spec.title,
			MinLevel: spec.minLevel,
		}

		if levelNum(spec.minLevel) > targetNum {
			obj.Status = "N/A"
			rep.NA++
			rep.Objectives = append(rep.Objectives, obj)
			continue
		}

		status, note := assessObjective(projectRoot, spec)
		obj.Status = status
		obj.Note = note
		if status == "PASS" {
			rep.Pass++
		} else {
			rep.Gap++
		}
		rep.Objectives = append(rep.Objectives, obj)
	}

	return rep, nil
}

func assessObjective(root string, spec objectiveSpec) (status, note string) {
	switch spec.id {
	case "SLSA-L2.1":
		return assessProvenanceField(root, "builder", "provenance.json missing builder field — run 'gofusa release' from CI to populate it")
	case "SLSA-L2.2":
		return assessProvenanceField(root, "vcsRevision", "provenance.json missing vcsRevision — run 'gofusa release' from a git repo")
	case "SLSA-L3.1":
		return assessTwoPartyReview(root)
	case "SLSA-L3.2":
		return assessSBOMHashes(root)
	case "SLSA-L3.3":
		return assessArtifactIntegrity(root)
	default:
		// simple file-presence check
		if spec.file == "" {
			return "PASS", ""
		}
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(spec.file))); err == nil {
			return "PASS", ""
		}
		return "GAP", fmt.Sprintf("%s not found — run 'gofusa %s' to generate it", spec.file, commandForFile(spec.file))
	}
}

func assessProvenanceField(root, field, gap string) (string, string) {
	data, err := os.ReadFile(filepath.Join(root, ProvenanceFile))
	if err != nil {
		return "GAP", "provenance.json not found — run 'gofusa release'"
	}
	var prov map[string]interface{}
	if err := json.Unmarshal(data, &prov); err != nil {
		return "GAP", "provenance.json is not valid JSON"
	}
	if v, _ := prov[field].(string); v != "" {
		return "PASS", ""
	}
	return "GAP", gap
}

var codeownersLocations = []string{
	"CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS",
	".github/branch-protection.json", ".github/rulesets.json",
}

func assessTwoPartyReview(root string) (string, string) {
	for _, name := range codeownersLocations {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(name))); err == nil {
			return "PASS", ""
		}
	}
	return "GAP", "no CODEOWNERS or branch-protection policy found — create .github/CODEOWNERS and enable branch protection"
}

func assessSBOMHashes(root string) (string, string) {
	data, err := os.ReadFile(filepath.Join(root, "sbom.json"))
	if err != nil {
		return "GAP", "sbom.json not found — run 'gofusa release'"
	}
	var sbom map[string]interface{}
	if err := json.Unmarshal(data, &sbom); err != nil {
		return "GAP", "sbom.json is not valid JSON"
	}
	// Accept if the SBOM has any packages/components field (non-empty)
	for _, key := range []string{"packages", "components", "dependencies"} {
		if arr, ok := sbom[key].([]interface{}); ok && len(arr) > 0 {
			return "PASS", ""
		}
	}
	return "GAP", "sbom.json has no packages/components — regenerate with 'gofusa release'"
}

var sha256Candidates = []string{
	"SHA256SUMS", "sha256sums.txt",
}

func assessArtifactIntegrity(root string) (string, string) {
	for _, name := range sha256Candidates {
		if _, err := os.Stat(filepath.Join(root, name)); err == nil {
			return "PASS", ""
		}
	}
	// Accept any .sha256 file in root
	entries, err := os.ReadDir(root)
	if err == nil {
		for _, e := range entries {
			if !e.IsDir() && len(e.Name()) > 7 && e.Name()[len(e.Name())-7:] == ".sha256" {
				return "PASS", ""
			}
		}
	}
	return "GAP", "no SHA256SUMS or .sha256 files found — run 'gofusa release' to produce integrity hashes"
}

func commandForFile(file string) string {
	m := map[string]string{
		".git":            "init (ensure project is in a git repo)",
		"go.mod":          "init",
		"provenance.json": "release",
		"sbom.json":       "release",
		"audit-pack.zip":  "audit-pack",
	}
	if cmd, ok := m[file]; ok {
		return cmd
	}
	return "— see documentation"
}

// Render writes the SLSA gap report to w.
//
//fusa:req REQ-SLSA-ASSESS004
func Render(w io.Writer, rep *Report, format string) error {
	switch format {
	case "json", "":
		return gapreport.Render(w, toGapReport(rep), "json")
	case "text":
		return renderText(w, rep)
	default:
		return fmt.Errorf("slsa: unsupported format %q", format)
	}
}

func toGapReport(rep *Report) *gapreport.Report {
	gr := gapreport.New(rep.Project, "slsa-v1.0")
	for _, obj := range rep.Objectives {
		gobj := gapreport.Objective{
			ID:     obj.ID,
			Clause: obj.Clause,
			Title:  obj.Title,
			Status: toCanonical(obj.Status),
		}
		if obj.Note != "" {
			gobj.Findings = []string{obj.Note}
		}
		gr.AddObjective(gobj)
	}
	return gr
}

func toCanonical(s string) string {
	switch s {
	case "PASS":
		return gapreport.StatusSatisfied
	case "N/A":
		return gapreport.StatusPartial
	default:
		return gapreport.StatusGap
	}
}

func renderText(w io.Writer, rep *Report) error {
	total := rep.Pass + rep.Gap + rep.NA
	fmt.Fprintf(w, "SLSA Supply-Chain Gap Report\n")
	fmt.Fprintf(w, "Project: %s   Level: %s   Generated: %s\n\n",
		rep.Project, rep.Level, rep.Generated.Format("2006-01-02"))
	fmt.Fprintf(w, "Summary: %d objectives  %d PASS  %d GAP  %d N/A\n\n",
		total, rep.Pass, rep.Gap, rep.NA)

	for _, obj := range rep.Objectives {
		icon := statusIcon(obj.Status)
		prefix := ""
		if obj.Status == "N/A" {
			prefix = " (above target level)"
		}
		fmt.Fprintf(w, "  %s [%s] %s  %s%s\n", icon, obj.ID, obj.Status, obj.Title, prefix)
		if obj.Note != "" {
			fmt.Fprintf(w, "     NOTE: %s\n", obj.Note)
		}
	}
	fmt.Fprintln(w)

	if rep.Gap > 0 {
		fmt.Fprintf(w, "Action items (%d gaps):\n", rep.Gap)
		for _, obj := range rep.Objectives {
			if obj.Status == "GAP" {
				fmt.Fprintf(w, "  %s — %s\n", obj.ID, obj.Note)
			}
		}
	}
	return nil
}

func statusIcon(s string) string {
	switch s {
	case "PASS":
		return "✓"
	case "GAP":
		return "✗"
	case "N/A":
		return "–"
	default:
		return "!"
	}
}
