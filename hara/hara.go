// Package hara manages Hazard Analysis and Risk Assessment (HARA) data for
// go-FuSa projects.
//
// A HARA captures operational situations, hazards, ASIL-rated risk assessments,
// and safety goals in a structured JSON file (.fusa-hara.json). ASIL is derived
// automatically from Severity, Exposure, and Controllability per ISO 26262-3:2018
// Table 4.
//
// Engine rules:
//   - HARA001: no .fusa-hara.json found
//   - HARA002: hazard with incomplete risk rating (S/E/C not all set)
//   - HARA003: hazard with no linked safety goal
//   - HARA004: safety goal with ASIL not determined
//   - HARA005: max hazard ASIL exceeds project ASIL from .fusa.json
//   - HARA006: safety goal with no fssrRefs (x-FuSa spec §1.2.5 MUST)
//   - HARA007: fssrRefs entry dangling (no matching id in .fusa-reqs.json)
//   - HARA008: hazard's stored risk.asil disagrees with DetermineASIL(S,E,C)
//
// Usage:
//
//	h, err := hara.Load(projectRoot)
//	report, _ := hara.Validate(h)
//	_ = hara.Render(os.Stdout, h, "text")
package hara

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/config"
	"github.com/SoundMatt/go-FuSa/engine"
	"github.com/SoundMatt/go-FuSa/trace"
)

// HARAFile is the default filename for the HARA data store.
const HARAFile = ".fusa-hara.json"

// Severity is the harm severity class (ISO 26262-3:2018 §6.4.3).
type Severity string

const (
	SeverityS0 Severity = "S0" // No injuries
	SeverityS1 Severity = "S1" // Light and moderate injuries
	SeverityS2 Severity = "S2" // Severe and life-threatening injuries (survival probable)
	SeverityS3 Severity = "S3" // Life-threatening injuries (survival uncertain), fatal
)

// Exposure is the probability of the operational situation (ISO 26262-3:2018 §6.4.4).
type Exposure string

const (
	ExposureE0 Exposure = "E0" // Incredible
	ExposureE1 Exposure = "E1" // Very low probability
	ExposureE2 Exposure = "E2" // Low probability
	ExposureE3 Exposure = "E3" // Medium probability
	ExposureE4 Exposure = "E4" // High probability
)

// Controllability is the ability to avoid harm (ISO 26262-3:2018 §6.4.5).
type Controllability string

const (
	ControllabilityC0 Controllability = "C0" // Controllable in general
	ControllabilityC1 Controllability = "C1" // Simply controllable
	ControllabilityC2 Controllability = "C2" // Normally controllable
	ControllabilityC3 Controllability = "C3" // Difficult to control or uncontrollable
)

// ASIL is the Automotive Safety Integrity Level (ISO 26262-1:2018 §3.6).
type ASIL string

const (
	ASILQM ASIL = "QM" // Quality Management — no ASIL required
	ASILA  ASIL = "ASIL-A"
	ASILB  ASIL = "ASIL-B"
	ASILC  ASIL = "ASIL-C"
	ASILD  ASIL = "ASIL-D"
)

// RiskRating holds the three ISO 26262-3 classification parameters and the
// derived ASIL.
//
//fusa:req REQ-HARA001
type RiskRating struct {
	Severity        Severity        `json:"severity"`
	Exposure        Exposure        `json:"exposure"`
	Controllability Controllability `json:"controllability"`
	ASIL            ASIL            `json:"asil"`
}

// OperationalSituation describes a scenario in which a hazard can manifest.
//
//fusa:req REQ-HARA002
type OperationalSituation struct {
	ID          string `json:"id"`
	Description string `json:"description"`
}

// Hazard describes a potential source of harm.
//
//fusa:req REQ-HARA003
type Hazard struct {
	ID          string     `json:"id"`
	Description string     `json:"description"`
	Source      string     `json:"source,omitempty"`
	Situations  []string   `json:"situations"` // OperationalSituation IDs
	Risk        RiskRating `json:"risk"`
	SafetyGoals []string   `json:"safetyGoals"` // SafetyGoal IDs
}

// SafetyGoal is a top-level safety requirement derived from one or more hazards.
//
//fusa:req REQ-HARA004
type SafetyGoal struct {
	ID          string   `json:"id"`
	Description string   `json:"description"`
	HazardIDs   []string `json:"hazards"`
	ASIL        ASIL     `json:"asil"`
	SafeState   string   `json:"safeState,omitempty"`
	// FSSRRefs links the Functional Safety Software Requirement(s) into
	// .fusa-reqs.json that decompose this goal. x-FuSa spec §1.2.5: MUST,
	// ≥1 entry — a safety goal with no decomposing requirement is exactly
	// the traceability gap ISO 26262-8 Clause 6 exists to prevent.
	//
	//fusa:req REQ-HARA016
	FSSRRefs []string `json:"fssrRefs"`
}

// HARA is the full hazard analysis and risk assessment for a project.
//
//fusa:req REQ-HARA005
type HARA struct {
	Project string `json:"project"`
	// Standard is the x-FuSa spec §2.4.1 canonical lowercase standard id
	// ("iso26262", "iec61508", …) — never a display string. Load normalises
	// a legacy display-string value (e.g. "ISO 26262") onto its canonical
	// id for backward compatibility with hand-authored files predating this
	// convention; see normalizeStandard.
	Standard    string                 `json:"standard"`
	CreatedAt   time.Time              `json:"createdAt"`
	Situations  []OperationalSituation `json:"operationalSituations"`
	Hazards     []Hazard               `json:"hazards"`
	SafetyGoals []SafetyGoal           `json:"safetyGoals"`
	// Attestation is the optional §1.6.2 independent-review assertion that
	// can suppress a FUSA-STUB002 (blanket-fallback) finding on this file.
	Attestation *fusa.Attestation `json:"attestation,omitempty"`
}

// Completeness summarises §1.2.5/§9.2 gap metrics for a hara --format json
// report — it is not itself part of .fusa-hara.json, it is computed by
// BuildCompleteness at render time.
//
//fusa:req REQ-HARA017
type Completeness struct {
	TotalHazards            int `json:"totalHazards"`
	HazardsWithASIL         int `json:"hazardsWithAsil"`
	HazardsWithSafetyGoal   int `json:"hazardsWithSafetyGoal"`
	TotalSafetyGoals        int `json:"totalSafetyGoals"`
	SafetyGoalsWithFssrRefs int `json:"safetyGoalsWithFssrRefs"`
	DanglingReferences      int `json:"danglingReferences"`
}

// ValidationFinding is a gap identified by Validate.
type ValidationFinding struct {
	HazardID     string
	SafetyGoalID string
	Message      string
}

// BuildCompleteness computes the §9.2 `hara --format json` completeness
// block. reqIDs is the set of requirement ids known to the project's
// .fusa-reqs.json (pass nil/empty to skip fssrRefs dangling-reference
// checking against it — every fssrRef then counts as dangling, fail-safe).
//
//fusa:req REQ-HARA017
func BuildCompleteness(h *HARA, reqIDs map[string]bool) Completeness {
	goalIDs := make(map[string]bool, len(h.SafetyGoals))
	for _, g := range h.SafetyGoals {
		goalIDs[g.ID] = true
	}
	situationIDs := make(map[string]bool, len(h.Situations))
	for _, s := range h.Situations {
		situationIDs[s.ID] = true
	}
	hazardIDs := make(map[string]bool, len(h.Hazards))
	for _, hz := range h.Hazards {
		hazardIDs[hz.ID] = true
	}

	c := Completeness{
		TotalHazards:     len(h.Hazards),
		TotalSafetyGoals: len(h.SafetyGoals),
	}
	for _, hz := range h.Hazards {
		if hz.Risk.ASIL != "" {
			c.HazardsWithASIL++
		}
		if len(hz.SafetyGoals) > 0 {
			c.HazardsWithSafetyGoal++
		}
		for _, s := range hz.Situations {
			if !situationIDs[s] {
				c.DanglingReferences++
			}
		}
		for _, g := range hz.SafetyGoals {
			if !goalIDs[g] {
				c.DanglingReferences++
			}
		}
	}
	for _, g := range h.SafetyGoals {
		if len(g.FSSRRefs) > 0 {
			c.SafetyGoalsWithFssrRefs++
		}
		for _, id := range g.FSSRRefs {
			if !reqIDs[id] {
				c.DanglingReferences++
			}
		}
		for _, hzID := range g.HazardIDs {
			if !hazardIDs[hzID] {
				c.DanglingReferences++
			}
		}
	}
	return c
}

// ─── ASIL determination ───────────────────────────────────────────────────────

// DetermineASIL derives the ASIL from S, E, C per ISO 26262-3:2018 Table 4.
//
//fusa:req REQ-HARA006
func DetermineASIL(s Severity, e Exposure, c Controllability) ASIL {
	// S0 always QM
	if s == SeverityS0 || s == "" {
		return ASILQM
	}
	// E0 always QM
	if e == ExposureE0 || e == "" {
		return ASILQM
	}

	type key struct {
		s Severity
		e Exposure
		c Controllability
	}
	table := map[key]ASIL{
		// S1
		{SeverityS1, ExposureE1, ControllabilityC0}: ASILQM,
		{SeverityS1, ExposureE1, ControllabilityC1}: ASILQM,
		{SeverityS1, ExposureE1, ControllabilityC2}: ASILQM,
		{SeverityS1, ExposureE1, ControllabilityC3}: ASILQM,
		{SeverityS1, ExposureE2, ControllabilityC0}: ASILQM,
		{SeverityS1, ExposureE2, ControllabilityC1}: ASILQM,
		{SeverityS1, ExposureE2, ControllabilityC2}: ASILQM,
		{SeverityS1, ExposureE2, ControllabilityC3}: ASILQM,
		{SeverityS1, ExposureE3, ControllabilityC0}: ASILQM,
		{SeverityS1, ExposureE3, ControllabilityC1}: ASILQM,
		{SeverityS1, ExposureE3, ControllabilityC2}: ASILQM,
		{SeverityS1, ExposureE3, ControllabilityC3}: ASILA,
		{SeverityS1, ExposureE4, ControllabilityC0}: ASILQM,
		{SeverityS1, ExposureE4, ControllabilityC1}: ASILQM,
		{SeverityS1, ExposureE4, ControllabilityC2}: ASILA,
		{SeverityS1, ExposureE4, ControllabilityC3}: ASILB,
		// S2
		{SeverityS2, ExposureE1, ControllabilityC0}: ASILQM,
		{SeverityS2, ExposureE1, ControllabilityC1}: ASILQM,
		{SeverityS2, ExposureE1, ControllabilityC2}: ASILQM,
		{SeverityS2, ExposureE1, ControllabilityC3}: ASILQM,
		{SeverityS2, ExposureE2, ControllabilityC0}: ASILQM,
		{SeverityS2, ExposureE2, ControllabilityC1}: ASILQM,
		{SeverityS2, ExposureE2, ControllabilityC2}: ASILA,
		{SeverityS2, ExposureE2, ControllabilityC3}: ASILB,
		{SeverityS2, ExposureE3, ControllabilityC0}: ASILQM,
		{SeverityS2, ExposureE3, ControllabilityC1}: ASILA,
		{SeverityS2, ExposureE3, ControllabilityC2}: ASILB,
		{SeverityS2, ExposureE3, ControllabilityC3}: ASILC,
		{SeverityS2, ExposureE4, ControllabilityC0}: ASILA,
		{SeverityS2, ExposureE4, ControllabilityC1}: ASILB,
		{SeverityS2, ExposureE4, ControllabilityC2}: ASILC,
		{SeverityS2, ExposureE4, ControllabilityC3}: ASILD,
		// S3
		{SeverityS3, ExposureE1, ControllabilityC0}: ASILQM,
		{SeverityS3, ExposureE1, ControllabilityC1}: ASILA,
		{SeverityS3, ExposureE1, ControllabilityC2}: ASILB,
		{SeverityS3, ExposureE1, ControllabilityC3}: ASILC,
		{SeverityS3, ExposureE2, ControllabilityC0}: ASILA,
		{SeverityS3, ExposureE2, ControllabilityC1}: ASILB,
		{SeverityS3, ExposureE2, ControllabilityC2}: ASILC,
		{SeverityS3, ExposureE2, ControllabilityC3}: ASILD,
		{SeverityS3, ExposureE3, ControllabilityC0}: ASILB,
		{SeverityS3, ExposureE3, ControllabilityC1}: ASILC,
		{SeverityS3, ExposureE3, ControllabilityC2}: ASILD,
		{SeverityS3, ExposureE3, ControllabilityC3}: ASILD,
		{SeverityS3, ExposureE4, ControllabilityC0}: ASILC,
		{SeverityS3, ExposureE4, ControllabilityC1}: ASILD,
		{SeverityS3, ExposureE4, ControllabilityC2}: ASILD,
		{SeverityS3, ExposureE4, ControllabilityC3}: ASILD,
	}
	if a, ok := table[key{s, e, c}]; ok {
		return a
	}
	return ASILQM
}

// ─── Load / Save ──────────────────────────────────────────────────────────────

// Load reads the HARA from projectRoot/.fusa-hara.json. Returns an empty HARA
// if the file does not exist.
//
//fusa:req REQ-HARA007
func Load(projectRoot string) (*HARA, error) {
	path := filepath.Join(projectRoot, HARAFile)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &HARA{}, nil
		}
		return nil, fmt.Errorf("hara: read %s: %w", HARAFile, err)
	}
	var h HARA
	if err := json.Unmarshal(data, &h); err != nil {
		return nil, fmt.Errorf("%w: %s: %s", fusa.ErrInvalidConfig, HARAFile, err)
	}
	h.Standard = normalizeStandard(h.Standard)
	return &h, nil
}

// normalizeStandard maps a legacy display-string standard value (e.g.
// "ISO 26262", as written by hara init before this normalisation existed)
// onto the x-FuSa spec §2.4.1 canonical lowercase id (e.g. "iso26262"), for
// backward compatibility with hand-authored/older .fusa-hara.json files. An
// empty value, an id that already looks canonical, or one go-FuSa does not
// recognise is returned unchanged — §2.4.1: an unrecognised id MUST be
// treated verbatim, never rejected.
//
//fusa:req REQ-HARA025
func normalizeStandard(s string) string {
	switch strings.ToLower(strings.Join(strings.Fields(s), " ")) {
	case "iso 26262", "iso26262":
		return "iso26262"
	case "iec 61508", "iec61508":
		return "iec61508"
	case "iso 21434", "iso21434":
		return "iso21434"
	case "do-178c", "do 178c", "do178c":
		return "do178c"
	default:
		return s
	}
}

// Save writes the HARA to path.
//
//fusa:req REQ-HARA008
func Save(path string, h *HARA) error {
	data, err := json.MarshalIndent(h, "", "  ")
	if err != nil {
		return fmt.Errorf("hara: marshal: %w", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o640); err != nil {
		return fmt.Errorf("hara: write %s: %w", path, err)
	}
	return nil
}

// ─── Validate ─────────────────────────────────────────────────────────────────

// Validate checks the HARA for completeness gaps.
//
//fusa:req REQ-HARA009
func Validate(h *HARA) []ValidationFinding {
	goalIDs := make(map[string]bool)
	for _, g := range h.SafetyGoals {
		goalIDs[g.ID] = true
	}

	var out []ValidationFinding

	for _, hz := range h.Hazards {
		// HARA002: incomplete risk rating
		if hz.Risk.Severity == "" || hz.Risk.Exposure == "" || hz.Risk.Controllability == "" {
			out = append(out, ValidationFinding{
				HazardID: hz.ID,
				Message:  fmt.Sprintf("hazard %s has incomplete risk rating — S, E, and C must all be set", hz.ID),
			})
		}
		// HARA003: no safety goal linked
		if len(hz.SafetyGoals) == 0 {
			out = append(out, ValidationFinding{
				HazardID: hz.ID,
				Message:  fmt.Sprintf("hazard %s has no linked safety goal", hz.ID),
			})
		}
		// Check referenced goals exist
		for _, gid := range hz.SafetyGoals {
			if !goalIDs[gid] {
				out = append(out, ValidationFinding{
					HazardID: hz.ID,
					Message:  fmt.Sprintf("hazard %s references unknown safety goal %s", hz.ID, gid),
				})
			}
		}
	}

	for _, g := range h.SafetyGoals {
		// HARA004: ASIL not determined
		if g.ASIL == "" {
			out = append(out, ValidationFinding{
				SafetyGoalID: g.ID,
				Message:      fmt.Sprintf("safety goal %s has no ASIL assigned", g.ID),
			})
		}
		// HARA006: fssrRefs is MUST, >=1 entry (x-FuSa spec §1.2.5).
		if len(g.FSSRRefs) == 0 {
			out = append(out, ValidationFinding{
				SafetyGoalID: g.ID,
				Message:      fmt.Sprintf("safety goal %s has no fssrRefs — every safety goal MUST decompose into at least one functional safety requirement", g.ID),
			})
		}
	}

	// HARA008: a hazard's declared risk.asil must match its own S/E/C rating
	// (x-FuSa spec §1.2.5 MUST — see ValidateASIL doc).
	out = append(out, ValidateASIL(h)...)

	return out
}

// ValidateReqRefs checks h's safetyGoals[].fssrRefs for dangling references
// into the project's requirement registry (x-FuSa spec §1.2.5 referential
// integrity rule). reqIDs is the set of requirement ids known to
// .fusa-reqs.json; pass nil to skip this check.
//
//fusa:req REQ-HARA018
func ValidateReqRefs(h *HARA, reqIDs map[string]bool) []ValidationFinding {
	if reqIDs == nil {
		return nil
	}
	var out []ValidationFinding
	for _, g := range h.SafetyGoals {
		for _, id := range g.FSSRRefs {
			if !reqIDs[id] {
				out = append(out, ValidationFinding{
					SafetyGoalID: g.ID,
					Message:      fmt.Sprintf("safety goal %s references unknown requirement %s in fssrRefs — add it to .fusa-reqs.json", g.ID, id),
				})
			}
		}
	}
	return out
}

// Report is the x-FuSa spec §9.2 `hara --format json` document: the §3.1
// common header plus .fusa-hara.json's content verbatim plus a completeness
// block. It is distinct from HARA itself — HARA is the input file
// (.fusa-hara.json); Report is what the `hara` command emits when asked for
// JSON, so a future consumer can route on schemaVersion/kind without
// depending on whether the on-disk input file happens to carry the same
// envelope (it doesn't — that file is authored by the project, not go-FuSa).
//
//fusa:req REQ-HARA021
type Report struct {
	SchemaVersion string    `json:"schemaVersion"`
	Kind          string    `json:"kind"`
	Tool          string    `json:"tool"`
	ToolVersion   string    `json:"toolVersion"`
	Language      string    `json:"language"`
	GeneratedAt   time.Time `json:"generatedAt"`

	// Project/Standard are informational passthrough from HARA, not part of
	// the minimal §9.2 example shape but useful to a human/tool reading the
	// report in isolation.
	Project  string `json:"project,omitempty"`
	Standard string `json:"standard,omitempty"`

	OperationalSituations []OperationalSituation `json:"operationalSituations"`
	Hazards               []Hazard               `json:"hazards"`
	SafetyGoals           []SafetyGoal           `json:"safetyGoals"`
	Completeness          Completeness           `json:"completeness"`
	Attestation           *fusa.Attestation      `json:"attestation,omitempty"`
}

// BuildReport assembles the §9.2 hara --format json document from h.
// reqIDs is passed through to BuildCompleteness (see its doc).
//
//fusa:req REQ-HARA021
func BuildReport(h *HARA, reqIDs map[string]bool) *Report {
	return &Report{
		SchemaVersion:         fusa.SchemaVersion(),
		Kind:                  "hara-report",
		Tool:                  "go-FuSa",
		ToolVersion:           fusa.Version,
		Language:              "go",
		GeneratedAt:           time.Now().UTC(),
		Project:               h.Project,
		Standard:              h.Standard,
		OperationalSituations: h.Situations,
		Hazards:               h.Hazards,
		SafetyGoals:           h.SafetyGoals,
		Completeness:          BuildCompleteness(h, reqIDs),
		Attestation:           h.Attestation,
	}
}

// ─── Render ───────────────────────────────────────────────────────────────────

// Render writes the HARA to w in text, json, or markdown format.
//
//fusa:req REQ-HARA010
func Render(w io.Writer, h *HARA, format string) error {
	switch format {
	case "json", "":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(h)
	case "text", "markdown":
		return renderText(w, h)
	default:
		return fmt.Errorf("hara: unsupported format %q", format)
	}
}

func renderText(w io.Writer, h *HARA) error {
	fmt.Fprintf(w, "# Hazard Analysis and Risk Assessment (HARA)\n\n")
	fmt.Fprintf(w, "Project: %s  Standard: %s\n\n", h.Project, h.Standard)

	fmt.Fprintf(w, "## Operational Situations (%d)\n\n", len(h.Situations))
	fmt.Fprintf(w, "| ID | Description |\n|---|---|\n")
	for _, s := range h.Situations {
		fmt.Fprintf(w, "| %s | %s |\n", s.ID, s.Description)
	}
	fmt.Fprintln(w)

	fmt.Fprintf(w, "## Hazards (%d)\n\n", len(h.Hazards))
	fmt.Fprintf(w, "| ID | Description | S | E | C | ASIL | Safety Goals |\n|---|---|---|---|---|---|---|\n")
	for _, hz := range h.Hazards {
		asil := hz.Risk.ASIL
		if asil == "" {
			asil = DetermineASIL(hz.Risk.Severity, hz.Risk.Exposure, hz.Risk.Controllability)
		}
		goals := ""
		for i, g := range hz.SafetyGoals {
			if i > 0 {
				goals += ", "
			}
			goals += g
		}
		fmt.Fprintf(w, "| %s | %s | %s | %s | %s | **%s** | %s |\n",
			hz.ID, hz.Description,
			hz.Risk.Severity, hz.Risk.Exposure, hz.Risk.Controllability,
			asil, goals)
	}
	fmt.Fprintln(w)

	fmt.Fprintf(w, "## Safety Goals (%d)\n\n", len(h.SafetyGoals))
	fmt.Fprintf(w, "| ID | Description | ASIL | Safe State | FSSR Refs |\n|---|---|---|---|---|\n")
	for _, g := range h.SafetyGoals {
		fmt.Fprintf(w, "| %s | %s | **%s** | %s | %s |\n", g.ID, g.Description, g.ASIL, g.SafeState, strings.Join(g.FSSRRefs, ", "))
	}
	fmt.Fprintln(w)

	findings := Validate(h)
	if len(findings) > 0 {
		fmt.Fprintf(w, "## Gaps (%d)\n\n", len(findings))
		for _, f := range findings {
			fmt.Fprintf(w, "- %s\n", f.Message)
		}
		fmt.Fprintln(w)
	}

	return nil
}

// ─── Engine rules ─────────────────────────────────────────────────────────────

func init() {
	engine.Default.MustRegister(&ruleHARA001{})
	engine.Default.MustRegister(&ruleHARA002{})
	engine.Default.MustRegister(&ruleHARA003{})
	engine.Default.MustRegister(&ruleHARA004{})
	engine.Default.MustRegister(&ruleHARA005{})
	engine.Default.MustRegister(&ruleHARA006{})
	engine.Default.MustRegister(&ruleHARA007{})
	engine.Default.MustRegister(&ruleHARA008{})
}

// HARA001 — no HARA file present.
type ruleHARA001 struct{}

func (r *ruleHARA001) ID() string { return "HARA001" }
func (r *ruleHARA001) Description() string {
	return "No .fusa-hara.json found — hazard analysis is required for ISO 26262 projects."
}

//fusa:req REQ-HARA011
func (r *ruleHARA001) Run(_ context.Context, projectRoot string, cfg *config.Config) ([]fusa.Finding, error) {
	_, err := os.Stat(filepath.Join(projectRoot, HARAFile))
	if err == nil {
		return nil, nil
	}
	sev := fusa.SeverityInfo
	if cfg != nil && (cfg.Project.Standard == "ISO26262" || cfg.Project.Standard == "IEC61508") {
		sev = fusa.SeverityWarning
	}
	return []fusa.Finding{{
		RuleID:      r.ID(),
		Severity:    sev,
		Message:     HARAFile + " not found — hazard analysis evidence is absent",
		Location:    fusa.Location{File: HARAFile},
		Remediation: "run 'gofusa hara init' to create a starter " + HARAFile,
	}}, nil
}

// HARA002 — hazard with incomplete S/E/C.
type ruleHARA002 struct{}

func (r *ruleHARA002) ID() string { return "HARA002" }
func (r *ruleHARA002) Description() string {
	return "Hazard has incomplete risk rating — Severity, Exposure, and Controllability must all be set."
}

//fusa:req REQ-HARA012
func (r *ruleHARA002) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	h, err := Load(projectRoot)
	if err != nil || len(h.Hazards) == 0 {
		return nil, nil
	}
	var out []fusa.Finding
	for _, hz := range h.Hazards {
		if hz.Risk.Severity == "" || hz.Risk.Exposure == "" || hz.Risk.Controllability == "" {
			out = append(out, fusa.Finding{
				RuleID:      r.ID(),
				Severity:    fusa.SeverityWarning,
				Message:     fmt.Sprintf("hazard %s: incomplete risk rating (S=%q E=%q C=%q)", hz.ID, hz.Risk.Severity, hz.Risk.Exposure, hz.Risk.Controllability),
				Location:    fusa.Location{File: HARAFile},
				Remediation: fmt.Sprintf("set severity, exposure, and controllability for hazard %s in %s", hz.ID, HARAFile),
			})
		}
	}
	return out, nil
}

// HARA003 — hazard with no linked safety goal.
type ruleHARA003 struct{}

func (r *ruleHARA003) ID() string { return "HARA003" }
func (r *ruleHARA003) Description() string {
	return "Hazard has no linked safety goal — every hazard must be mitigated by at least one safety goal."
}

//fusa:req REQ-HARA013
func (r *ruleHARA003) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	h, err := Load(projectRoot)
	if err != nil || len(h.Hazards) == 0 {
		return nil, nil
	}
	var out []fusa.Finding
	for _, hz := range h.Hazards {
		if len(hz.SafetyGoals) == 0 {
			out = append(out, fusa.Finding{
				RuleID:      r.ID(),
				Severity:    fusa.SeverityWarning,
				Message:     fmt.Sprintf("hazard %s has no linked safety goal", hz.ID),
				Location:    fusa.Location{File: HARAFile},
				Remediation: fmt.Sprintf("add a safety goal for hazard %s in %s", hz.ID, HARAFile),
			})
		}
	}
	return out, nil
}

// HARA004 — safety goal without ASIL.
type ruleHARA004 struct{}

func (r *ruleHARA004) ID() string { return "HARA004" }
func (r *ruleHARA004) Description() string {
	return "Safety goal has no ASIL assigned — every safety goal must have an ASIL determined from the linked hazard."
}

//fusa:req REQ-HARA014
func (r *ruleHARA004) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	h, err := Load(projectRoot)
	if err != nil || len(h.SafetyGoals) == 0 {
		return nil, nil
	}
	var out []fusa.Finding
	for _, g := range h.SafetyGoals {
		if g.ASIL == "" {
			out = append(out, fusa.Finding{
				RuleID:      r.ID(),
				Severity:    fusa.SeverityWarning,
				Message:     fmt.Sprintf("safety goal %s has no ASIL assigned", g.ID),
				Location:    fusa.Location{File: HARAFile},
				Remediation: fmt.Sprintf("assign ASIL to safety goal %s using DetermineASIL or manually in %s", g.ID, HARAFile),
			})
		}
	}
	return out, nil
}

// HARA005 — max hazard ASIL exceeds project ASIL in .fusa.json.
type ruleHARA005 struct{}

func (r *ruleHARA005) ID() string { return "HARA005" }
func (r *ruleHARA005) Description() string {
	return "Highest hazard ASIL exceeds project ASIL declared in .fusa.json — project configuration understates risk."
}

//fusa:req REQ-HARA015
func (r *ruleHARA005) Run(_ context.Context, projectRoot string, cfg *config.Config) ([]fusa.Finding, error) {
	if cfg == nil || cfg.Project.ASIL == "" {
		return nil, nil
	}
	h, err := Load(projectRoot)
	if err != nil || len(h.Hazards) == 0 {
		return nil, nil
	}
	maxHazard := maxHazardASIL(h.Hazards)
	if maxHazard == "" || maxHazard == string(ASILQM) {
		return nil, nil
	}
	if asilRank(ASIL(maxHazard)) <= asilRank(ASIL(cfg.Project.ASIL)) {
		return nil, nil
	}
	return []fusa.Finding{{
		RuleID:   r.ID(),
		Severity: fusa.SeverityWarning,
		Message: fmt.Sprintf(
			"highest hazard ASIL is %s but project ASIL is %s — update .fusa.json asil field to match or exceed %s",
			maxHazard, cfg.Project.ASIL, maxHazard,
		),
		Location:    fusa.Location{File: HARAFile},
		Remediation: "set project.asil in .fusa.json to " + maxHazard + " or higher",
	}}, nil
}

func maxHazardASIL(hazards []Hazard) string {
	best := ""
	for _, hz := range hazards {
		a := string(hz.Risk.ASIL)
		if asilRank(ASIL(a)) > asilRank(ASIL(best)) {
			best = a
		}
	}
	return best
}

// asilRank maps ASIL to a comparable integer (QM=0, A=1, B=2, C=3, D=4).
func asilRank(a ASIL) int {
	switch a {
	case ASILQM:
		return 0
	case ASILA:
		return 1
	case ASILB:
		return 2
	case ASILC:
		return 3
	case ASILD:
		return 4
	}
	return -1
}

// HARA006 — safety goal with no fssrRefs (x-FuSa spec §1.2.5 MUST, ≥1 entry).
type ruleHARA006 struct{}

func (r *ruleHARA006) ID() string { return "HARA006" }
func (r *ruleHARA006) Description() string {
	return "Safety goal has no fssrRefs — every safety goal MUST decompose into at least one functional safety requirement (x-FuSa spec §1.2.5)."
}

//fusa:req REQ-HARA019
func (r *ruleHARA006) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	h, err := Load(projectRoot)
	if err != nil || len(h.SafetyGoals) == 0 {
		return nil, nil
	}
	var out []fusa.Finding
	for _, g := range h.SafetyGoals {
		if len(g.FSSRRefs) == 0 {
			out = append(out, fusa.Finding{
				RuleID:      r.ID(),
				Severity:    fusa.SeverityWarning,
				Message:     fmt.Sprintf("safety goal %s has no fssrRefs", g.ID),
				Location:    fusa.Location{File: HARAFile},
				Category:    fusa.CategoryRequirement,
				Remediation: fmt.Sprintf("add at least one requirement id to safety goal %s's fssrRefs in %s and register it in %s", g.ID, HARAFile, trace.ReqsFile),
			})
		}
	}
	return out, nil
}

// HARA007 — fssrRefs entry with no matching requirement in .fusa-reqs.json.
type ruleHARA007 struct{}

func (r *ruleHARA007) ID() string { return "HARA007" }
func (r *ruleHARA007) Description() string {
	return "A safety goal's fssrRefs entry does not resolve to any requirement in .fusa-reqs.json (dangling reference)."
}

//fusa:req REQ-HARA020
func (r *ruleHARA007) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	h, err := Load(projectRoot)
	if err != nil || len(h.SafetyGoals) == 0 {
		return nil, nil
	}
	reqs, reqErr := trace.LoadRequirements(projectRoot)
	if reqErr != nil {
		// No .fusa-reqs.json (or unreadable) — nothing to cross-check against.
		return nil, nil
	}
	reqIDs := make(map[string]bool, len(reqs))
	for _, req := range reqs {
		reqIDs[req.ID] = true
	}
	var out []fusa.Finding
	for _, f := range ValidateReqRefs(h, reqIDs) {
		out = append(out, fusa.Finding{
			RuleID:      r.ID(),
			Severity:    fusa.SeverityWarning,
			Message:     f.Message,
			Location:    fusa.Location{File: HARAFile},
			Category:    fusa.CategoryRequirement,
			Remediation: fmt.Sprintf("add the missing requirement to %s or correct the fssrRefs entry in %s", trace.ReqsFile, HARAFile),
		})
	}
	return out, nil
}

// HARA008 — a hazard's stored risk.asil disagrees with the S/E/C-derived ASIL.
type ruleHARA008 struct{}

func (r *ruleHARA008) ID() string { return "HARA008" }
func (r *ruleHARA008) Description() string {
	return "Hazard's declared risk.asil does not match DetermineASIL(severity, exposure, controllability) per ISO 26262-3:2018 Table 4 (x-FuSa spec §1.2.5 MUST)."
}

// ValidateASIL cross-checks every hazard in h with a complete S/E/C rating
// against DetermineASIL, flagging a hazard whose stored risk.asil disagrees
// with what the table derives. A hazard with an incomplete S/E/C rating is
// skipped here — that gap is HARA002's responsibility, and DetermineASIL
// would otherwise report a misleading "should be QM" for missing inputs
// rather than a genuine table mismatch.
//
//fusa:req REQ-HARA024
func ValidateASIL(h *HARA) []ValidationFinding {
	var out []ValidationFinding
	for _, hz := range h.Hazards {
		if hz.Risk.ASIL == "" {
			continue
		}
		if hz.Risk.Severity == "" || hz.Risk.Exposure == "" || hz.Risk.Controllability == "" {
			continue
		}
		derived := DetermineASIL(hz.Risk.Severity, hz.Risk.Exposure, hz.Risk.Controllability)
		if hz.Risk.ASIL != derived {
			out = append(out, ValidationFinding{
				HazardID: hz.ID,
				Message: fmt.Sprintf(
					"hazard %s declares risk.asil=%s but S=%s E=%s C=%s derives %s per ISO 26262-3 Table 4 (DetermineASIL)",
					hz.ID, hz.Risk.ASIL, hz.Risk.Severity, hz.Risk.Exposure, hz.Risk.Controllability, derived,
				),
			})
		}
	}
	return out
}

//fusa:req REQ-HARA024
func (r *ruleHARA008) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	h, err := Load(projectRoot)
	if err != nil || len(h.Hazards) == 0 {
		return nil, nil
	}
	var out []fusa.Finding
	for _, f := range ValidateASIL(h) {
		out = append(out, fusa.Finding{
			RuleID:      r.ID(),
			Severity:    fusa.SeverityWarning,
			Message:     f.Message,
			Location:    fusa.Location{File: HARAFile},
			Remediation: fmt.Sprintf("update risk.asil for hazard %s in %s to match its S/E/C rating, or correct the S/E/C rating if the ASIL is right and the inputs are wrong", f.HazardID, HARAFile),
		})
	}
	return out, nil
}
