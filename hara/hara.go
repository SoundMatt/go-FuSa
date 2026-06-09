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
	"time"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/config"
	"github.com/SoundMatt/go-FuSa/engine"
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
	FSSRRef     string   `json:"fssrRef,omitempty"` // Functional Safety Software Requirement ref
}

// HARA is the full hazard analysis and risk assessment for a project.
//
//fusa:req REQ-HARA005
type HARA struct {
	Project     string                 `json:"project"`
	Standard    string                 `json:"standard"` // "ISO 26262" or "IEC 61508"
	CreatedAt   time.Time              `json:"createdAt"`
	Situations  []OperationalSituation `json:"operationalSituations"`
	Hazards     []Hazard               `json:"hazards"`
	SafetyGoals []SafetyGoal           `json:"safetyGoals"`
}

// ValidationFinding is a gap identified by Validate.
type ValidationFinding struct {
	HazardID     string
	SafetyGoalID string
	Message      string
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
	return &h, nil
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
	}

	return out
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
	fmt.Fprintf(w, "| ID | Description | ASIL | Safe State |\n|---|---|---|---|\n")
	for _, g := range h.SafetyGoals {
		fmt.Fprintf(w, "| %s | %s | **%s** | %s |\n", g.ID, g.Description, g.ASIL, g.SafeState)
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
