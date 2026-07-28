package stubcheck

import (
	"context"
	"os"
	"path/filepath"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/config"
	"github.com/SoundMatt/go-FuSa/engine"
	"github.com/SoundMatt/go-FuSa/fmea"
	"github.com/SoundMatt/go-FuSa/hara"
	"github.com/SoundMatt/go-FuSa/safetycase"
	"github.com/SoundMatt/go-FuSa/sas"
	"github.com/SoundMatt/go-FuSa/tara"
)

// ─── per-artifact field extraction ────────────────────────────────────────────
//
// Each function below extracts one artifact's own §1.6-relevant qualitative
// fields into []Field, shared by the engine rules in this file and by each
// `gofusa <artifact>` command's own --strict/--require-attestation gate
// (cmd/gofusa/cmd_*.go), so both call sites apply the identical scan.

// HaraFields extracts .fusa-hara.json's qualitative fields.
//
//fusa:req REQ-STUB005
func HaraFields(h *hara.HARA) []Field {
	sits := make([]string, len(h.Situations))
	for i, s := range h.Situations {
		sits[i] = s.Description
	}
	hazards := make([]string, len(h.Hazards))
	for i, hz := range h.Hazards {
		hazards[i] = hz.Description
	}
	goals := make([]string, len(h.SafetyGoals))
	for i, g := range h.SafetyGoals {
		goals[i] = g.Description
	}
	return []Field{
		{Name: "operationalSituations[].description", Values: sits},
		{Name: "hazards[].description", Values: hazards},
		{Name: "safetyGoals[].description", Values: goals},
	}
}

// FmeaFields extracts fmea.json's qualitative fields.
//
//fusa:req REQ-STUB006
func FmeaFields(r *fmea.Report) []Field {
	modes := make([]string, len(r.Entries))
	effects := make([]string, len(r.Entries))
	causes := make([]string, len(r.Entries))
	for i, e := range r.Entries {
		modes[i] = e.FailureMode
		effects[i] = e.Effect
		causes[i] = e.Cause
	}
	return []Field{
		{Name: "entries[].failureMode", Values: modes},
		{Name: "entries[].effect", Values: effects},
		{Name: "entries[].cause", Values: causes},
	}
}

// TaraFields extracts tara.json's qualitative fields.
//
//fusa:req REQ-STUB007
func TaraFields(r *tara.Report) []Field {
	threats := make([]string, len(r.Entries))
	assets := make([]string, len(r.Entries))
	for i, e := range r.Entries {
		threats[i] = e.Threat
		assets[i] = e.Asset
	}
	return []Field{
		{Name: "threats[].threat", Values: threats},
		{Name: "threats[].asset", Values: assets},
	}
}

// SafetyCaseFields extracts safety-case.json's qualitative fields.
//
//fusa:req REQ-STUB008
func SafetyCaseFields(sc *safetycase.SafetyCase) []Field {
	texts := make([]string, len(sc.Nodes))
	for i, n := range sc.Nodes {
		texts[i] = n.Text
	}
	return []Field{
		{Name: "nodes[].text", Values: texts},
	}
}

// SasFields extracts sas.json's qualitative fields. Only Deviations is
// user-authored free text subject to rule A; the fixed evidenceItems
// checklist is catalog metadata, not per-project-derived content, so it is
// not scanned here (rule B in particular would be nonsensical against it).
//
//fusa:req REQ-STUB009
func SasFields(s *sas.SAS) []Field {
	return []Field{
		{Name: "deviations[]", Values: s.Deviations},
	}
}

// ─── engine rules ──────────────────────────────────────────────────────────────

func init() {
	engine.Default.MustRegister(&rulePlaceholder{})
	engine.Default.MustRegister(&ruleBlanketFallback{})
}

// artifactScan is one known evidence artifact's file path and extracted
// qualitative fields plus attestation (nil if the artifact carries none).
type artifactScan struct {
	file   string
	fields []Field
	att    *fusa.Attestation
	// content is the artifact's substantive content (for attestation
	// hash verification) — nil skips staleness checking (treated as stale).
	content interface{}
}

func loadArtifacts(projectRoot string) []artifactScan {
	var out []artifactScan

	if _, err := os.Stat(filepath.Join(projectRoot, hara.HARAFile)); err == nil {
		if h, err := hara.Load(projectRoot); err == nil {
			out = append(out, artifactScan{
				file: hara.HARAFile, fields: HaraFields(h), att: h.Attestation,
				content: struct {
					Situations  interface{} `json:"operationalSituations"`
					Hazards     interface{} `json:"hazards"`
					SafetyGoals interface{} `json:"safetyGoals"`
				}{h.Situations, h.Hazards, h.SafetyGoals},
			})
		}
	}
	if p := filepath.Join(projectRoot, fmea.FMEAFile); fileExists(p) {
		if r, err := fmea.LoadReport(p); err == nil {
			out = append(out, artifactScan{
				file: fmea.FMEAFile, fields: FmeaFields(r), att: r.Attestation,
				content: r.Entries,
			})
		}
	}
	if p := filepath.Join(projectRoot, tara.TARAFile); fileExists(p) {
		if r, err := tara.LoadReport(p); err == nil {
			out = append(out, artifactScan{
				file: tara.TARAFile, fields: TaraFields(r), att: r.Attestation,
				content: r.Entries,
			})
		}
	}
	if p := filepath.Join(projectRoot, safetycase.SafeCaseFile); fileExists(p) {
		if sc, err := safetycase.Load(p); err == nil {
			out = append(out, artifactScan{
				file: safetycase.SafeCaseFile, fields: SafetyCaseFields(sc), att: sc.Attestation,
				content: struct {
					Nodes interface{} `json:"nodes"`
					Edges interface{} `json:"edges"`
				}{sc.Nodes, sc.Edges},
			})
		}
	}
	if p := filepath.Join(projectRoot, sas.SASJSONFile); fileExists(p) {
		if s, err := sas.LoadReport(p); err == nil {
			out = append(out, artifactScan{
				file: sas.SASJSONFile, fields: SasFields(s), att: s.Attestation,
				content: s.Deviations,
			})
		}
	}
	return out
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// rulePlaceholder implements FUSA-STUB001 across every known evidence
// artifact present in the project. Always an ERROR; never
// attestation-suppressed (§1.6.1 rule A).
type rulePlaceholder struct{}

func (r *rulePlaceholder) ID() string { return RuleStub001 }
func (r *rulePlaceholder) Description() string {
	return "Evidence artifact contains literal placeholder/template text (x-FuSa spec §1.6.1 rule A) — disposition-suppressible only, never by attestation."
}

//fusa:req REQ-STUB010
func (r *rulePlaceholder) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	var out []fusa.Finding
	for _, a := range loadArtifacts(projectRoot) {
		for _, m := range ScanPlaceholders(a.fields) {
			out = append(out, PlaceholderFinding(a.file, m))
		}
	}
	return out, nil
}

// ruleBlanketFallback implements FUSA-STUB002 across every known evidence
// artifact present in the project. A WARNING by default (not gating); a
// non-stale, genuinely independent §1.6.2 attestation suppresses it for
// that artifact.
type ruleBlanketFallback struct{}

func (r *ruleBlanketFallback) ID() string { return RuleStub002 }
func (r *ruleBlanketFallback) Description() string {
	return "Evidence artifact has a qualitative field with a distinct-value ratio below 10% across >=10 entries (x-FuSa spec §1.6.1 rule B) — advisory; suppressed by a valid §1.6.2 attestation."
}

//fusa:req REQ-STUB011
func (r *ruleBlanketFallback) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	var out []fusa.Finding
	for _, a := range loadArtifacts(projectRoot) {
		matches := ScanBlanketFallback(a.fields)
		if len(matches) == 0 {
			continue
		}
		if AttestationSuppresses(a.att, a.content) {
			continue
		}
		for _, m := range matches {
			out = append(out, BlanketFallbackFinding(a.file, m))
		}
	}
	return out, nil
}

// AttestationSuppresses reports whether att is a valid (non-stale,
// independent) §1.6.2 "reviewed" attestation for content's current
// canonical hash — i.e. whether it suppresses a FUSA-STUB002 finding on the
// artifact att belongs to. A hash-computation failure is treated as
// unsuppressed (fail-safe).
//
//fusa:req REQ-STUB012
func AttestationSuppresses(att *fusa.Attestation, content interface{}) bool {
	if att == nil {
		return false
	}
	hash, err := fusa.AttestationContentHash(content)
	if err != nil {
		return false
	}
	return fusa.AttestationValid(att, hash)
}
