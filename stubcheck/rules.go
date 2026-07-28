package stubcheck

import (
	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/fmea"
	"github.com/SoundMatt/go-FuSa/hara"
	"github.com/SoundMatt/go-FuSa/safetycase"
	"github.com/SoundMatt/go-FuSa/sas"
	"github.com/SoundMatt/go-FuSa/tara"
)

// ─── per-artifact field extraction ────────────────────────────────────────────
//
// Each function below extracts one artifact's own §1.6-relevant qualitative
// fields into []Field. x-FuSa spec §1.6.1 ("Who runs this (MUST)") requires
// detection to run *inside each artifact-producing command*, over the
// content that command itself just built or loaded — never inside `check`,
// which does not read sibling evidence artifacts. Accordingly these
// extractors are consumed directly by each `gofusa <artifact>` command's own
// gateContentQuality call (cmd/gofusa/cmd_*.go) and by nothing else; there is
// deliberately no engine.Rule wrapper here that would run this scan as part
// of `gofusa check`/`report`/`fix`/`qualify` (all of which execute
// engine.Default) — see x-FuSa spec §1.6.1 and the fix for the go-FuSa issue
// that found this scan leaking into `check`'s own finding list.

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

// ─── attestation suppression ──────────────────────────────────────────────────

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
