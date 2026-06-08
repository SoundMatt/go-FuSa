// Package sarif renders go-FuSa findings as SARIF 2.1.0 for GitHub
// code-scanning and compatible tools.
//
// SARIF spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/
package sarif

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/engine"
)

const sarifVersion = "2.1.0"
const sarifSchema = "https://json.schemastore.org/sarif-2.1.0.json"

// ─── SARIF schema types ───────────────────────────────────────────────────────

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name,omitempty"`
	ShortDescription sarifMessage   `json:"shortDescription"`
	HelpURI          string         `json:"helpUri,omitempty"`
	Properties       map[string]any `json:"properties,omitempty"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
}

// ─── Render ───────────────────────────────────────────────────────────────────

// Render writes findings as a SARIF 2.1.0 log to w.
//
//fusa:req REQ-SARIF001
//fusa:req REQ-SARIF002
func Render(w io.Writer, findings []fusa.Finding, toolVersion string) error {
	rules := buildRuleIndex()

	var results []sarifResult
	for _, f := range findings {
		results = append(results, toSARIFResult(f))
	}
	if results == nil {
		results = []sarifResult{}
	}

	log := sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:           "gofusa",
					Version:        toolVersion,
					InformationURI: "https://github.com/SoundMatt/go-FuSa",
					Rules:          rules,
				},
			},
			Results: results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(log); err != nil {
		return fmt.Errorf("sarif: encode: %w", err)
	}
	return nil
}

func buildRuleIndex() []sarifRule {
	var rules []sarifRule
	seen := make(map[string]bool)
	for _, r := range engine.Default.Rules() {
		if seen[r.ID()] {
			continue
		}
		seen[r.ID()] = true
		rules = append(rules, sarifRule{
			ID:               r.ID(),
			ShortDescription: sarifMessage{Text: r.Description()},
		})
	}
	return rules
}

func toSARIFResult(f fusa.Finding) sarifResult {
	r := sarifResult{
		RuleID:  f.RuleID,
		Level:   severityToLevel(f.Severity),
		Message: sarifMessage{Text: f.Message},
	}
	if f.Location.File != "" {
		uri := fileURI(f.Location.File)
		loc := sarifLocation{
			PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{
					URI:       uri,
					URIBaseID: "%SRCROOT%",
				},
			},
		}
		if f.Location.Line > 0 {
			loc.PhysicalLocation.Region = &sarifRegion{
				StartLine:   f.Location.Line,
				StartColumn: f.Location.Column,
			}
		}
		r.Locations = []sarifLocation{loc}
	}
	return r
}

func severityToLevel(s fusa.Severity) string {
	switch s {
	case fusa.SeverityError:
		return "error"
	case fusa.SeverityWarning:
		return "warning"
	default:
		return "note"
	}
}

// fileURI converts a path to a forward-slash URI suitable for SARIF.
func fileURI(path string) string {
	path = filepath.ToSlash(path)
	if strings.HasPrefix(path, "/") {
		return "file://" + path
	}
	return path
}
