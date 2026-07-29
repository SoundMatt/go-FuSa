// Package config manages go-FuSa project configuration.
//
// A project is configured via a .fusa.json file at the project root.
// Use Load to read an existing file, Default to build a starter config,
// and Save to write it to disk.
//
// go-FuSa historically read/wrote a proprietary .fusa.json shape: a
// top-level "version" field, with "standard"/"asil"/"sil" nested inside
// "project". x-FuSa spec §1.2.1 documents a different canonical shape:
// top-level "configVersion", top-level "standard"/"asil"/"sil"/"dal", and a
// "project" object of just {"name", "version"} (or, per the spec's legacy
// form, a flat "project" string). Config accepts both shapes and Load
// normalises whichever fields are present into both locations, so existing
// accessors (cfg.Project.Standard, cfg.Version, …) keep working no matter
// which shape was on disk, and a spec-compliant .fusa.json written by any
// other x-FuSa tool loads without error. Save mirrors the same
// normalisation before writing, so go-FuSa's own output satisfies both
// shapes at once.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	fusa "github.com/SoundMatt/go-FuSa"
)

// ConfigFile is the conventional name for the go-FuSa configuration file.
const ConfigFile = ".fusa.json"

// Standard is a recognised functional safety standard identifier.
//
//fusa:req REQ-NF003
type Standard string

const (
	StandardISO26262 Standard = "ISO26262"
	StandardIEC61508 Standard = "IEC61508"
	StandardISO21434 Standard = "ISO21434"
	StandardDO178C   Standard = "DO178C"
	StandardGeneric  Standard = "generic"
)

// Config is the top-level project configuration.
//
// Version is go-FuSa's own legacy config-format field; ConfigVersion is the
// x-FuSa spec §1.2.1 equivalent. Standard/ASIL/SIL/DAL are the spec's
// top-level integrity fields; go-FuSa's legacy shape nests the equivalents
// under Project instead. Load and Save keep both locations in sync — see
// the package doc comment.
type Config struct {
	Version       string `json:"version,omitempty"`
	ConfigVersion string `json:"configVersion,omitempty"`

	Project ProjectConfig `json:"project"`

	Standard Standard `json:"standard,omitempty"`
	ASIL     string   `json:"asil,omitempty"` // ASIL-A … ASIL-D (ISO 26262)
	SIL      string   `json:"sil,omitempty"`  // SIL-1 … SIL-4 (IEC 61508)
	DAL      string   `json:"dal,omitempty"`  // DAL-A … DAL-E (DO-178C)

	Rules  RulesConfig  `json:"rules"`
	Report ReportConfig `json:"report"`
}

// ProjectConfig holds project identity and safety context.
//
// Standard/ASIL/SIL/DAL are go-FuSa's legacy nested location for the spec's
// top-level integrity fields (kept for back-compat); Load/Save keep them in
// sync with Config's top-level equivalents. Version is the spec's
// project.version (§1.2.1).
type ProjectConfig struct {
	Name     string   `json:"name"`
	Module   string   `json:"module,omitempty"`
	Version  string   `json:"version,omitempty"`
	Standard Standard `json:"standard,omitempty"`
	ASIL     string   `json:"asil,omitempty"`
	SIL      string   `json:"sil,omitempty"`
	DAL      string   `json:"dal,omitempty"`
}

// UnmarshalJSON accepts both the object form of "project" and x-FuSa spec
// §1.2.1's legacy flat string form (`"project": "name"`), normalising the
// flat form to {"name": "..."}.
//
//fusa:req REQ-CFG009
func (p *ProjectConfig) UnmarshalJSON(data []byte) error {
	var flat string
	if err := json.Unmarshal(data, &flat); err == nil {
		*p = ProjectConfig{Name: flat}
		return nil
	}
	type alias ProjectConfig
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	*p = ProjectConfig(a)
	return nil
}

// RulesConfig controls which rules are active and how findings are reported.
type RulesConfig struct {
	Exclude []string `json:"exclude,omitempty"`
	// Severity overrides the severity of findings for the keyed rule ID.
	// Values must be "ERROR", "WARNING", or "INFO".
	//
	//fusa:req REQ-CFG008
	Severity map[string]string `json:"severity,omitempty"`
}

// ReportConfig controls report output.
type ReportConfig struct {
	Format string `json:"format"`           // "text" or "json"
	Output string `json:"output,omitempty"` // file path; stdout if empty
}

// Default returns a starter Config for the given module path and project name.
//
//fusa:req REQ-CFG005
func Default(module, name string) *Config {
	cfg := &Config{
		Version:       "1",
		ConfigVersion: "1.0",
		Project: ProjectConfig{
			Name:     name,
			Module:   module,
			Version:  "0.1.0",
			Standard: StandardGeneric,
		},
		Standard: StandardGeneric,
		Rules:    RulesConfig{},
		Report:   ReportConfig{Format: "text"},
	}
	return cfg
}

// Load reads and validates a Config from the JSON file at path.
//
//fusa:req REQ-CFG001
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			//fusa:req REQ-CFG001
			return nil, fmt.Errorf("%w: %s", fusa.ErrNoConfig, path)
		}
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		//fusa:req REQ-CFG002
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	normalize(&cfg)
	if err := Validate(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Save marshals cfg to indented JSON and writes it to path. It first
// normalises cfg so both the spec's top-level fields and go-FuSa's legacy
// project-nested fields are populated, regardless of which shape the
// caller set — see the package doc comment.
//
//fusa:req REQ-CFG006
//fusa:req REQ-CFG009
func Save(path string, cfg *Config) error {
	normalize(cfg)
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("config: marshal: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o640); err != nil {
		return fmt.Errorf("config: write %s: %w", path, err)
	}
	return nil
}

// normalize synchronises Config's spec-shape top-level fields (configVersion,
// standard, asil, sil, dal) with go-FuSa's legacy project-nested equivalents
// (version, project.standard, project.asil, project.sil, project.dal), so a
// Config read from — or destined for — either §1.2.1 shape has both
// populated consistently. The standard id is additionally canonicalised
// (case-insensitively) onto go-FuSa's own internal Standard enum so
// standard-specific behaviour elsewhere in the codebase (which compares
// against the uppercase constants) works the same regardless of whether the
// source file used go-FuSa's legacy casing or the spec's canonical lowercase
// id (§2.4.1). An id go-FuSa does not recognise is left verbatim.
//
//fusa:req REQ-CFG009
func normalize(cfg *Config) {
	if cfg.ConfigVersion == "" {
		cfg.ConfigVersion = cfg.Version
	}
	if cfg.Version == "" {
		cfg.Version = cfg.ConfigVersion
	}

	std := cfg.Standard
	if std == "" {
		std = cfg.Project.Standard
	}
	std = canonicalStandard(std)
	cfg.Standard = std
	cfg.Project.Standard = std

	if cfg.ASIL == "" {
		cfg.ASIL = cfg.Project.ASIL
	}
	if cfg.Project.ASIL == "" {
		cfg.Project.ASIL = cfg.ASIL
	}

	if cfg.SIL == "" {
		cfg.SIL = cfg.Project.SIL
	}
	if cfg.Project.SIL == "" {
		cfg.Project.SIL = cfg.SIL
	}

	if cfg.DAL == "" {
		cfg.DAL = cfg.Project.DAL
	}
	if cfg.Project.DAL == "" {
		cfg.Project.DAL = cfg.DAL
	}
}

// canonicalStandard maps an x-FuSa spec §2.4.1 canonical standard id (e.g.
// "iso26262") onto go-FuSa's internal Standard enum (e.g. "ISO26262"). An
// empty id, or one go-FuSa does not recognise, is returned unchanged — per
// §2.4.1, an unrecognised id MUST be treated verbatim, never rejected.
func canonicalStandard(s Standard) Standard {
	if s == "" {
		return s
	}
	switch strings.ToLower(string(s)) {
	case "iso26262":
		return StandardISO26262
	case "iec61508":
		return StandardIEC61508
	case "iso21434":
		return StandardISO21434
	case "do178c":
		return StandardDO178C
	case "generic":
		return StandardGeneric
	default:
		return s
	}
}

// CanonicalID returns the x-FuSa spec §2.4.1 canonical lowercase standard id
// for s (e.g. StandardISO26262 -> "iso26262"), the inverse of
// canonicalStandard. StandardGeneric and an empty Standard both map to ""
// — §2.4.1 defines no id for "generic", so callers writing a JSON envelope's
// `standard` field (§3.2) MUST omit the field rather than emit a
// non-canonical value. A value that isn't one of go-FuSa's internal
// constants is lowercased and returned verbatim (§2.4.1: an unrecognised id
// MUST be treated verbatim, never rejected).
//
//fusa:req REQ-CFG010
func (s Standard) CanonicalID() string {
	switch s {
	case StandardISO26262:
		return "iso26262"
	case StandardIEC61508:
		return "iec61508"
	case StandardISO21434:
		return "iso21434"
	case StandardDO178C:
		return "do178c"
	case StandardGeneric, "":
		return ""
	default:
		return strings.ToLower(string(s))
	}
}

// Validate returns an error if cfg contains inconsistencies.
//
//fusa:req REQ-CFG003
func Validate(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("%w: nil config", fusa.ErrInvalidConfig)
	}
	//fusa:req REQ-CFG003
	//fusa:req REQ-CFG009
	if cfg.Version == "" && cfg.ConfigVersion == "" {
		return fmt.Errorf("%w: missing version field", fusa.ErrInvalidConfig)
	}
	switch cfg.Report.Format {
	case "", "text", "json":
		// valid
	default:
		//fusa:req REQ-CFG004
		return fmt.Errorf("%w: unsupported report format %q", fusa.ErrInvalidConfig, cfg.Report.Format)
	}
	for id, sev := range cfg.Rules.Severity {
		switch sev {
		case "ERROR", "WARNING", "INFO":
			// valid
		default:
			return fmt.Errorf("%w: rule %s has invalid severity override %q (must be ERROR, WARNING, or INFO)", fusa.ErrInvalidConfig, id, sev)
		}
	}
	return nil
}
