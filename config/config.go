// Package config manages go-FuSa project configuration.
//
// A project is configured via a .fusa.json file at the project root.
// Use Load to read an existing file, Default to build a starter config,
// and Save to write it to disk.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

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
type Config struct {
	Version string        `json:"version"`
	Project ProjectConfig `json:"project"`
	Rules   RulesConfig   `json:"rules"`
	Report  ReportConfig  `json:"report"`
}

// ProjectConfig holds project identity and safety context.
type ProjectConfig struct {
	Name     string   `json:"name"`
	Module   string   `json:"module"`
	Standard Standard `json:"standard"`
	ASIL     string   `json:"asil,omitempty"` // ASIL-A … ASIL-D (ISO 26262)
	SIL      string   `json:"sil,omitempty"`  // SIL-1 … SIL-4 (IEC 61508)
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
	return &Config{
		Version: "1",
		Project: ProjectConfig{
			Name:     name,
			Module:   module,
			Standard: StandardGeneric,
		},
		Rules:  RulesConfig{},
		Report: ReportConfig{Format: "text"},
	}
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
	if err := Validate(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Save marshals cfg to indented JSON and writes it to path.
//
//fusa:req REQ-CFG006
func Save(path string, cfg *Config) error {
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

// Validate returns an error if cfg contains inconsistencies.
//
//fusa:req REQ-CFG003
func Validate(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("%w: nil config", fusa.ErrInvalidConfig)
	}
	//fusa:req REQ-CFG003
	if cfg.Version == "" {
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
