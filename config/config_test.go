package config_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/config"
)

//fusa:test REQ-CFG005
func TestDefault(t *testing.T) {
	cfg := config.Default("github.com/example/proj", "proj")
	if cfg.Version == "" {
		t.Error("Default: version is empty")
	}
	if cfg.Project.Module != "github.com/example/proj" {
		t.Errorf("Default: module = %q, want %q", cfg.Project.Module, "github.com/example/proj")
	}
	if cfg.Project.Name != "proj" {
		t.Errorf("Default: name = %q, want %q", cfg.Project.Name, "proj")
	}
	if cfg.Project.Standard != config.StandardGeneric {
		t.Errorf("Default: standard = %q, want %q", cfg.Project.Standard, config.StandardGeneric)
	}
	if cfg.Report.Format != "text" {
		t.Errorf("Default: report format = %q, want %q", cfg.Report.Format, "text")
	}
}

//fusa:test REQ-CFG006
func TestSaveLoad_Roundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, config.ConfigFile)

	original := config.Default("github.com/example/proj", "proj")
	original.Project.Standard = config.StandardISO26262
	original.Project.ASIL = "B"
	original.Rules.Exclude = []string{"FUSA003"}

	if err := config.Save(path, original); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Project.Module != original.Project.Module {
		t.Errorf("module mismatch: got %q, want %q", loaded.Project.Module, original.Project.Module)
	}
	if loaded.Project.Standard != original.Project.Standard {
		t.Errorf("standard mismatch: got %q, want %q", loaded.Project.Standard, original.Project.Standard)
	}
	if loaded.Project.ASIL != "B" {
		t.Errorf("asil mismatch: got %q, want %q", loaded.Project.ASIL, "B")
	}
	if len(loaded.Rules.Exclude) != 1 || loaded.Rules.Exclude[0] != "FUSA003" {
		t.Errorf("exclude mismatch: got %v", loaded.Rules.Exclude)
	}
}

//fusa:test REQ-CFG001
//fusa:test REQ-ERR001
func TestLoad_Missing(t *testing.T) {
	_, err := config.Load("/nonexistent/.fusa.json")
	if !errors.Is(err, fusa.ErrNoConfig) {
		t.Errorf("Load missing: want ErrNoConfig, got %v", err)
	}
}

//fusa:test REQ-CFG002
func TestLoad_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, config.ConfigFile)
	if err := os.WriteFile(path, []byte("{not valid json"), 0o640); err != nil {
		t.Fatal(err)
	}
	_, err := config.Load(path)
	if err == nil {
		t.Error("Load invalid JSON: expected error, got nil")
	}
}

//fusa:test REQ-CFG003
//fusa:test REQ-CFG004
//fusa:test REQ-ERR002
func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *config.Config
		wantErr bool
	}{
		{
			name:    "nil config",
			cfg:     nil,
			wantErr: true,
		},
		{
			name:    "missing version",
			cfg:     &config.Config{},
			wantErr: true,
		},
		{
			name:    "invalid format",
			cfg:     &config.Config{Version: "1", Report: config.ReportConfig{Format: "pdf"}},
			wantErr: true,
		},
		{
			name:    "valid minimal",
			cfg:     config.Default("github.com/x/y", "y"),
			wantErr: false,
		},
		{
			name: "valid json format",
			cfg: &config.Config{
				Version: "1",
				Report:  config.ReportConfig{Format: "json"},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := config.Validate(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate(%v): err = %v, wantErr = %v", tt.name, err, tt.wantErr)
			}
			if tt.wantErr && err != nil && !errors.Is(err, fusa.ErrInvalidConfig) {
				t.Errorf("Validate: expected ErrInvalidConfig chain, got %v", err)
			}
		})
	}
}

//fusa:test REQ-NF003
func TestStandard_Identifiers(t *testing.T) {
	for _, std := range []struct {
		id   string
		want string
	}{
		{"ISO26262", string(config.StandardISO26262)},
		{"IEC61508", string(config.StandardIEC61508)},
		{"ISO21434", string(config.StandardISO21434)},
		{"DO178C", string(config.StandardDO178C)},
		{"generic", string(config.StandardGeneric)},
	} {
		if std.id != std.want {
			t.Errorf("Standard %s: got %q, want %q", std.id, std.want, std.id)
		}
		cfg := config.Default("github.com/x/y", "y")
		cfg.Project.Standard = config.Standard(std.id)
		if err := config.Validate(cfg); err != nil {
			t.Errorf("Standard %q: Validate returned unexpected error: %v", std.id, err)
		}
	}
}

func TestSave_FileCreated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, config.ConfigFile)
	cfg := config.Default("github.com/x/y", "y")

	if err := config.Save(path, cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("file not created: %v", err)
	}
}

//fusa:test REQ-CFG008
func TestRulesConfig_SeverityRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, config.ConfigFile)
	cfg := config.Default("github.com/x/y", "y")
	cfg.Rules.Severity = map[string]string{"LINT001": "ERROR", "LINT002": "WARNING"}

	if err := config.Save(path, cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}
	loaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Rules.Severity["LINT001"] != "ERROR" {
		t.Errorf("Severity[LINT001] = %q, want ERROR", loaded.Rules.Severity["LINT001"])
	}
	if loaded.Rules.Severity["LINT002"] != "WARNING" {
		t.Errorf("Severity[LINT002] = %q, want WARNING", loaded.Rules.Severity["LINT002"])
	}
}

func TestValidate_InvalidSeverityOverride(t *testing.T) {
	cfg := config.Default("github.com/x/y", "y")
	cfg.Rules.Severity = map[string]string{"LINT001": "CRITICAL"}
	if err := config.Validate(cfg); err == nil {
		t.Error("Validate: expected error for invalid severity override")
	}
}

func FuzzLoad(f *testing.F) {
	f.Add(`{"version":"1","project":{"name":"x","module":"m","standard":"generic"},"rules":{},"report":{"format":"text"}}`)
	f.Add(`{}`)
	f.Add(`not json`)
	f.Add(`{"version":"1","rules":{"severity":{"X":"ERROR"}}}`)
	f.Fuzz(func(t *testing.T, data string) {
		dir := t.TempDir()
		path := filepath.Join(dir, config.ConfigFile)
		_ = os.WriteFile(path, []byte(data), 0o640)
		_, _ = config.Load(path) // must not panic
	})
}
