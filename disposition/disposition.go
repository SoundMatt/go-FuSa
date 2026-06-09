// Package disposition manages finding disposition entries for go-FuSa projects.
//
// A disposition entry records that a specific finding (by rule ID) has been
// reviewed and accepted or scheduled for fixing. The DISP001 engine rule
// cross-references dispositions against check-report.json ERROR findings and
// warns about undispositioned errors.
//
// Usage:
//
//	log, err := disposition.Load(projectRoot)
//	log = disposition.Add(log, disposition.Entry{...})
//	err = disposition.Save(path, log)
package disposition

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

// DispositionsFile is the default filename for the dispositions log.
const DispositionsFile = ".fusa-dispositions.json"

// Action describes what was decided for a finding.
//
//fusa:req REQ-DISP001
type Action string

const (
	// ActionAccept records the finding as accepted/waived.
	ActionAccept Action = "accept"
	// ActionFix records the finding as scheduled for remediation.
	ActionFix Action = "fix"
)

// Entry records a single disposition decision.
//
//fusa:req REQ-DISP002
type Entry struct {
	RuleID    string    `json:"ruleID"`
	Rationale string    `json:"rationale"`
	Reviewer  string    `json:"reviewer"`
	Date      time.Time `json:"date"`
	Action    Action    `json:"action"`
	Reference string    `json:"reference,omitempty"`
}

// Log is the full dispositions log for a project.
//
//fusa:req REQ-DISP003
type Log struct {
	Project string  `json:"project"`
	Entries []Entry `json:"entries"`
}

// Load reads the dispositions log from projectRoot. If the file does not exist,
// it returns an empty log with no error.
//
//fusa:req REQ-DISP004
func Load(projectRoot string) (*Log, error) {
	path := filepath.Join(projectRoot, DispositionsFile)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Log{}, nil
		}
		return nil, fmt.Errorf("disposition: read %s: %w", DispositionsFile, err)
	}
	var log Log
	if err := json.Unmarshal(data, &log); err != nil {
		return nil, fmt.Errorf("%w: %s: %s", fusa.ErrInvalidConfig, DispositionsFile, err)
	}
	return &log, nil
}

// Save writes the dispositions log to path.
//
//fusa:req REQ-DISP005
func Save(path string, log *Log) error {
	data, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return fmt.Errorf("disposition: marshal: %w", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o640); err != nil {
		return fmt.Errorf("disposition: write %s: %w", path, err)
	}
	return nil
}

// Add appends entry to log, deduplicating by RuleID+Action. If an entry with
// the same RuleID and Action already exists it is replaced. Returns the
// updated log.
//
//fusa:req REQ-DISP006
func Add(log *Log, entry Entry) *Log {
	for i, e := range log.Entries {
		if e.RuleID == entry.RuleID && e.Action == entry.Action {
			log.Entries[i] = entry
			return log
		}
	}
	log.Entries = append(log.Entries, entry)
	return log
}

// IsDispositioned reports whether ruleID has any disposition entry.
//
//fusa:req REQ-DISP007
func IsDispositioned(log *Log, ruleID string) bool {
	for _, e := range log.Entries {
		if e.RuleID == ruleID {
			return true
		}
	}
	return false
}

// checkReportFinding is a minimal struct for parsing check-report.json.
type checkReportFinding struct {
	RuleID   string `json:"ruleId"`
	Severity string `json:"severity"`
}

// ─── Engine rule ───────────────────────────────────────────────────────────────

func init() {
	engine.Default.MustRegister(&ruleDISP001{})
}

// DISP001 — undispositioned ERROR findings.
type ruleDISP001 struct{}

func (r *ruleDISP001) ID() string { return "DISP001" }
func (r *ruleDISP001) Description() string {
	return "Each ERROR finding in check-report.json must have a disposition entry in .fusa-dispositions.json."
}

//fusa:req REQ-DISP008
func (r *ruleDISP001) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	checkPath := filepath.Join(projectRoot, "check-report.json")
	data, err := os.ReadFile(checkPath)
	if err != nil {
		if os.IsNotExist(err) {
			return []fusa.Finding{{
				RuleID:      r.ID(),
				Severity:    fusa.SeverityInfo,
				Message:     "check-report.json not found — run gofusa check first",
				Location:    fusa.Location{File: "check-report.json"},
				Remediation: "run 'gofusa check' to generate the check report",
			}}, nil
		}
		return nil, err
	}

	// Parse findings array (the file may be a JSON object with a "findings" field
	// or a flat array depending on format; handle both).
	var findings []checkReportFinding
	unmarshalErr := json.Unmarshal(data, &findings)
	if unmarshalErr != nil {
		// Try nested format: {"findings": [...]}
		var obj struct {
			Findings []checkReportFinding `json:"findings"`
		}
		if err2 := json.Unmarshal(data, &obj); err2 != nil {
			// Cannot parse — skip silently
			return nil, nil
		}
		findings = obj.Findings
	}

	log, err := Load(projectRoot)
	if err != nil {
		return nil, err
	}

	var out []fusa.Finding
	seen := make(map[string]bool)
	for _, f := range findings {
		if f.Severity != "ERROR" {
			continue
		}
		if seen[f.RuleID] {
			continue
		}
		seen[f.RuleID] = true
		if IsDispositioned(log, f.RuleID) {
			continue
		}
		out = append(out, fusa.Finding{
			RuleID:      r.ID(),
			Severity:    fusa.SeverityWarning,
			Message:     fmt.Sprintf("finding %s has no disposition entry — run 'gofusa disposition add --rule %s'", f.RuleID, f.RuleID),
			Location:    fusa.Location{File: DispositionsFile},
			Remediation: fmt.Sprintf("run 'gofusa disposition add --rule %s --action accept --reviewer \"Name\" --rationale \"reason\"'", f.RuleID),
		})
	}
	return out, nil
}

// RenderEntries writes a human-readable table of entries to w.
//
//fusa:req REQ-DISP009
func RenderEntries(w io.Writer, log *Log) error {
	if len(log.Entries) == 0 {
		_, err := fmt.Fprintf(w, "No disposition entries found in %s\n", DispositionsFile)
		return err
	}
	fmt.Fprintf(w, "%-20s %-8s %-20s %-12s %s\n", "Rule ID", "Action", "Reviewer", "Date", "Rationale")
	fmt.Fprintf(w, "%s\n", "──────────────────────────────────────────────────────────────────────────────")
	for _, e := range log.Entries {
		fmt.Fprintf(w, "%-20s %-8s %-20s %-12s %s\n",
			e.RuleID, e.Action, e.Reviewer, e.Date.Format("2006-01-02"), e.Rationale)
		if e.Reference != "" {
			fmt.Fprintf(w, "  Reference: %s\n", e.Reference)
		}
	}
	return nil
}
