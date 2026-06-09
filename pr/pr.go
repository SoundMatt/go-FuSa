// Package pr implements the Problem Reporting workflow required by DO-178C §11.17.
//
// Problem reports are stored in .fusa-problems.json. Each report records an
// issue ID, title, phase found, phase fixed, severity, status, and description.
// The log is committed alongside the codebase as a lifecycle data item.
//
// Activate the engine rule by importing this package for its side effects:
//
//	import _ "github.com/SoundMatt/go-FuSa/pr"
package pr

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

// ProblemsFile is the default filename for the problem report log.
const ProblemsFile = ".fusa-problems.json"

// Phase identifies the software lifecycle phase.
type Phase string

const (
	PhasePlanning     Phase = "planning"
	PhaseDevelopment  Phase = "development"
	PhaseVerification Phase = "verification"
	PhaseIntegration  Phase = "integration"
	PhaseOperation    Phase = "operation"
)

// Status is the current state of a problem report.
type Status string

const (
	StatusOpen     Status = "open"
	StatusInWork   Status = "in-work"
	StatusClosed   Status = "closed"
	StatusDeferred Status = "deferred"
)

// Severity is the impact classification of the problem.
type PRSeverity string

const (
	PRSeverityCritical PRSeverity = "critical"
	PRSeverityMajor    PRSeverity = "major"
	PRSeverityMinor    PRSeverity = "minor"
)

// ProblemReport is a single DO-178C problem report entry.
//
//fusa:req REQ-PR001
type ProblemReport struct {
	ID          string     `json:"id"`
	Title       string     `json:"title"`
	Description string     `json:"description,omitempty"`
	PhaseFound  Phase      `json:"phaseFound"`
	PhaseFixed  Phase      `json:"phaseFixed,omitempty"`
	Severity    PRSeverity `json:"severity"`
	Status      Status     `json:"status"`
	Created     time.Time  `json:"created"`
	Updated     time.Time  `json:"updated"`
	Resolution  string     `json:"resolution,omitempty"`
}

// Log is the complete problem report log.
//
//fusa:req REQ-PR002
type Log struct {
	Project string          `json:"project"`
	Reports []ProblemReport `json:"reports"`
}

// Load reads the problem report log from path.
//
//fusa:req REQ-PR001
func Load(path string) (*Log, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Log{}, nil
		}
		return nil, fmt.Errorf("pr: read %s: %w", path, err)
	}
	var log Log
	if err := json.Unmarshal(data, &log); err != nil {
		return nil, fmt.Errorf("pr: parse %s: %w", path, err)
	}
	return &log, nil
}

// Save writes the log to path as indented JSON.
//
//fusa:req REQ-PR002
func Save(path string, log *Log) error {
	data, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o640)
}

// Add appends a new problem report to the log and saves it.
//
//fusa:req REQ-PR003
func Add(path string, report ProblemReport) error {
	log, err := Load(path)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	report.Created = now
	report.Updated = now
	if report.Status == "" {
		report.Status = StatusOpen
	}
	log.Reports = append(log.Reports, report)
	return Save(path, log)
}

// Close marks a problem report as closed and saves it.
//
//fusa:req REQ-PR004
func Close(path, id, resolution string) error {
	log, err := Load(path)
	if err != nil {
		return err
	}
	for i, r := range log.Reports {
		if r.ID == id {
			log.Reports[i].Status = StatusClosed
			log.Reports[i].Resolution = resolution
			log.Reports[i].Updated = time.Now().UTC()
			return Save(path, log)
		}
	}
	return fmt.Errorf("pr: report %q not found", id)
}

// Render writes a text or JSON summary of the log to w.
//
//fusa:req REQ-PR003
func Render(w io.Writer, log *Log, format string) error {
	switch format {
	case "json", "":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(log)
	case "text":
		return renderText(w, log)
	default:
		return fmt.Errorf("pr: unsupported format %q", format)
	}
}

func renderText(w io.Writer, log *Log) error {
	open, closed := 0, 0
	for _, r := range log.Reports {
		if r.Status == StatusClosed {
			closed++
		} else {
			open++
		}
	}
	fmt.Fprintf(w, "Problem Reports: %d total  %d open  %d closed\n\n", len(log.Reports), open, closed)
	for _, r := range log.Reports {
		fmt.Fprintf(w, "[%s] %s  (%s / %s)\n  %s\n  Phase: %s  Status: %s\n\n",
			r.ID, r.Title, r.Severity, r.Status,
			r.Description, r.PhaseFound, r.Status)
	}
	return nil
}

// ─── engine rule ──────────────────────────────────────────────────────────────

func init() {
	engine.Default.MustRegister(&rulePRLog{})
}

type rulePRLog struct{}

func (r *rulePRLog) ID() string { return "PR001" }
func (r *rulePRLog) Description() string {
	return "No .fusa-problems.json problem report log found (DO-178C §11.17)."
}

//fusa:req REQ-PR001
func (r *rulePRLog) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	path := filepath.Join(projectRoot, ProblemsFile)
	if _, err := os.Stat(path); err == nil {
		// File exists; check for open critical/major issues.
		log, loadErr := Load(path)
		if loadErr != nil {
			return nil, loadErr
		}
		var findings []fusa.Finding
		for _, rep := range log.Reports {
			if rep.Status != StatusClosed && rep.Severity == PRSeverityCritical {
				findings = append(findings, fusa.Finding{
					RuleID:      r.ID(),
					Severity:    fusa.SeverityError,
					Message:     fmt.Sprintf("problem report %s (%s) is open with critical severity", rep.ID, rep.Title),
					Location:    fusa.Location{File: ProblemsFile},
					Remediation: "resolve or defer critical problem reports before release",
				})
			}
		}
		return findings, nil
	}
	return []fusa.Finding{{
		RuleID:      r.ID(),
		Severity:    fusa.SeverityInfo,
		Message:     "no .fusa-problems.json found — problem report log required for DO-178C §11.17",
		Location:    fusa.Location{File: ProblemsFile},
		Remediation: "run 'gofusa pr init' to create the problem report log",
	}}, nil
}
