// Package metrics tracks go-FuSa project safety metrics over time.
//
// Use Collect to take a snapshot of current project metrics, Append to add it
// to the time series, and Save to persist it to .fusa-metrics.json.
//
// Usage:
//
//	ts, err := metrics.Load(projectRoot)
//	snap, err := metrics.Collect(projectRoot)
//	ts = metrics.Append(ts, snap)
//	err = metrics.Save(filepath.Join(projectRoot, metrics.MetricsFile), ts)
package metrics

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/trace"
)

// MetricsFile is the default filename for the metrics time series.
const MetricsFile = ".fusa-metrics.json"

// Snapshot captures a point-in-time set of project safety metrics.
//
//fusa:req REQ-METRICS001
type Snapshot struct {
	Timestamp            time.Time `json:"timestamp"`
	Version              string    `json:"version"`
	ErrorCount           int       `json:"errorCount"`
	WarningCount         int       `json:"warningCount"`
	InfoCount            int       `json:"infoCount"`
	TotalRequirements    int       `json:"totalRequirements"`
	TracedRequirements   int       `json:"tracedRequirements"`
	TestedRequirements   int       `json:"testedRequirements"`
	CoveragePct          float64   `json:"coveragePct,omitempty"`
	UntracedCount        int       `json:"untracedCount"`
	AnnotationDensityPct float64   `json:"annotationDensityPct,omitempty"`
}

// TimeSeries is the full metrics history for a project.
//
//fusa:req REQ-METRICS002
type TimeSeries struct {
	Project   string     `json:"project"`
	Snapshots []Snapshot `json:"snapshots"`
}

// Load reads the metrics time series from projectRoot. If the file does not
// exist it returns an empty series with no error.
//
//fusa:req REQ-METRICS003
func Load(projectRoot string) (*TimeSeries, error) {
	path := filepath.Join(projectRoot, MetricsFile)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &TimeSeries{}, nil
		}
		return nil, fmt.Errorf("metrics: read %s: %w", MetricsFile, err)
	}
	var ts TimeSeries
	if err := json.Unmarshal(data, &ts); err != nil {
		return nil, fmt.Errorf("metrics: parse %s: %w", MetricsFile, err)
	}
	return &ts, nil
}

// Save writes ts to path.
//
//fusa:req REQ-METRICS004
func Save(path string, ts *TimeSeries) error {
	data, err := json.MarshalIndent(ts, "", "  ")
	if err != nil {
		return fmt.Errorf("metrics: marshal: %w", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o640); err != nil {
		return fmt.Errorf("metrics: write %s: %w", path, err)
	}
	return nil
}

// Append adds snap to ts and returns the updated series.
//
//fusa:req REQ-METRICS005
func Append(ts *TimeSeries, snap Snapshot) *TimeSeries {
	ts.Snapshots = append(ts.Snapshots, snap)
	return ts
}

// checkFinding is a minimal struct for parsing check-report.json.
type checkFinding struct {
	Severity string `json:"severity"`
}

// coverageReport is a minimal struct for parsing coverage-report.json.
type coverageReport struct {
	StmtPct float64 `json:"stmtPct"`
}

// Collect reads project artefacts and builds a metrics snapshot.
// It reads check-report.json, .fusa-reqs.json, and coverage-report.json.
//
//fusa:req REQ-METRICS006
func Collect(projectRoot string) (Snapshot, error) {
	snap := Snapshot{Timestamp: time.Now().UTC()}

	// Parse check-report.json
	checkPath := filepath.Join(projectRoot, "check-report.json")
	if data, err := os.ReadFile(checkPath); err == nil {
		var findings []checkFinding
		if err2 := json.Unmarshal(data, &findings); err2 == nil {
			for _, f := range findings {
				switch f.Severity {
				case "ERROR":
					snap.ErrorCount++
				case "WARNING":
					snap.WarningCount++
				case "INFO":
					snap.InfoCount++
				}
			}
		} else {
			// Try nested format
			var obj struct {
				Findings []checkFinding `json:"findings"`
			}
			if err3 := json.Unmarshal(data, &obj); err3 == nil {
				for _, f := range obj.Findings {
					switch f.Severity {
					case "ERROR":
						snap.ErrorCount++
					case "WARNING":
						snap.WarningCount++
					case "INFO":
						snap.InfoCount++
					}
				}
			}
		}
	}

	// Parse .fusa-reqs.json using trace package
	matrix, err := trace.Build(projectRoot)
	if err != nil && !errors.Is(err, fusa.ErrNoConfig) {
		return snap, fmt.Errorf("metrics: build trace: %w", err)
	}
	if matrix != nil {
		snap.TotalRequirements = matrix.Coverage.TotalRequirements
		snap.TracedRequirements = matrix.Coverage.TracedRequirements
		snap.TestedRequirements = matrix.Coverage.TestedRequirements
		snap.UntracedCount = snap.TotalRequirements - snap.TracedRequirements

		// Annotation density from func coverage
		if len(matrix.Tags) > 0 {
			fc, err := trace.ScanFuncCoverage(projectRoot, matrix.Tags)
			if err == nil && fc.Total > 0 {
				snap.AnnotationDensityPct = fc.Pct
			}
		}
	}

	// Parse coverage-report.json
	covPath := filepath.Join(projectRoot, "coverage-report.json")
	if data, err := os.ReadFile(covPath); err == nil {
		var cov coverageReport
		if err2 := json.Unmarshal(data, &cov); err2 == nil {
			snap.CoveragePct = cov.StmtPct
		}
	}

	return snap, nil
}

// Render writes the time series to w in the requested format ("text" or "json").
//
//fusa:req REQ-METRICS007
func Render(w io.Writer, ts *TimeSeries, format string) error {
	switch format {
	case "json", "":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(ts)
	case "text":
		return renderText(w, ts)
	default:
		return fmt.Errorf("metrics: unsupported format %q", format)
	}
}

func renderText(w io.Writer, ts *TimeSeries) error {
	fmt.Fprintf(w, "go-FuSa Metrics — %s\n\n", ts.Project)
	if len(ts.Snapshots) == 0 {
		fmt.Fprintf(w, "No snapshots recorded. Run 'gofusa metrics record' to record one.\n")
		return nil
	}
	fmt.Fprintf(w, "%-20s %-6s %-6s %-6s %-5s %-9s %s\n",
		"Date", "ERR", "WARN", "INFO", "Reqs", "Traced%", "Coverage%")
	fmt.Fprintln(w, "──────────────────────────────────────────────────────────────────────")
	for _, s := range ts.Snapshots {
		tracedPct := 0.0
		if s.TotalRequirements > 0 {
			tracedPct = float64(s.TracedRequirements) * 100 / float64(s.TotalRequirements)
		}
		fmt.Fprintf(w, "%-20s %-6d %-6d %-6d %-5d %-9.0f%% %.0f%%\n",
			s.Timestamp.Format("2006-01-02 15:04"),
			s.ErrorCount, s.WarningCount, s.InfoCount,
			s.TotalRequirements,
			tracedPct,
			s.CoveragePct,
		)
	}
	return nil
}
