// Package impact analyses the effect of source-code changes on requirements,
// test evidence, and safety artefacts.
//
// It runs git diff to discover changed files, cross-references requirement
// annotations to find impacted requirements, and checks whether evidence
// artefacts are stale relative to the changed source files.
//
// Usage:
//
//	rep, err := impact.Analyse(projectRoot, "", "")  // diff vs HEAD
//	_ = impact.Render(os.Stdout, rep, "text")
package impact

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/trace"
)

// FileChange describes a single file that changed in the diff.
//
//fusa:req REQ-IMPACT001
type FileChange struct {
	Path   string `json:"path"`
	Status string `json:"status"` // "M", "A", "D", "R"
}

// RequirementImpact describes a requirement affected by changes.
//
//fusa:req REQ-IMPACT002
type RequirementImpact struct {
	RequirementID string   `json:"requirementID"`
	AffectedFiles []string `json:"affectedFiles"`
	TestsNeeded   []string `json:"testsNeeded"`  // test files that reference this req
	Stale         bool     `json:"stale"`
}

// ArtifactStatus reports whether a safety artefact is stale.
//
//fusa:req REQ-IMPACT003
type ArtifactStatus struct {
	File   string `json:"file"`
	Stale  bool   `json:"stale"`
	Reason string `json:"reason"`
}

// Report is the complete impact analysis.
//
//fusa:req REQ-IMPACT004
type Report struct {
	Generated      time.Time            `json:"generated"`
	ChangedFiles   []FileChange         `json:"changedFiles"`
	ImpactedReqs   []RequirementImpact  `json:"impactedReqs"`
	StaleArtifacts []ArtifactStatus     `json:"staleArtifacts"`
	RerunTests     []string             `json:"rerunTests"`
}

// evidenceArtefacts are the safety evidence files to check for staleness.
var evidenceArtefacts = []string{
	".fusa-evidence.json",
	"coverage-report.json",
	"sbom.json",
	"iso26262-gap-report.json",
	"iec61508-gap-report.json",
	"do178-gap-report.json",
}

// Analyse runs a change-impact analysis for projectRoot.
// If fromRef and toRef are both empty, it diffs the working tree against HEAD.
// If only fromRef is set, it diffs fromRef..HEAD.
// If both are set, it diffs fromRef..toRef.
//
//fusa:req REQ-IMPACT001
func Analyse(projectRoot, fromRef, toRef string) (*Report, error) {
	rep := &Report{Generated: time.Now().UTC()}

	changes, err := changedFiles(projectRoot, fromRef, toRef)
	if err != nil {
		// git unavailable or no repo — return empty report
		return rep, nil
	}
	rep.ChangedFiles = changes

	if len(changes) == 0 {
		return rep, nil
	}

	// Build requirement traceability matrix.
	matrix, err := trace.Build(projectRoot)
	if err != nil && !errors.Is(err, fusa.ErrNoConfig) {
		return rep, nil
	}

	changedSet := make(map[string]bool)
	for _, c := range changes {
		changedSet[c.Path] = true
		// Also normalise separators
		changedSet[filepath.FromSlash(c.Path)] = true
	}

	// Find the latest mtime of changed source files for staleness check.
	var latestSrc time.Time
	for _, c := range changes {
		abs := filepath.Join(projectRoot, filepath.FromSlash(c.Path))
		if info, err := os.Stat(abs); err == nil {
			if info.ModTime().After(latestSrc) {
				latestSrc = info.ModTime()
			}
		}
	}

	// Map requirement → impl files, test files from trace matrix.
	reqImplFiles := make(map[string][]string)
	reqTestFiles := make(map[string][]string)
	for _, tag := range matrix.Tags {
		switch tag.Kind {
		case trace.KindImpl:
			reqImplFiles[tag.RequirementID] = appendUniq(reqImplFiles[tag.RequirementID], tag.File)
		case trace.KindTest, trace.KindSecTest:
			reqTestFiles[tag.RequirementID] = appendUniq(reqTestFiles[tag.RequirementID], tag.File)
		}
	}

	// Find impacted requirements.
	rerunSet := make(map[string]bool)
	impactedReqSet := make(map[string]bool)
	for reqID, files := range reqImplFiles {
		var affected []string
		for _, f := range files {
			if changedSet[f] || changedSet[filepath.ToSlash(f)] {
				affected = append(affected, f)
			}
		}
		if len(affected) == 0 {
			continue
		}
		if impactedReqSet[reqID] {
			continue
		}
		impactedReqSet[reqID] = true
		tests := reqTestFiles[reqID]
		for _, t := range tests {
			rerunSet[t] = true
		}
		rep.ImpactedReqs = append(rep.ImpactedReqs, RequirementImpact{
			RequirementID: reqID,
			AffectedFiles: affected,
			TestsNeeded:   tests,
			Stale:         len(tests) > 0,
		})
	}

	for t := range rerunSet {
		rep.RerunTests = append(rep.RerunTests, t)
	}

	// Check evidence artefact staleness.
	if !latestSrc.IsZero() {
		for _, artefact := range evidenceArtefacts {
			abs := filepath.Join(projectRoot, artefact)
			info, err := os.Stat(abs)
			if err != nil {
				// artefact absent — mark stale
				rep.StaleArtifacts = append(rep.StaleArtifacts, ArtifactStatus{
					File:   artefact,
					Stale:  true,
					Reason: "file not present",
				})
				continue
			}
			if info.ModTime().Before(latestSrc) {
				rep.StaleArtifacts = append(rep.StaleArtifacts, ArtifactStatus{
					File:   artefact,
					Stale:  true,
					Reason: fmt.Sprintf("last updated %s, older than changed sources", info.ModTime().Format("2006-01-02 15:04:05")),
				})
			} else {
				rep.StaleArtifacts = append(rep.StaleArtifacts, ArtifactStatus{
					File:  artefact,
					Stale: false,
				})
			}
		}
	}

	return rep, nil
}

// changedFiles runs git diff and returns the changed file list.
func changedFiles(projectRoot, fromRef, toRef string) ([]FileChange, error) {
	var args []string
	if fromRef == "" && toRef == "" {
		args = []string{"diff", "--name-status", "HEAD"}
	} else if toRef == "" {
		args = []string{"diff", "--name-status", fromRef + "..HEAD"}
	} else {
		args = []string{"diff", "--name-status", fromRef + ".." + toRef}
	}

	cmd := exec.Command("git", args...)
	cmd.Dir = projectRoot
	var out bytes.Buffer
	var errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("impact: git diff: %w", err)
	}

	var changes []FileChange
	sc := bufio.NewScanner(&out)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		status := string(parts[0][0]) // first char: M, A, D, R, etc.
		path := parts[1]
		changes = append(changes, FileChange{Path: path, Status: status})
	}
	return changes, sc.Err()
}

func appendUniq(s []string, v string) []string {
	for _, existing := range s {
		if existing == v {
			return s
		}
	}
	return append(s, v)
}

// Render writes the impact report to w in the requested format ("text" or "json").
//
//fusa:req REQ-IMPACT005
func Render(w io.Writer, rep *Report, format string) error {
	switch format {
	case "json", "":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	case "text":
		return renderText(w, rep)
	default:
		return fmt.Errorf("impact: unsupported format %q", format)
	}
}

func renderText(w io.Writer, rep *Report) error {
	fmt.Fprintf(w, "Impact Analysis Report — %s\n\n", rep.Generated.Format("2006-01-02 15:04:05"))

	fmt.Fprintf(w, "Changed files (%d):\n", len(rep.ChangedFiles))
	for _, c := range rep.ChangedFiles {
		fmt.Fprintf(w, "  [%s] %s\n", c.Status, c.Path)
	}
	if len(rep.ChangedFiles) == 0 {
		fmt.Fprintf(w, "  (no changes detected)\n")
	}
	fmt.Fprintln(w)

	fmt.Fprintf(w, "Impacted requirements (%d):\n", len(rep.ImpactedReqs))
	for _, ir := range rep.ImpactedReqs {
		fmt.Fprintf(w, "  %s\n", ir.RequirementID)
		for _, f := range ir.AffectedFiles {
			fmt.Fprintf(w, "    impl: %s\n", f)
		}
		for _, t := range ir.TestsNeeded {
			fmt.Fprintf(w, "    test: %s\n", t)
		}
	}
	if len(rep.ImpactedReqs) == 0 {
		fmt.Fprintf(w, "  (none)\n")
	}
	fmt.Fprintln(w)

	staleCount := 0
	for _, a := range rep.StaleArtifacts {
		if a.Stale {
			staleCount++
		}
	}
	fmt.Fprintf(w, "Stale artefacts (%d of %d):\n", staleCount, len(rep.StaleArtifacts))
	for _, a := range rep.StaleArtifacts {
		icon := "✓"
		if a.Stale {
			icon = "✗"
		}
		fmt.Fprintf(w, "  %s %s", icon, a.File)
		if a.Reason != "" {
			fmt.Fprintf(w, " — %s", a.Reason)
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w)

	if len(rep.RerunTests) > 0 {
		fmt.Fprintf(w, "Tests to re-run (%d):\n", len(rep.RerunTests))
		for _, t := range rep.RerunTests {
			fmt.Fprintf(w, "  %s\n", t)
		}
	}

	return nil
}
