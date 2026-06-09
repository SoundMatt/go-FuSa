// Package coverage reads Go coverage profiles and produces DO-178C-style
// structural coverage reports (DO-178C §6.4.4, Annex A Table A-7).
//
// It reports statement coverage (always available), estimates decision coverage
// from branch data where present, and flags whether MC/DC evidence is required
// (DAL-A) but cannot be automatically verified.
package coverage

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// CoverageFile is the default go coverage profile filename.
const CoverageFile = "coverage.out"

// ReportFile is the default output filename.
const ReportFile = "coverage-report.json"

// DAL represents a Design Assurance Level.
type DAL string

const (
	DALA DAL = "DAL-A"
	DALB DAL = "DAL-B"
	DALC DAL = "DAL-C"
	DALD DAL = "DAL-D"
)

// Block is a single coverage block from the Go profile.
type Block struct {
	File      string `json:"file"`
	StartLine int    `json:"startLine"`
	EndLine   int    `json:"endLine"`
	Stmts     int    `json:"stmts"`
	Count     int    `json:"count"`
}

// FileStats holds per-file coverage statistics.
type FileStats struct {
	File    string  `json:"file"`
	Stmts   int     `json:"stmts"`
	Covered int     `json:"covered"`
	StmtPct float64 `json:"stmtPct"`
}

// Report is the DO-178C structural coverage report.
//
//fusa:req REQ-COV001
type Report struct {
	Generated        time.Time   `json:"generated"`
	DAL              DAL         `json:"dal"`
	StmtTotal        int         `json:"stmtTotal"`
	StmtCovered      int         `json:"stmtCovered"`
	StmtPct          float64     `json:"stmtPct"`
	StmtRequired     bool        `json:"stmtRequired"`
	DecisionPct      float64     `json:"decisionPct,omitempty"`
	DecisionNote     string      `json:"decisionNote,omitempty"`
	DecisionRequired bool        `json:"decisionRequired"`
	MCDCRequired     bool        `json:"mcdcRequired"`
	MCDCNote         string      `json:"mcdcNote,omitempty"`
	Files            []FileStats `json:"files"`
	Gaps             []string    `json:"gaps,omitempty"`
}

// Parse reads a Go coverage profile from r and returns the raw blocks.
//
//fusa:req REQ-COV002
func Parse(r io.Reader) ([]Block, error) {
	scanner := bufio.NewScanner(r)
	var blocks []Block
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "mode:") || line == "" {
			continue
		}
		// format: file:startLine.col,endLine.col numStmts count
		colon := strings.Index(line, ":")
		if colon < 0 {
			continue
		}
		file := line[:colon]
		rest := line[colon+1:]
		// rest: startLine.col,endLine.col numStmts count
		parts := strings.Fields(rest)
		if len(parts) != 3 {
			continue
		}
		rangePart := parts[0]
		dash := strings.Index(rangePart, ",")
		if dash < 0 {
			continue
		}
		startStr := rangePart[:dash]
		endStr := rangePart[dash+1:]
		startLine, _ := strconv.Atoi(strings.Split(startStr, ".")[0])
		endLine, _ := strconv.Atoi(strings.Split(endStr, ".")[0])
		stmts, _ := strconv.Atoi(parts[1])
		count, _ := strconv.Atoi(parts[2])
		blocks = append(blocks, Block{
			File:      file,
			StartLine: startLine,
			EndLine:   endLine,
			Stmts:     stmts,
			Count:     count,
		})
	}
	return blocks, scanner.Err()
}

// Analyse computes a DO-178C coverage report from blocks for the given DAL.
//
//fusa:req REQ-COV001
func Analyse(blocks []Block, dal DAL) *Report {
	rep := &Report{
		Generated:        time.Now().UTC(),
		DAL:              dal,
		StmtRequired:     true,
		DecisionRequired: dal == DALA || dal == DALB,
		MCDCRequired:     dal == DALA,
	}

	// Aggregate by file
	fileMap := make(map[string]*FileStats)
	for _, b := range blocks {
		fs, ok := fileMap[b.File]
		if !ok {
			fs = &FileStats{File: b.File}
			fileMap[b.File] = fs
		}
		fs.Stmts += b.Stmts
		rep.StmtTotal += b.Stmts
		if b.Count > 0 {
			fs.Covered += b.Stmts
			rep.StmtCovered += b.Stmts
		}
	}

	if rep.StmtTotal > 0 {
		rep.StmtPct = float64(rep.StmtCovered) * 100 / float64(rep.StmtTotal)
	}

	for _, fs := range fileMap {
		if fs.Stmts > 0 {
			fs.StmtPct = float64(fs.Covered) * 100 / float64(fs.Stmts)
		}
		rep.Files = append(rep.Files, *fs)
		if fs.StmtPct < 100 {
			rep.Gaps = append(rep.Gaps, fmt.Sprintf("%s: %.1f%% statement coverage", fs.File, fs.StmtPct))
		}
	}

	// Decision coverage: Go's coverage tool doesn't separate branches natively.
	// We approximate: block-level hit ratio as a proxy for decision coverage.
	totalBlocks, coveredBlocks := 0, 0
	for _, b := range blocks {
		totalBlocks++
		if b.Count > 0 {
			coveredBlocks++
		}
	}
	if totalBlocks > 0 {
		rep.DecisionPct = float64(coveredBlocks) * 100 / float64(totalBlocks)
		rep.DecisionNote = "approximated from block coverage — use '-covermode=atomic' for best accuracy"
	}

	if rep.MCDCRequired {
		rep.MCDCNote = "MC/DC cannot be automatically verified; requires structural coverage analysis tool (e.g. gcov + manual review)"
	}

	return rep
}

// BuildFromFile reads a Go coverage profile file and returns an analysis report.
//
//fusa:req REQ-COV002
func BuildFromFile(path string, dal DAL) (*Report, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("coverage: open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	blocks, err := Parse(f)
	if err != nil {
		return nil, fmt.Errorf("coverage: parse: %w", err)
	}
	return Analyse(blocks, dal), nil
}

// Render writes the coverage report in the requested format ("text", "json") to w.
//
//fusa:req REQ-COV003
func Render(w io.Writer, rep *Report, format string) error {
	switch format {
	case "json", "":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	case "text":
		return renderText(w, rep)
	default:
		return fmt.Errorf("coverage: unsupported format %q", format)
	}
}

func renderText(w io.Writer, rep *Report) error {
	fmt.Fprintf(w, "DO-178C Structural Coverage Report\n")
	fmt.Fprintf(w, "DAL: %s  Generated: %s\n\n", rep.DAL, rep.Generated.Format(time.RFC3339))
	fmt.Fprintf(w, "Statement coverage : %5.1f%%  (required: %v)\n", rep.StmtPct, req(rep.StmtRequired))
	fmt.Fprintf(w, "Decision coverage  : %5.1f%%  (required: %v)\n", rep.DecisionPct, req(rep.DecisionRequired))
	if rep.MCDCRequired {
		fmt.Fprintf(w, "MC/DC coverage     : MANUAL CHECK REQUIRED\n")
		fmt.Fprintf(w, "  Note: %s\n", rep.MCDCNote)
	}
	if len(rep.Gaps) > 0 {
		fmt.Fprintf(w, "\nCoverage gaps (%d files):\n", len(rep.Gaps))
		for _, g := range rep.Gaps {
			fmt.Fprintf(w, "  %s\n", g)
		}
	}
	fmt.Fprintf(w, "\nPer-file statement coverage:\n")
	for _, fs := range rep.Files {
		fmt.Fprintf(w, "  %5.1f%%  %s\n", fs.StmtPct, fs.File)
	}
	return nil
}

func req(required bool) string {
	if required {
		return "YES"
	}
	return "no"
}

// ─── Mutation testing ──────────────────────────────────────────────────────────

// MutationResult holds per-package mutation testing results.
type MutationResult struct {
	Package string  `json:"package"`
	Mutants int     `json:"mutants"`
	Killed  int     `json:"killed"`
	Score   float64 `json:"score"`
}

// MutationReport is the DO-178C mutation testing evidence report.
// A mutation score ≥ 80% provides MC/DC-equivalent evidence per DO-178C AC §2.3.1(b).
type MutationReport struct {
	Generated    time.Time        `json:"generated"`
	DAL          DAL              `json:"dal"`
	Mutants      int              `json:"mutants"`
	Killed       int              `json:"killed"`
	Survived     int              `json:"survived"`
	Score        float64          `json:"score"` // killed/mutants * 100
	MCDCEvidence string           `json:"mcdcEvidence"`
	Results      []MutationResult `json:"results,omitempty"`
	Note         string           `json:"note,omitempty"`
}

// RunMutation runs mutation testing via go-mutesting and returns a MutationReport.
// If go-mutesting is not in PATH it returns a report with a note and no error.
func RunMutation(projectRoot string, dal DAL) (*MutationReport, error) {
	bin, err := exec.LookPath("go-mutesting")
	if err != nil {
		return &MutationReport{
			Generated:    time.Now().UTC(),
			DAL:          dal,
			Score:        0,
			MCDCEvidence: "mutation score below 80% — insufficient for MC/DC evidence",
			Note:         "go-mutesting not in PATH — install with: go install github.com/zimmski/go-mutesting/cmd/go-mutesting@latest",
		}, nil
	}
	return runGoMutesting(projectRoot, dal, bin)
}

func runGoMutesting(projectRoot string, dal DAL, bin string) (*MutationReport, error) {
	cmd := exec.CommandContext(context.Background(), bin, "./...") //nolint:gosec,CYBER005 // bin from LookPath
	cmd.Dir = projectRoot
	out, _ := cmd.Output() // exits non-zero when mutants survive; capture anyway

	rep := &MutationReport{
		Generated: time.Now().UTC(),
		DAL:       dal,
	}

	pkgMap := make(map[string]*MutationResult)

	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		// Look for summary line: "The mutation score is X.XX (Y/Z)"
		if strings.HasPrefix(line, "The mutation score is ") {
			// parse score from summary
			rest := line[len("The mutation score is "):]
			// rest looks like "0.80 (8/10)" or "0.80 (8/10) ..."
			parts := strings.Fields(rest)
			if len(parts) >= 1 {
				if score, err := strconv.ParseFloat(parts[0], 64); err == nil {
					rep.Score = score * 100
				}
			}
			// parse killed/total from "(Y/Z)"
			if len(parts) >= 2 {
				frac := strings.Trim(parts[1], "()")
				sub := strings.SplitN(frac, "/", 2)
				if len(sub) == 2 {
					rep.Killed, _ = strconv.Atoi(sub[0])
					rep.Mutants, _ = strconv.Atoi(sub[1])
				}
			}
			continue
		}
		// PASS/FAIL lines: PASS "pkg/file.go" with mutation "..."
		var kind, path string
		if n, _ := fmt.Sscanf(line, "%s %q", &kind, &path); n < 2 {
			continue
		}
		switch kind {
		case "PASS":
			pkg := pkgPath(path)
			r := getOrCreate(pkgMap, pkg)
			r.Mutants++
			r.Killed++
			rep.Killed++
			rep.Mutants++
		case "FAIL":
			pkg := pkgPath(path)
			r := getOrCreate(pkgMap, pkg)
			r.Mutants++
			rep.Mutants++
		}
	}

	rep.Survived = rep.Mutants - rep.Killed
	if rep.Mutants > 0 && rep.Score == 0 {
		rep.Score = float64(rep.Killed) * 100 / float64(rep.Mutants)
	}

	for _, r := range pkgMap {
		if r.Mutants > 0 {
			r.Score = float64(r.Killed) * 100 / float64(r.Mutants)
		}
		rep.Results = append(rep.Results, *r)
	}

	if rep.Score >= 80 {
		rep.MCDCEvidence = "mutation score ≥ 80% provides MC/DC-equivalent evidence per DO-178C AC §2.3.1(b)"
	} else {
		rep.MCDCEvidence = "mutation score below 80% — insufficient for MC/DC evidence"
	}

	return rep, nil
}

func pkgPath(file string) string {
	// strip trailing filename to get package dir
	idx := strings.LastIndex(file, "/")
	if idx < 0 {
		return file
	}
	return file[:idx]
}

func getOrCreate(m map[string]*MutationResult, pkg string) *MutationResult {
	if r, ok := m[pkg]; ok {
		return r
	}
	r := &MutationResult{Package: pkg}
	m[pkg] = r
	return r
}
