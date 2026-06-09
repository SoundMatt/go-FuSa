// Package coverage reads Go coverage profiles and produces DO-178C-style
// structural coverage reports (DO-178C §6.4.4, Annex A Table A-7).
//
// It reports statement coverage (always available), estimates decision coverage
// from branch data where present, and flags whether MC/DC evidence is required
// (DAL-A) but cannot be automatically verified.
package coverage

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
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
