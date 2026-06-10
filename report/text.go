package report

import (
	"fmt"
	"io"
	"strings"
)

func renderText(w io.Writer, r *Report) error {
	lines := []string{
		"go-FuSa Safety Report",
		fmt.Sprintf("Generated: %s", r.GeneratedAt.Format("2006-01-02 15:04:05 UTC")),
		fmt.Sprintf("Project:   %s", r.ProjectRoot),
		"",
	}
	for _, l := range lines {
		if _, err := fmt.Fprintln(w, l); err != nil {
			return err
		}
	}

	if len(r.Findings) == 0 {
		if _, err := fmt.Fprintln(w, "No findings. All checks passed."); err != nil {
			return err
		}
	} else {
		//fusa:req REQ-RPT001
		for _, f := range r.Findings {
			loc := f.Location.File
			if f.Location.Line > 0 {
				loc = fmt.Sprintf("%s:%d", loc, f.Location.Line)
				if f.Location.Column > 0 {
					loc = fmt.Sprintf("%s:%d", loc, f.Location.Column)
				}
			}
			msg := fmt.Sprintf("[%s] %s  %s", f.Severity, f.RuleID, f.Message)
			if loc != "" {
				msg += fmt.Sprintf(" (%s)", loc)
			}
			if _, err := fmt.Fprintln(w, msg); err != nil {
				return err
			}
			if f.Remediation != "" {
				if _, err := fmt.Fprintf(w, "  → %s\n", f.Remediation); err != nil {
					return err
				}
			}
		}
	}

	if _, err := fmt.Fprintf(w, "\nSummary: %d total  %d errors  %d warnings  %d infos\n",
		r.Summary.Total, r.Summary.Errors, r.Summary.Warnings, r.Summary.Infos); err != nil {
		return err
	}
	//fusa:req REQ-RPT002
	result := "PASS"
	if r.Summary.Errors > 0 {
		result = "FAIL"
	}
	if _, err := fmt.Fprintf(w, "Result:  %s\n", result); err != nil {
		return err
	}
	if !r.NoSummary && len(r.SummaryTable.ByCategory) > 0 {
		return renderSummaryTable(w, r.SummaryTable)
	}
	return nil
}

const ruleCols = 53

func renderSummaryTable(w io.Writer, t SummaryTable) error {
	sep := strings.Repeat("─", ruleCols)

	// ── CATEGORY TABLE ────────────────────────────────────────────
	fmt.Fprintln(w)
	fmt.Fprintln(w, "SUMMARY")
	fmt.Fprintln(w, sep)
	fmt.Fprintf(w, "%-14s  %8s  %8s  %8s  %8s\n", "Category", "Errors", "Warnings", "Info", "Total")
	fmt.Fprintln(w, sep)
	var totErr, totWarn, totInfo, totAll int
	for _, row := range t.ByCategory {
		fmt.Fprintf(w, "%-14s  %8s  %8s  %8s  %8s\n",
			strings.ToLower(row.Category),
			commaInt(row.Errors), commaInt(row.Warnings),
			commaInt(row.Infos), commaInt(row.Total))
		totErr += row.Errors
		totWarn += row.Warnings
		totInfo += row.Infos
		totAll += row.Total
	}
	fmt.Fprintln(w, sep)
	fmt.Fprintf(w, "%-14s  %8s  %8s  %8s  %8s\n",
		"Total",
		commaInt(totErr), commaInt(totWarn), commaInt(totInfo), commaInt(totAll))

	// ── TOP RULES ─────────────────────────────────────────────────
	fmt.Fprintln(w)
	fmt.Fprintln(w, "TOP RULES")
	fmt.Fprintln(w, sep)
	fmt.Fprintf(w, "%-14s  %-7s  %8s\n", "Rule", "Sev", "Count")
	fmt.Fprintln(w, sep)
	const maxRules = 10
	shown := t.ByRule
	if len(shown) > maxRules {
		shown = shown[:maxRules]
	}
	for _, row := range shown {
		sev := abbreviateSev(row.Severity)
		fmt.Fprintf(w, "%-14s  %-7s  %8s\n", row.RuleID, sev, commaInt(row.Count))
	}
	if len(t.ByRule) > maxRules {
		fmt.Fprintf(w, "  ... and %d more rules\n", len(t.ByRule)-maxRules)
	}
	fmt.Fprintln(w, sep)
	_, err := fmt.Fprintf(w, "Files with findings: %s\n", commaInt(t.FileCount))
	return err
}
