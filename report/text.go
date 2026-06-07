package report

import (
	"fmt"
	"io"
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
	result := "PASS"
	if r.Summary.Errors > 0 {
		result = "FAIL"
	}
	_, err := fmt.Fprintf(w, "Result:  %s\n", result)
	return err
}
