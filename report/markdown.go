package report

import (
	"fmt"
	"io"

	fusa "github.com/SoundMatt/go-FuSa"
)

// renderMarkdown emits a Markdown compliance report suitable for embedding in
// documentation pipelines (GitHub Wiki, Confluence, etc.).
//
//fusa:req REQ-REPORT-MD001
func renderMarkdown(w io.Writer, r *Report) error {
	level := r.ASIL
	if r.SIL != "" {
		level = r.SIL
	} else if r.DAL != "" {
		level = r.DAL
	}

	fmt.Fprintf(w, "# go-FuSa Compliance Report\n\n")
	if r.Standard != "" || level != "" {
		fmt.Fprintf(w, "**Standard:** %s", r.Standard)
		if level != "" {
			fmt.Fprintf(w, "  **Level:** %s", level)
		}
		fmt.Fprintf(w, "\n")
	}
	fmt.Fprintf(w, "**Project:** %s  **Generated:** %s\n\n",
		r.ProjectRoot, r.GeneratedAt.Format("2006-01-02"))

	fmt.Fprintf(w, "## Summary\n\n")
	fmt.Fprintf(w, "| Severity | Count |\n|---|---|\n")
	fmt.Fprintf(w, "| ERROR | %d |\n", r.Summary.Errors)
	fmt.Fprintf(w, "| WARNING | %d |\n", r.Summary.Warnings)
	fmt.Fprintf(w, "| INFO | %d |\n", r.Summary.Infos)
	fmt.Fprintf(w, "| **Total** | **%d** |\n\n", r.Summary.Total)

	if len(r.Findings) == 0 {
		fmt.Fprintf(w, "_No findings — all checks passed._\n")
		return nil
	}

	fmt.Fprintf(w, "## Findings\n\n")
	fmt.Fprintf(w, "| Rule | Severity | File | Line | Message |\n|---|---|---|---|---|\n")
	for _, f := range r.Findings {
		sev := string(f.Severity)
		switch f.Severity {
		case fusa.SeverityError:
			sev = "🔴 ERROR"
		case fusa.SeverityWarning:
			sev = "🟡 WARNING"
		case fusa.SeverityInfo:
			sev = "ℹ️ INFO"
		}
		fmt.Fprintf(w, "| `%s` | %s | `%s` | %d | %s |\n",
			f.RuleID, sev, f.Location.File, f.Location.Line, escapeMarkdown(f.Message))
	}
	return nil
}

func escapeMarkdown(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '|':
			out = append(out, '\\', '|')
		case '\n', '\r':
			out = append(out, ' ')
		default:
			out = append(out, c)
		}
	}
	return string(out)
}
