package report

import (
	"sort"
	"strings"
	"unicode"

	fusa "github.com/SoundMatt/go-FuSa"
)


// CategoryRow holds aggregate finding counts for one rule-ID prefix category.
type CategoryRow struct {
	Category string `json:"category"`
	Errors   int    `json:"errors"`
	Warnings int    `json:"warnings"`
	Infos    int    `json:"infos"`
	Total    int    `json:"total"`
}

// RuleRow holds aggregate finding counts for one rule ID, sorted by count descending.
type RuleRow struct {
	RuleID   string        `json:"ruleId"`
	Severity fusa.Severity `json:"severity"` // highest severity seen for this rule
	Count    int           `json:"count"`
}

// SummaryTable holds per-category and per-rule finding breakdowns.
//
//fusa:req REQ-RPT006
type SummaryTable struct {
	ByCategory []CategoryRow `json:"by_category,omitempty"`
	ByRule     []RuleRow     `json:"by_rule,omitempty"`
	FileCount  int           `json:"file_count"`
}

// buildSummaryTable computes a SummaryTable from findings.
func buildSummaryTable(findings []fusa.Finding) SummaryTable {
	catMap := make(map[string]*CategoryRow)
	ruleMap := make(map[string]*RuleRow)
	fileSet := make(map[string]struct{})

	for _, f := range findings {
		cat := ruleCategory(f.RuleID)
		cr, ok := catMap[cat]
		if !ok {
			cr = &CategoryRow{Category: cat}
			catMap[cat] = cr
		}
		rr, ok := ruleMap[f.RuleID]
		if !ok {
			rr = &RuleRow{RuleID: f.RuleID, Severity: f.Severity}
			ruleMap[f.RuleID] = rr
		}
		switch f.Severity {
		case fusa.SeverityError:
			cr.Errors++
			rr.Severity = fusa.SeverityError // error dominates
		case fusa.SeverityWarning:
			cr.Warnings++
			if rr.Severity == fusa.SeverityInfo {
				rr.Severity = fusa.SeverityWarning
			}
		case fusa.SeverityInfo:
			cr.Infos++
		}
		cr.Total++
		rr.Count++
		if f.Location.File != "" {
			fileSet[f.Location.File] = struct{}{}
		}
	}

	cats := make([]CategoryRow, 0, len(catMap))
	for _, cr := range catMap {
		cats = append(cats, *cr)
	}
	sort.Slice(cats, func(i, j int) bool { return cats[i].Category < cats[j].Category })

	rules := make([]RuleRow, 0, len(ruleMap))
	for _, rr := range ruleMap {
		rules = append(rules, *rr)
	}
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Count != rules[j].Count {
			return rules[i].Count > rules[j].Count
		}
		return rules[i].RuleID < rules[j].RuleID
	})

	return SummaryTable{
		ByCategory: cats,
		ByRule:     rules,
		FileCount:  len(fileSet),
	}
}

// abbreviateSev returns a short severity label for text output.
func abbreviateSev(s fusa.Severity) string {
	switch s {
	case fusa.SeverityError:
		return "ERR"
	case fusa.SeverityWarning:
		return "WARN"
	default:
		return "INFO"
	}
}

// ruleCategory extracts the alphabetic prefix from a rule ID (e.g., "LINT001" → "LINT").
func ruleCategory(id string) string {
	for i, r := range id {
		if unicode.IsDigit(r) {
			return strings.ToUpper(id[:i])
		}
	}
	return strings.ToUpper(id)
}

// commaInt formats n with thousands separators (e.g., 1234567 → "1,234,567").
func commaInt(n int) string {
	return formatInt(n)
}

func formatInt(n int) string {
	neg := n < 0
	if neg {
		n = -n
	}
	digits := []byte(intToStr(n))
	var out []byte
	for i, d := range digits {
		if i > 0 && (len(digits)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, d)
	}
	if neg {
		return "-" + string(out)
	}
	return string(out)
}

func intToStr(n int) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 0, 20)
	for n > 0 {
		buf = append(buf, byte('0'+n%10))
		n /= 10
	}
	// reverse
	for i, j := 0, len(buf)-1; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}
	return string(buf)
}
