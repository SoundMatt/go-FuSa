// Package misra provides a MISRA C:2023 to Go / go-FuSa rule mapping report.
//
// It statically maps MISRA C:2023 directives and rules to their equivalent
// coverage in Go, go vet, and go-FuSa rules. Use Assess to get the full
// mapping, and Render to format it.
//
// Usage:
//
//	rep := misra.Assess()
//	_ = misra.Render(os.Stdout, rep, "text")
package misra

import (
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// Coverage describes how a MISRA rule is addressed.
//
//fusa:req REQ-MISRA001
type Coverage string

const (
	// CoverageGofusa means the rule is enforced by a go-FuSa rule.
	CoverageGofusa Coverage = "go-FuSa rule"
	// CoverageGovet means the rule is enforced by go vet or the Go compiler.
	CoverageGovet Coverage = "go vet / compiler"
	// CoverageNA means the rule is not applicable because Go's type system prevents the issue.
	CoverageNA Coverage = "N/A — Go type system prevents this"
	// CoverageManual means the rule requires manual review.
	CoverageManual Coverage = "manual review"
)

// Rule is a single MISRA C:2023 rule and its Go coverage mapping.
//
//fusa:req REQ-MISRA002
type Rule struct {
	ID         string   `json:"id"`       // e.g. "Dir 4.1"
	Category   string   `json:"category"` // "Required" / "Advisory"
	Title      string   `json:"title"`
	Coverage   Coverage `json:"coverage"`
	GoFuSaRule string   `json:"gofusaRule,omitempty"` // e.g. "LINT004"
	Notes      string   `json:"notes,omitempty"`
}

// Report is the full MISRA C:2023 coverage mapping.
//
//fusa:req REQ-MISRA003
type Report struct {
	Generated time.Time `json:"generated"`
	Total     int       `json:"total"`
	Covered   int       `json:"covered"` // go-FuSa + go vet
	NA        int       `json:"na"`
	Manual    int       `json:"manual"`
	Rules     []Rule    `json:"rules"`
}

// allRules is the static MISRA C:2023 to Go/go-FuSa mapping table.
var allRules = []Rule{
	// ── Directives ──────────────────────────────────────────────────────────
	{
		"Dir 1.1", "Required",
		"Any implementation-defined behaviour on which the output of the program depends shall be documented and understood",
		CoverageGovet, "", "Go spec fully defines behaviour; go vet checks portability",
	},
	{
		"Dir 2.1", "Required",
		"All source files shall compile without any compilation errors",
		CoverageGovet, "", "Go compiler enforces this; build errors are fatal",
	},
	{
		"Dir 4.1", "Required",
		"Run-time failures shall be minimised",
		CoverageManual, "", "Enforce via LINT001, LINT002, ANA003 and runtime watchdog",
	},
	{
		"Dir 4.2", "Advisory",
		"All usage of assembly language should be documented",
		CoverageNA, "", "Go has no inline assembly; cgo asm files require manual review",
	},
	{
		"Dir 4.3", "Required",
		"Assembly language shall be encapsulated and isolated",
		CoverageNA, "", "Go does not support inline assembly",
	},
	{
		"Dir 4.4", "Advisory",
		"Sections of code should not be 'commented out'",
		CoverageManual, "", "Static analysis heuristic; not enforced automatically",
	},
	{
		"Dir 4.5", "Advisory",
		"Identifiers in the same namespace with overlapping visibility should be typographically unambiguous",
		CoverageGovet, "", "Go compiler rejects shadowing in most cases; go vet shadow",
	},
	{
		"Dir 4.6", "Advisory",
		"typedefs that indicate size and signedness should be used in place of the basic numerical types",
		CoverageNA, "", "Go's int/uint types are unambiguously sized; no typedef confusion",
	},
	{
		"Dir 4.7", "Required",
		"If a function returns error information, then that error information shall be tested",
		CoverageGofusa, "LINT001", "LINT001 flags ignored error returns",
	},
	{
		"Dir 4.8", "Advisory",
		"If a pointer to a struct or union is never dereferenced within a translation unit, then the implementation of the object should be hidden",
		CoverageNA, "", "Go interfaces enforce this pattern by design",
	},
	{
		"Dir 4.9", "Advisory",
		"A function should be used in preference to a function-like macro where they are interchangeable",
		CoverageNA, "", "Go has no preprocessor macros",
	},
	{
		"Dir 4.10", "Required",
		"Precautions shall be taken in order to prevent the contents of a header file being included more than once",
		CoverageNA, "", "Go package system prevents this by design",
	},
	{
		"Dir 4.11", "Required",
		"The validity of values passed to library functions shall be checked",
		CoverageManual, "", "Reviewed via LINT001 + manual inspection of stdlib usage",
	},
	{
		"Dir 4.12", "Required",
		"Dynamic memory allocation shall not be used",
		CoverageManual, "", "Go uses GC; LINT004 (unsafe) and manual review apply",
	},
	{
		"Dir 4.13", "Advisory",
		"Functions which are designed to provide operations on a resource should be called in an appropriate sequence",
		CoverageManual, "", "Reviewed via code review and ANA003 (deferred cleanup)",
	},
	{
		"Dir 4.14", "Required",
		"The validity of values received from external sources shall be checked",
		CoverageManual, "", "Manual review of all external interface inputs",
	},
	// ── Rules ────────────────────────────────────────────────────────────────
	{
		"Rule 1.1", "Required",
		"The program shall contain no violations of the standard C syntax and constraints",
		CoverageNA, "", "Go has no undefined behaviour from syntax violations",
	},
	{
		"Rule 1.2", "Advisory",
		"Language extensions should not be used",
		CoverageNA, "", "Go has no preprocessor or compiler extensions in the C sense",
	},
	{
		"Rule 1.3", "Required",
		"There shall be no occurrence of undefined or critical unspecified behaviour",
		CoverageNA, "", "Go specification eliminates undefined behaviour",
	},
	{
		"Rule 2.1", "Required",
		"A project shall not contain unreachable code",
		CoverageGofusa, "ANA009", "ANA009 detects unreachable code paths",
	},
	{
		"Rule 2.2", "Required",
		"There shall be no dead code",
		CoverageGofusa, "ANA009", "ANA009 detects dead/unreachable code",
	},
	{
		"Rule 2.3", "Advisory",
		"A project should not contain unused type declarations",
		CoverageGovet, "", "Go compiler errors on unused imports; vet catches others",
	},
	{
		"Rule 2.4", "Advisory",
		"A project should not contain unused tag declarations",
		CoverageGovet, "", "Go compiler enforces this",
	},
	{
		"Rule 2.5", "Advisory",
		"A project should not contain unused macro declarations",
		CoverageNA, "", "Go has no macros",
	},
	{
		"Rule 2.6", "Advisory",
		"A function should not contain unused label declarations",
		CoverageGovet, "", "Go compiler errors on unused labels",
	},
	{
		"Rule 2.7", "Advisory",
		"There should be no unused parameters in functions",
		CoverageGovet, "", "Linter / staticcheck detects unused parameters",
	},
	{
		"Rule 5.1", "Required",
		"External identifiers shall be distinct",
		CoverageGovet, "", "Go compiler enforces unique identifiers in package scope",
	},
	{
		"Rule 5.2", "Required",
		"Identifiers declared in the same scope and namespace shall be distinct",
		CoverageGovet, "", "Go compiler rejects duplicate declarations in same scope",
	},
	{
		"Rule 5.3", "Required",
		"An identifier declared in an inner scope shall not hide an identifier declared in an outer scope",
		CoverageGovet, "", "go vet -shadow detects identifier shadowing",
	},
	{
		"Rule 5.4", "Required",
		"Macro identifiers shall be distinct",
		CoverageNA, "", "Go has no macros",
	},
	{
		"Rule 5.5", "Required",
		"Identifiers shall be distinct from macro names",
		CoverageNA, "", "Go has no macros",
	},
	{
		"Rule 5.6", "Required",
		"A typedef name shall be a unique identifier",
		CoverageGovet, "", "Go type names must be unique within a package",
	},
	{
		"Rule 5.7", "Required",
		"A tag name shall be a unique identifier",
		CoverageGovet, "", "Struct/interface names must be unique; compiler enforces",
	},
	{
		"Rule 5.8", "Required",
		"Identifiers that define objects or functions with external linkage shall be unique",
		CoverageGovet, "", "Go compiler + linker enforce this",
	},
	{
		"Rule 5.9", "Advisory",
		"Identifiers that define objects or functions with internal linkage should be unique",
		CoverageGovet, "", "Go package-level unexported names enforced by compiler",
	},
	{
		"Rule 8.1", "Required",
		"Types shall be explicitly specified",
		CoverageNA, "", "Go's := infers types but they are unambiguous; explicit declaration encouraged",
	},
	{
		"Rule 8.2", "Required",
		"Function types shall be in prototype form with named parameters",
		CoverageNA, "", "Go functions always use named parameters in definitions",
	},
	{
		"Rule 8.13", "Advisory",
		"A pointer should point to a const-qualified type whenever possible",
		CoverageManual, "", "Go does not have const pointers; immutability via design",
	},
	{
		"Rule 10.1", "Required",
		"Operands shall not be of an inappropriate essential type",
		CoverageGofusa, "CYBER009", "CYBER009 checks unsafe type conversions",
	},
	{
		"Rule 10.2", "Required",
		"Expressions of essentially character type shall not be used inappropriately in addition and subtraction operations",
		CoverageNA, "", "Go type system prevents byte/rune arithmetic confusion",
	},
	{
		"Rule 10.3", "Required",
		"The value of an expression shall not be assigned to an object with a narrower essential type",
		CoverageGofusa, "CYBER009", "CYBER009 detects narrowing conversions",
	},
	{
		"Rule 10.4", "Required",
		"Both operands of an operator in which the usual arithmetic conversions are performed shall have the same essential type category",
		CoverageGovet, "", "Go compiler rejects mixed-type arithmetic without explicit cast",
	},
	{
		"Rule 10.5", "Advisory",
		"The value of an expression should not be cast to an inappropriate essential type",
		CoverageGofusa, "CYBER009", "CYBER009 reviews unsafe type assertions",
	},
	{
		"Rule 10.8", "Required",
		"The value of a composite expression shall not be cast to a different essential type category or a wider essential type",
		CoverageGofusa, "CYBER009", "",
	},
	{
		"Rule 11.1", "Required",
		"Conversions shall not be performed between a pointer to a function and any other type",
		CoverageGofusa, "CYBER004", "CYBER004 detects unsafe function pointer patterns",
	},
	{
		"Rule 11.2", "Required",
		"Conversions shall not be performed between a pointer to an incomplete type and any other type",
		CoverageNA, "", "Go interfaces handle polymorphism safely",
	},
	{
		"Rule 11.3", "Required",
		"A cast shall not be performed between a pointer to object type and a pointer to a different object type",
		CoverageGofusa, "CYBER004", "CYBER004 and LINT004 detect unsafe pointer casts",
	},
	{
		"Rule 11.4", "Advisory",
		"A conversion should not be performed between a pointer to object and an integer type",
		CoverageGofusa, "LINT004", "LINT004 flags unsafe package usage",
	},
	{
		"Rule 11.5", "Advisory",
		"A conversion should not be performed from pointer to void into pointer to object",
		CoverageNA, "", "Go does not have void pointers; unsafe.Pointer is flagged by LINT004",
	},
	{
		"Rule 11.6", "Required",
		"A cast shall not be performed between pointer to void and an arithmetic type",
		CoverageGofusa, "LINT004", "LINT004 catches unsafe.Pointer arithmetic",
	},
	{
		"Rule 11.7", "Required",
		"A cast shall not be performed between pointer to object and a non-integer arithmetic type",
		CoverageNA, "", "Go type system prevents this pattern",
	},
	{
		"Rule 11.8", "Required",
		"A cast shall not remove any const or volatile qualification from the type pointed to by a pointer",
		CoverageNA, "", "Go has no const qualification on pointers",
	},
	{
		"Rule 13.1", "Required",
		"Initializer lists shall not contain persistent side effects",
		CoverageManual, "", "Composite literals reviewed during code review",
	},
	{
		"Rule 13.2", "Required",
		"The value of an expression and its persistent side effects shall be the same under all permitted evaluation orders",
		CoverageManual, "", "Go evaluation order is defined but side effects reviewed manually",
	},
	{
		"Rule 13.3", "Advisory",
		"A full expression containing an increment (++) or decrement (--) operator should have no other potential side effects other than that caused by the operator",
		CoverageManual, "", "Code review",
	},
	{
		"Rule 13.4", "Advisory",
		"The result of an assignment operator should not be used",
		CoverageManual, "", "Code review; rare in idiomatic Go",
	},
	{
		"Rule 14.1", "Required",
		"A loop counter shall not have essentially floating-point type",
		CoverageGovet, "", "Go range loops over floats are uncommon; vet catches range misuse",
	},
	{
		"Rule 14.2", "Required",
		"A for loop shall be well-formed",
		CoverageGovet, "", "Go for loops are well-formed by construction",
	},
	{
		"Rule 14.3", "Required",
		"Controlling expressions shall not be invariant",
		CoverageManual, "", "Reviewed as part of ANA009 unreachable analysis",
	},
	{
		"Rule 14.4", "Required",
		"The controlling expression of an if statement and the controlling expression of an iteration-statement shall have essentially Boolean type",
		CoverageNA, "", "Go enforces boolean conditions in if/for by language spec",
	},
	{
		"Rule 15.1", "Advisory",
		"The goto statement should not be used",
		CoverageManual, "", "Code review — goto rare in Go",
	},
	{
		"Rule 15.2", "Required",
		"The goto statement shall jump to a label declared later in the same function",
		CoverageGovet, "", "Go compiler enforces forward-only goto",
	},
	{
		"Rule 15.3", "Required",
		"Any label referenced by a goto statement shall be declared in the same block, or in any block enclosing the goto statement",
		CoverageGovet, "", "Go compiler enforces label scope",
	},
	{
		"Rule 15.4", "Advisory",
		"There should be no more than one break or goto statement used to terminate any iteration statement",
		CoverageManual, "", "Code review",
	},
	{
		"Rule 15.5", "Advisory",
		"A function should have a single point of exit at the end",
		CoverageManual, "", "Code review — multiple returns are idiomatic in Go",
	},
	{
		"Rule 15.6", "Required",
		"The body of an iteration-statement or a selection-statement shall be a compound statement",
		CoverageNA, "", "Go requires braces for all control structures",
	},
	{
		"Rule 15.7", "Required",
		"All if … else if constructs shall be terminated with an else statement",
		CoverageManual, "", "Code review",
	},
	{
		"Rule 16.1", "Required",
		"All switch statements shall be well-formed",
		CoverageGofusa, "COMP001", "COMP001 assesses switch complexity",
	},
	{
		"Rule 16.2", "Required",
		"A switch label shall only be used when the most closely-enclosing compound statement is the body of a switch statement",
		CoverageNA, "", "Go switch syntax prevents misuse",
	},
	{
		"Rule 16.3", "Required",
		"An unconditional break statement shall terminate every switch-clause",
		CoverageNA, "", "Go switch cases do not fall through by default (unlike C)",
	},
	{
		"Rule 16.4", "Required",
		"Every switch statement shall have a default label",
		CoverageManual, "", "Code review — idiomatic Go often omits default for exhaustive switches",
	},
	{
		"Rule 16.5", "Required",
		"A default label shall appear as either the first or the last switch label of a switch statement",
		CoverageManual, "", "Code review",
	},
	{
		"Rule 17.1", "Required",
		"The features of <stdarg.h> shall not be used",
		CoverageNA, "", "Go does not have C-style variadic functions via stdarg",
	},
	{
		"Rule 17.2", "Required",
		"Functions shall not call themselves, either directly or indirectly",
		CoverageManual, "", "Code review — recursion reviewed for stack depth",
	},
	{
		"Rule 17.3", "Mandatory",
		"A function shall not be declared implicitly",
		CoverageNA, "", "Go requires explicit function declarations",
	},
	{
		"Rule 17.4", "Mandatory",
		"All exit paths from a function with non-void return type shall have an explicit return statement with an expression",
		CoverageGovet, "", "Go compiler enforces this",
	},
	{
		"Rule 17.5", "Advisory",
		"The function argument corresponding to a parameter declared to have an array type shall have an appropriate number of elements",
		CoverageNA, "", "Go slice bounds are checked at runtime",
	},
	{
		"Rule 17.6", "Mandatory",
		"The declaration of an array parameter shall not contain the static keyword between the [ ]",
		CoverageNA, "", "Go does not use C static array parameter syntax",
	},
	{
		"Rule 17.7", "Required",
		"The value returned by a function having non-void return type shall be used",
		CoverageGofusa, "LINT001", "LINT001 enforces error return checking",
	},
	{
		"Rule 17.8", "Advisory",
		"A function parameter should not be modified",
		CoverageManual, "", "Code review — idiomatic Go uses named return or new var",
	},
	{
		"Rule 18.1", "Required",
		"A pointer resulting from arithmetic on a pointer operand shall address an element of the same array as that pointer operand",
		CoverageNA, "", "Go slice indexing is bounds-checked at runtime",
	},
	{
		"Rule 18.2", "Required",
		"Subtraction between pointers shall only be applied to pointers that address elements of the same array",
		CoverageNA, "", "Go pointer arithmetic requires unsafe; LINT004 flags this",
	},
	{
		"Rule 18.3", "Required",
		"The relational operators >, >=, <, and <= shall not be applied to objects of pointer type except where they point into the same object",
		CoverageNA, "", "Go does not support pointer comparison with relational operators",
	},
	{
		"Rule 18.4", "Advisory",
		"The +, -, += and -= operators should not be applied to an expression of pointer type",
		CoverageGofusa, "LINT004", "LINT004 detects unsafe pointer arithmetic",
	},
	{
		"Rule 18.5", "Advisory",
		"Declarations should contain no more than two levels of pointer nesting",
		CoverageManual, "", "Code review",
	},
	{
		"Rule 18.6", "Required",
		"The address of an object with automatic storage shall not be copied to another object that persists after the first object has ceased to exist",
		CoverageNA, "", "Go's GC and escape analysis prevent dangling pointers",
	},
	{
		"Rule 18.7", "Required",
		"Flexible array members shall not be declared",
		CoverageNA, "", "Go does not have C flexible array members",
	},
	{
		"Rule 18.8", "Required",
		"Variable-length array types shall not be used",
		CoverageNA, "", "Go does not have C VLAs",
	},
	{
		"Rule 21.1", "Required",
		"#define and #undef shall not be used on a reserved identifier or reserved macro name",
		CoverageNA, "", "Go has no macros",
	},
	{
		"Rule 21.2", "Required",
		"A reserved identifier or macro name shall not be declared",
		CoverageGovet, "", "Go compiler prevents reuse of built-in names",
	},
	{
		"Rule 21.3", "Required",
		"The memory allocation and deallocation functions of <stdlib.h> shall not be used",
		CoverageManual, "", "Go uses GC; unsafe.Pointer and cgo reviewed via LINT004/CYBER001",
	},
	{
		"Rule 21.4", "Required",
		"The standard header file <setjmp.h> shall not be used",
		CoverageNA, "", "Go does not have setjmp/longjmp",
	},
	{
		"Rule 21.5", "Required",
		"The standard header file <signal.h> shall not be used",
		CoverageGofusa, "CYBER001", "CYBER001 reviews unsafe system calls including signals",
	},
	{
		"Rule 21.6", "Required",
		"The Standard Library input/output functions shall not be used",
		CoverageGofusa, "CYBER002", "CYBER002 reviews unsafe I/O patterns",
	},
	{
		"Rule 21.7", "Required",
		"The atof, atoi, atol, and atoll functions of <stdlib.h> shall not be used",
		CoverageNA, "", "Go standard library uses strconv which returns errors",
	},
	{
		"Rule 21.8", "Required",
		"The library functions abort, exit, getenv and system of <stdlib.h> shall not be used",
		CoverageGofusa, "CYBER003", "CYBER003 flags os.Exit and os.Getenv misuse",
	},
	{
		"Rule 21.9", "Required",
		"The library functions bsearch, qsort, and strtok of <stdlib.h> shall not be used",
		CoverageNA, "", "Go sort/strings packages are safe; no C-style strtok",
	},
	{
		"Rule 22.1", "Required",
		"All resources obtained dynamically by means of a Standard Library function shall be explicitly released",
		CoverageManual, "", "Code review + ANA003 (deferred resource release)",
	},
	{
		"Rule 22.2", "Mandatory",
		"A block of memory shall only be freed if it was allocated by means of a Standard Library function",
		CoverageNA, "", "Go GC manages memory; no manual free needed",
	},
	{
		"Rule 22.3", "Required",
		"The same file shall not be open for read and write access at the same time on different streams",
		CoverageManual, "", "Code review",
	},
	{
		"Rule 22.4", "Mandatory",
		"There shall be no attempt to write to a stream which has been opened as read-only",
		CoverageManual, "", "Code review; Go's os.OpenFile flags prevent this at OS level",
	},
	{
		"Rule 22.5", "Mandatory",
		"A pointer to a FILE object shall not be dereferenced",
		CoverageNA, "", "Go's os.File is an opaque handle",
	},
	{
		"Rule 22.6", "Mandatory",
		"The value of a pointer to a FILE shall not be used after the associated stream has been closed",
		CoverageManual, "", "Code review — closed file handles reviewed for use-after-close",
	},
}

// Assess builds the full MISRA C:2023 coverage report.
//
//fusa:req REQ-MISRA004
func Assess() *Report {
	rep := &Report{Generated: time.Now().UTC()}
	for _, r := range allRules {
		rep.Total++
		switch r.Coverage {
		case CoverageGofusa, CoverageGovet:
			rep.Covered++
		case CoverageNA:
			rep.NA++
		case CoverageManual:
			rep.Manual++
		}
		rep.Rules = append(rep.Rules, r)
	}
	return rep
}

// Render writes the MISRA coverage report to w in the requested format ("text" or "json").
//
//fusa:req REQ-MISRA005
func Render(w io.Writer, rep *Report, format string) error {
	switch format {
	case "json", "":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	case "text":
		return renderText(w, rep)
	default:
		return fmt.Errorf("misra: unsupported format %q", format)
	}
}

func renderText(w io.Writer, rep *Report) error {
	covPct := 0.0
	if rep.Total > 0 {
		covPct = float64(rep.Covered) * 100 / float64(rep.Total)
	}
	fmt.Fprintf(w, "MISRA C:2023 Coverage Report — generated %s\n", rep.Generated.Format("2006-01-02"))
	fmt.Fprintf(w, "Total: %d rules  Covered: %d (%.0f%%)  N/A: %d  Manual: %d\n\n",
		rep.Total, rep.Covered, covPct, rep.NA, rep.Manual)

	// Group: Directives first, then Rules
	for _, prefix := range []string{"Dir", "Rule"} {
		heading := "Directives"
		if prefix == "Rule" {
			heading = "Rules"
		}
		printed := false
		for _, r := range rep.Rules {
			isDir := len(r.ID) > 3 && r.ID[:3] == "Dir"
			if prefix == "Dir" && !isDir {
				continue
			}
			if prefix == "Rule" && isDir {
				continue
			}
			if !printed {
				fmt.Fprintf(w, "%s\n", heading)
				fmt.Fprintf(w, "%-12s %-12s %-35s %-30s %s\n",
					"ID", "Category", "Title", "Coverage", "go-FuSa")
				fmt.Fprintln(w, "──────────────────────────────────────────────────────────────────────────────────────────────────────────────")
				printed = true
			}
			title := r.Title
			if len(title) > 34 {
				title = title[:31] + "..."
			}
			fmt.Fprintf(w, "%-12s %-12s %-35s %-30s %s\n",
				r.ID, r.Category, title, r.Coverage, r.GoFuSaRule)
		}
		if printed {
			fmt.Fprintln(w)
		}
	}
	return nil
}
