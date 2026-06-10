package fusa_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	fusa "github.com/SoundMatt/go-FuSa"
)

//fusa:test REQ-ERR001
func TestErrNoConfig_Wrappable(t *testing.T) {
	if fusa.ErrNoConfig == nil {
		t.Fatal("ErrNoConfig must not be nil")
	}
	wrapped := fmt.Errorf("context: %w", fusa.ErrNoConfig)
	if !errors.Is(wrapped, fusa.ErrNoConfig) {
		t.Error("ErrNoConfig: errors.Is must work on wrapped error")
	}
}

//fusa:test REQ-ERR002
func TestErrInvalidConfig_Wrappable(t *testing.T) {
	if fusa.ErrInvalidConfig == nil {
		t.Fatal("ErrInvalidConfig must not be nil")
	}
	wrapped := fmt.Errorf("context: %w", fusa.ErrInvalidConfig)
	if !errors.Is(wrapped, fusa.ErrInvalidConfig) {
		t.Error("ErrInvalidConfig: errors.Is must work on wrapped error")
	}
}

//fusa:test REQ-ERR003
func TestErrCheckFailed_Wrappable(t *testing.T) {
	if fusa.ErrCheckFailed == nil {
		t.Fatal("ErrCheckFailed must not be nil")
	}
	wrapped := fmt.Errorf("context: %w", fusa.ErrCheckFailed)
	if !errors.Is(wrapped, fusa.ErrCheckFailed) {
		t.Error("ErrCheckFailed: errors.Is must work on wrapped error")
	}
}

//fusa:test REQ-NF001
func TestNoExternalDependencies(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller: could not determine source file path")
	}
	root := filepath.Dir(file)
	data, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	content := string(data)
	if strings.Contains(content, "\nrequire ") || strings.Contains(content, "\nrequire(") {
		t.Error("go.mod must not declare external dependencies (zero-dep design)")
	}
}

func TestSeverity_String(t *testing.T) {
	cases := []struct {
		s    fusa.Severity
		want string
	}{
		{fusa.SeverityError, "ERROR"},
		{fusa.SeverityWarning, "WARNING"},
		{fusa.SeverityInfo, "INFO"},
	}
	for _, tc := range cases {
		if got := tc.s.String(); got != tc.want {
			t.Errorf("Severity(%q).String() = %q, want %q", tc.s, got, tc.want)
		}
	}
}

// ─── DeriveCategory ───────────────────────────────────────────────────────────

//fusa:test REQ-NF001
func TestDeriveCategory_KnownPrefixes(t *testing.T) {
	cases := []struct {
		ruleID string
		want   fusa.Category
	}{
		{"LINT001", fusa.CategoryLint},
		{"lint-foo", fusa.CategoryLint},
		{"STYLE001", fusa.CategoryStyle},
		{"FUSA001", fusa.CategorySafety},
		{"SEC001", fusa.CategorySecurity},
		{"CWE-79", fusa.CategorySecurity},
		{"CYBER001", fusa.CategorySecurity},
		{"COV001", fusa.CategoryCoverage},
		{"REQ-001", fusa.CategoryRequirement},
		{"TRACE001", fusa.CategoryRequirement},
		{"CONC001", fusa.CategoryConcurrency},
		{"RACE001", fusa.CategoryConcurrency},
		{"SBOM001", fusa.CategorySupplyChain},
		{"SLSA001", fusa.CategorySupplyChain},
		{"VULN001", fusa.CategorySupplyChain},
		{"RELEASE001", fusa.CategorySupplyChain},
		{"CFG001", fusa.CategoryConfig},
		{"ISO001", fusa.CategorySafety},
		{"IEC001", fusa.CategorySafety},
		{"DO001", fusa.CategorySafety},
		{"MISRA001", fusa.CategorySafety},
		{"AUTOSAR001", fusa.CategorySafety},
		{"CERT001", fusa.CategorySafety},
		{"UNECE001", fusa.CategorySafety},
		{"ANA001", fusa.CategorySafety},
		{"HARA001", fusa.CategorySafety},
		{"TARA001", fusa.CategorySafety},
	}
	for _, tc := range cases {
		got := fusa.DeriveCategory(tc.ruleID)
		if got != tc.want {
			t.Errorf("DeriveCategory(%q) = %q, want %q", tc.ruleID, got, tc.want)
		}
	}
}

//fusa:test REQ-NF001
func TestDeriveCategory_UnknownPrefix(t *testing.T) {
	got := fusa.DeriveCategory("XYZ999")
	if got != fusa.CategoryOther {
		t.Errorf("DeriveCategory(unknown) = %q, want %q", got, fusa.CategoryOther)
	}
}

//fusa:test REQ-NF001
func TestDeriveCategory_EmptyString(t *testing.T) {
	got := fusa.DeriveCategory("")
	if got != fusa.CategoryOther {
		t.Errorf("DeriveCategory(\"\") = %q, want %q", got, fusa.CategoryOther)
	}
}

//fusa:test REQ-NF001
func TestDeriveCategory_LowercaseInput(t *testing.T) {
	got := fusa.DeriveCategory("lint001")
	if got != fusa.CategoryLint {
		t.Errorf("DeriveCategory(lowercase lint) = %q, want %q", got, fusa.CategoryLint)
	}
}

//fusa:test REQ-NF001
func TestDeriveCategory_MixedCase(t *testing.T) {
	got := fusa.DeriveCategory("Fusa42")
	if got != fusa.CategorySafety {
		t.Errorf("DeriveCategory(Fusa42) = %q, want %q", got, fusa.CategorySafety)
	}
}

// ─── ComputeFingerprint ───────────────────────────────────────────────────────

//fusa:test REQ-NF001
func TestComputeFingerprint_Format(t *testing.T) {
	f := fusa.Finding{
		RuleID:  "LINT001",
		Message: "variable foo unused",
		Location: fusa.Location{
			File: "pkg/foo/bar.go",
			Line: 42,
		},
	}
	fp := fusa.ComputeFingerprint(f)
	if !strings.HasPrefix(fp, "sha256:") {
		t.Errorf("fingerprint should start with sha256:; got %q", fp)
	}
	// sha256 hex = 64 chars; total = len("sha256:") + 64 = 71
	if len(fp) != 71 {
		t.Errorf("fingerprint length = %d, want 71; got %q", len(fp), fp)
	}
}

//fusa:test REQ-NF001
func TestComputeFingerprint_Stable(t *testing.T) {
	f := fusa.Finding{
		RuleID:   "FUSA007",
		Message:  "unsafe.Pointer used in hot path",
		Location: fusa.Location{File: "runtime/safety.go", Line: 100},
	}
	fp1 := fusa.ComputeFingerprint(f)
	fp2 := fusa.ComputeFingerprint(f)
	if fp1 != fp2 {
		t.Errorf("fingerprint is not stable: %q != %q", fp1, fp2)
	}
}

//fusa:test REQ-NF001
func TestComputeFingerprint_DifferentRuleID(t *testing.T) {
	base := fusa.Finding{
		RuleID:   "LINT001",
		Message:  "unused variable",
		Location: fusa.Location{File: "main.go"},
	}
	other := base
	other.RuleID = "LINT002"
	if fusa.ComputeFingerprint(base) == fusa.ComputeFingerprint(other) {
		t.Error("different ruleIDs must produce different fingerprints")
	}
}

//fusa:test REQ-NF001
func TestComputeFingerprint_DifferentFile(t *testing.T) {
	base := fusa.Finding{
		RuleID:   "LINT001",
		Message:  "unused",
		Location: fusa.Location{File: "a.go"},
	}
	other := base
	other.Location.File = "b.go"
	if fusa.ComputeFingerprint(base) == fusa.ComputeFingerprint(other) {
		t.Error("different files must produce different fingerprints")
	}
}

//fusa:test REQ-NF001
func TestComputeFingerprint_MessageNormalization(t *testing.T) {
	// Messages that differ only in digit sequences or whitespace runs should
	// produce the same fingerprint (normalizeMessage behaviour).
	f1 := fusa.Finding{
		RuleID:   "COV001",
		Message:  "covered 42 of 100 statements",
		Location: fusa.Location{File: "foo.go"},
	}
	f2 := fusa.Finding{
		RuleID:   "COV001",
		Message:  "covered 7 of 9 statements",
		Location: fusa.Location{File: "foo.go"},
	}
	// Both normalise to "covered # of # statements" → same fingerprint
	if fusa.ComputeFingerprint(f1) != fusa.ComputeFingerprint(f2) {
		t.Error("messages differing only in numbers should yield the same fingerprint")
	}
}

//fusa:test REQ-NF001
func TestComputeFingerprint_WhitespaceCollapsed(t *testing.T) {
	f1 := fusa.Finding{RuleID: "X1", Message: "foo  bar", Location: fusa.Location{File: "f.go"}}
	f2 := fusa.Finding{RuleID: "X1", Message: "foo bar", Location: fusa.Location{File: "f.go"}}
	if fusa.ComputeFingerprint(f1) != fusa.ComputeFingerprint(f2) {
		t.Error("messages with collapsed whitespace must yield the same fingerprint")
	}
}
