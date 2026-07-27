package cyber_test

// Gap tests for isNolinted() in cyber.go (v0.33.1).
// Exercises the three inline-suppression comment forms:
//   //nolint:RULEID, //nolint:A,RULEID,B, //fusa:ignore RULEID

import "testing"

// isNolinted is exercised indirectly: a CYBER005 finding is suppressed when
// the exec.Command call has a matching inline comment on the same source line.

//fusa:test REQ-CYBER005
func TestIsNolinted_NolintDirective_SuppressesCYBER005(t *testing.T) {
	// //nolint:CYBER005 on the same line as exec.Command → first branch
	findings := runCyber(t, `package pkg
import "os/exec"
func Run(name string) { _ = exec.Command(name) //nolint:CYBER005
}
`)
	if hasRule(findings, "CYBER005") {
		t.Error("CYBER005: expected suppression by //nolint:CYBER005")
	}
}

//fusa:test REQ-CYBER005
func TestIsNolinted_NolintCommaList_SuppressesCYBER005(t *testing.T) {
	// //nolint:CYBER001,CYBER005 → second branch (strings.Contains(text, ","+ruleID))
	findings := runCyber(t, `package pkg
import "os/exec"
func Run(name string) { _ = exec.Command(name) //nolint:CYBER001,CYBER005
}
`)
	if hasRule(findings, "CYBER005") {
		t.Error("CYBER005: expected suppression by //nolint:CYBER001,CYBER005")
	}
}

//fusa:test REQ-CYBER005
func TestIsNolinted_FusaIgnore_SuppressesCYBER005(t *testing.T) {
	// //fusa:ignore CYBER005 → third branch
	findings := runCyber(t, `package pkg
import "os/exec"
func Run(name string) { _ = exec.Command(name) //fusa:ignore CYBER005
}
`)
	if hasRule(findings, "CYBER005") {
		t.Error("CYBER005: expected suppression by //fusa:ignore CYBER005")
	}
}

// Verify that a nolint comment for a DIFFERENT rule does NOT suppress CYBER005.
//
//fusa:test REQ-CYBER005
func TestIsNolinted_WrongRule_DoesNotSuppress(t *testing.T) {
	findings := runCyber(t, `package pkg
import "os/exec"
func Run(name string) { _ = exec.Command(name) //nolint:CYBER001
}
`)
	if !hasRule(findings, "CYBER005") {
		t.Error("CYBER005: should NOT be suppressed by //nolint:CYBER001")
	}
}
