package impact

// Internal tests for unexported functions in the impact package.

import "testing"

// TestAppendUniq_NewElement verifies that a new element is appended.
func TestAppendUniq_NewElement(t *testing.T) {
	s := []string{"a", "b"}
	got := appendUniq(s, "c")
	if len(got) != 3 {
		t.Fatalf("appendUniq: expected 3 elements, got %d", len(got))
	}
	if got[2] != "c" {
		t.Errorf("appendUniq: expected 'c' at index 2, got %q", got[2])
	}
}

// TestAppendUniq_DuplicateNotAdded verifies that a duplicate is not appended.
func TestAppendUniq_DuplicateNotAdded(t *testing.T) {
	s := []string{"x", "y", "z"}
	got := appendUniq(s, "y")
	if len(got) != 3 {
		t.Fatalf("appendUniq: expected slice length 3 after duplicate insert, got %d", len(got))
	}
}

// TestAppendUniq_EmptySlice verifies behaviour with a nil/empty slice.
func TestAppendUniq_EmptySlice(t *testing.T) {
	got := appendUniq(nil, "first")
	if len(got) != 1 {
		t.Fatalf("appendUniq: expected 1 element on nil slice, got %d", len(got))
	}
	if got[0] != "first" {
		t.Errorf("appendUniq: expected 'first', got %q", got[0])
	}
}
