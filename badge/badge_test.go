package badge_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/SoundMatt/go-FuSa/badge"
)

//fusa:test REQ-BADGE001
func TestNew_Status(t *testing.T) {
	cases := []struct {
		errors, warnings int
		want             badge.Status
	}{
		{0, 0, badge.StatusPass},
		{0, 3, badge.StatusWarn},
		{1, 0, badge.StatusFail},
		{2, 5, badge.StatusFail},
	}
	for _, tc := range cases {
		b := badge.New(tc.errors, tc.warnings, "0.17.0")
		if b.Status != tc.want {
			t.Errorf("New(%d,%d): got %d, want %d", tc.errors, tc.warnings, b.Status, tc.want)
		}
	}
}

//fusa:test REQ-BADGE002
func TestRender_ProducesSVG(t *testing.T) {
	b := badge.New(0, 0, "0.17.0")
	var buf bytes.Buffer
	if err := badge.Render(&buf, b); err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "<svg") {
		t.Error("expected <svg element in output")
	}
	if !strings.Contains(out, "go-fusa") {
		t.Error("expected label in SVG")
	}
	if !strings.Contains(out, "passing") {
		t.Error("expected passing status in SVG")
	}
}

func TestRender_FailStatus(t *testing.T) {
	b := badge.New(2, 0, "0.17.0")
	var buf bytes.Buffer
	_ = badge.Render(&buf, b)
	if !strings.Contains(buf.String(), "failing") {
		t.Error("expected failing in error badge")
	}
}

func TestRender_WarnStatus(t *testing.T) {
	b := badge.New(0, 5, "0.17.0")
	var buf bytes.Buffer
	_ = badge.Render(&buf, b)
	if !strings.Contains(buf.String(), "warnings") {
		t.Error("expected warnings in warn badge")
	}
}
