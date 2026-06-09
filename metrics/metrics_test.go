package metrics_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SoundMatt/go-FuSa/metrics"
)

func TestLoad_MissingFile(t *testing.T) {
	dir := t.TempDir()
	ts, err := metrics.Load(dir)
	if err != nil {
		t.Fatalf("Load missing file: %v", err)
	}
	if ts == nil {
		t.Fatal("expected non-nil time series")
	}
	if len(ts.Snapshots) != 0 {
		t.Errorf("expected 0 snapshots, got %d", len(ts.Snapshots))
	}
}

func TestLoad_InvalidFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, metrics.MetricsFile), []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := metrics.Load(dir)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestSave_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, metrics.MetricsFile)
	ts := &metrics.TimeSeries{
		Project: "test",
		Snapshots: []metrics.Snapshot{
			{
				Timestamp:         time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
				ErrorCount:        2,
				WarningCount:      5,
				TotalRequirements: 10,
				TracedRequirements: 8,
			},
		},
	}
	if err := metrics.Save(path, ts); err != nil {
		t.Fatalf("Save: %v", err)
	}
	loaded, err := metrics.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(loaded.Snapshots) != 1 {
		t.Fatalf("expected 1 snapshot, got %d", len(loaded.Snapshots))
	}
	if loaded.Snapshots[0].ErrorCount != 2 {
		t.Errorf("ErrorCount = %d", loaded.Snapshots[0].ErrorCount)
	}
}

func TestAppend(t *testing.T) {
	ts := &metrics.TimeSeries{}
	s1 := metrics.Snapshot{Timestamp: time.Now(), ErrorCount: 1}
	s2 := metrics.Snapshot{Timestamp: time.Now(), ErrorCount: 2}
	ts = metrics.Append(ts, s1)
	ts = metrics.Append(ts, s2)
	if len(ts.Snapshots) != 2 {
		t.Errorf("expected 2 snapshots, got %d", len(ts.Snapshots))
	}
}

func TestCollect_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	snap, err := metrics.Collect(dir)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if snap.ErrorCount != 0 {
		t.Errorf("ErrorCount = %d in empty dir", snap.ErrorCount)
	}
}

func TestCollect_WithCheckReport(t *testing.T) {
	dir := t.TempDir()
	report := `[{"ruleId":"FUSA001","severity":"ERROR"},{"ruleId":"FUSA002","severity":"WARNING"},{"ruleId":"FUSA003","severity":"INFO"}]`
	if err := os.WriteFile(filepath.Join(dir, "check-report.json"), []byte(report), 0o644); err != nil {
		t.Fatal(err)
	}
	snap, err := metrics.Collect(dir)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if snap.ErrorCount != 1 {
		t.Errorf("ErrorCount = %d, want 1", snap.ErrorCount)
	}
	if snap.WarningCount != 1 {
		t.Errorf("WarningCount = %d, want 1", snap.WarningCount)
	}
	if snap.InfoCount != 1 {
		t.Errorf("InfoCount = %d, want 1", snap.InfoCount)
	}
}

func TestCollect_WithCoverageReport(t *testing.T) {
	dir := t.TempDir()
	coverage := `{"stmtPct": 87.5, "branchPct": 75.0}`
	if err := os.WriteFile(filepath.Join(dir, "coverage-report.json"), []byte(coverage), 0o644); err != nil {
		t.Fatal(err)
	}
	snap, err := metrics.Collect(dir)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if snap.CoveragePct != 87.5 {
		t.Errorf("CoveragePct = %f, want 87.5", snap.CoveragePct)
	}
}

func TestRender_Text(t *testing.T) {
	ts := &metrics.TimeSeries{
		Project: "myproject",
		Snapshots: []metrics.Snapshot{
			{
				Timestamp:         time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
				ErrorCount:        0,
				TotalRequirements: 5,
				TracedRequirements: 5,
				CoveragePct:       92.0,
			},
		},
	}
	var buf bytes.Buffer
	if err := metrics.Render(&buf, ts, "text"); err != nil {
		t.Fatalf("Render text: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "go-FuSa Metrics") {
		t.Error("missing header in text output")
	}
	if !strings.Contains(out, "2026-01-01") {
		t.Error("missing date in text output")
	}
}

func TestRender_EmptySeries(t *testing.T) {
	ts := &metrics.TimeSeries{Project: "empty"}
	var buf bytes.Buffer
	if err := metrics.Render(&buf, ts, "text"); err != nil {
		t.Fatalf("Render text empty: %v", err)
	}
	if !strings.Contains(buf.String(), "No snapshots") {
		t.Error("missing 'No snapshots' message for empty series")
	}
}

func TestRender_JSON(t *testing.T) {
	ts := &metrics.TimeSeries{Project: "p"}
	var buf bytes.Buffer
	if err := metrics.Render(&buf, ts, "json"); err != nil {
		t.Fatalf("Render json: %v", err)
	}
	if !strings.Contains(buf.String(), `"project"`) {
		t.Error("missing project field in JSON")
	}
}

func TestRender_InvalidFormat(t *testing.T) {
	ts := &metrics.TimeSeries{}
	if err := metrics.Render(&bytes.Buffer{}, ts, "xml"); err == nil {
		t.Error("expected error for unsupported format")
	}
}
