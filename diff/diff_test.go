package diff_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/diff"
	"github.com/SoundMatt/go-FuSa/report"
)

func makeReport(findings []fusa.Finding) *report.Report {
	return report.New("/proj", findings)
}

//fusa:test REQ-DIFF001
func TestCompare_Introduced(t *testing.T) {
	base := makeReport(nil)
	cur := makeReport([]fusa.Finding{
		{RuleID: "FUSA001", Severity: fusa.SeverityWarning, Message: "m", Location: fusa.Location{File: "a.go", Line: 1}},
	})
	d := diff.Compare(base, cur)
	if len(d.Introduced) != 1 {
		t.Errorf("Introduced: want 1 got %d", len(d.Introduced))
	}
	if len(d.Resolved) != 0 {
		t.Errorf("Resolved: want 0 got %d", len(d.Resolved))
	}
}

func TestCompare_Resolved(t *testing.T) {
	base := makeReport([]fusa.Finding{
		{RuleID: "FUSA001", Severity: fusa.SeverityWarning, Message: "m", Location: fusa.Location{File: "a.go", Line: 1}},
	})
	cur := makeReport(nil)
	d := diff.Compare(base, cur)
	if len(d.Resolved) != 1 {
		t.Errorf("Resolved: want 1 got %d", len(d.Resolved))
	}
	if len(d.Introduced) != 0 {
		t.Errorf("Introduced: want 0 got %d", len(d.Introduced))
	}
}

func TestCompare_Unchanged(t *testing.T) {
	f := fusa.Finding{RuleID: "FUSA001", Severity: fusa.SeverityWarning, Message: "m", Location: fusa.Location{File: "a.go", Line: 1}}
	base := makeReport([]fusa.Finding{f})
	cur := makeReport([]fusa.Finding{f})
	d := diff.Compare(base, cur)
	if len(d.Unchanged) != 1 {
		t.Errorf("Unchanged: want 1 got %d", len(d.Unchanged))
	}
	if len(d.Introduced) != 0 || len(d.Resolved) != 0 {
		t.Error("unexpected introduced/resolved for identical reports")
	}
}

//fusa:test REQ-DIFF002
func TestLoadReport(t *testing.T) {
	r := makeReport([]fusa.Finding{
		{RuleID: "FUSA001", Severity: fusa.SeverityInfo, Message: "test", Location: fusa.Location{File: "x.go", Line: 5}},
	})
	data, _ := json.MarshalIndent(r, "", "  ")
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, data, 0o640); err != nil {
		t.Fatal(err)
	}
	loaded, err := diff.LoadReport(path)
	if err != nil {
		t.Fatalf("LoadReport: %v", err)
	}
	if len(loaded.Findings) != 1 {
		t.Errorf("findings: want 1 got %d", len(loaded.Findings))
	}
}

func TestLoadReport_MissingFile(t *testing.T) {
	_, err := diff.LoadReport("/nonexistent/report.json")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

//fusa:test REQ-DIFF003
func TestRender_Text(t *testing.T) {
	d := &diff.Diff{
		Introduced: []fusa.Finding{{RuleID: "X", Message: "new", Location: fusa.Location{File: "f.go", Line: 1}}},
		Resolved:   []fusa.Finding{{RuleID: "Y", Message: "old", Location: fusa.Location{File: "g.go", Line: 2}}},
	}
	var buf bytes.Buffer
	if err := diff.Render(&buf, d, "text"); err != nil {
		t.Fatalf("Render text: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Introduced: 1") {
		t.Error("expected introduced count")
	}
	if !strings.Contains(out, "[+]") {
		t.Error("expected [+] prefix for introduced finding")
	}
	if !strings.Contains(out, "[-]") {
		t.Error("expected [-] prefix for resolved finding")
	}
}

func TestRender_JSON(t *testing.T) {
	d := &diff.Diff{}
	var buf bytes.Buffer
	if err := diff.Render(&buf, d, "json"); err != nil {
		t.Fatalf("Render json: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
}

func TestRender_UnknownFormat(t *testing.T) {
	if err := diff.Render(&bytes.Buffer{}, &diff.Diff{}, "xml"); err == nil {
		t.Error("expected error for unsupported format")
	}
}
