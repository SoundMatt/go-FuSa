package report_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/SoundMatt/go-FuSa/report"
)

//fusa:test REQ-REPORT-SIL001
func TestReport_SILField_JSON(t *testing.T) {
	rep := report.New("/project", nil)
	rep.SIL = "SIL-3"
	rep.Standard = "IEC61508"
	var buf bytes.Buffer
	if err := report.Render(&buf, rep, "json"); err != nil {
		t.Fatalf("Render: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m["sil"] != "SIL-3" {
		t.Errorf("sil field = %v, want SIL-3", m["sil"])
	}
	if _, ok := m["asil"]; ok {
		t.Errorf("asil field should be absent when SIL is set, got %v", m["asil"])
	}
}

//fusa:test REQ-REPORT-SIL001
func TestReport_DALField_JSON(t *testing.T) {
	rep := report.New("/project", nil)
	rep.DAL = "DAL-C"
	rep.Standard = "DO178C"
	var buf bytes.Buffer
	if err := report.Render(&buf, rep, "json"); err != nil {
		t.Fatalf("Render: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m["dal"] != "DAL-C" {
		t.Errorf("dal field = %v, want DAL-C", m["dal"])
	}
}

//fusa:test REQ-REPORT-SIL001
func TestReport_ASILField_JSON(t *testing.T) {
	rep := report.New("/project", nil)
	rep.ASIL = "ASIL-B"
	rep.Standard = "ISO26262"
	var buf bytes.Buffer
	if err := report.Render(&buf, rep, "json"); err != nil {
		t.Fatalf("Render: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m["asil"] != "ASIL-B" {
		t.Errorf("asil field = %v, want ASIL-B", m["asil"])
	}
}

//fusa:test REQ-REPORT-SIL001
func TestReport_SILField_Text(t *testing.T) {
	rep := report.New("/project", nil)
	rep.SIL = "SIL-2"
	rep.Standard = "IEC61508"
	var buf bytes.Buffer
	if err := report.Render(&buf, rep, "text"); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(buf.String(), "SIL-2") {
		t.Errorf("expected SIL-2 in text output: %s", buf.String())
	}
}
