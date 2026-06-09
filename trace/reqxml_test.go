package trace_test

import (
	"strings"
	"testing"

	"github.com/SoundMatt/go-FuSa/trace"
)

// ─── DOORS ReqIF ─────────────────────────────────────────────────────────────

//fusa:test REQ-TRACE006
func TestParseDOORS_Basic(t *testing.T) {
	xmlData := `<?xml version="1.0"?>
<REQ-IF>
  <CORE-CONTENT>
    <SPEC-OBJECTS>
      <SPEC-OBJECT>
        <VALUES>
          <ATTRIBUTE-VALUE-STRING THE-VALUE="REQ-001">
            <DEFINITION><ATTRIBUTE-DEFINITION-STRING-REF>id</ATTRIBUTE-DEFINITION-STRING-REF></DEFINITION>
          </ATTRIBUTE-VALUE-STRING>
          <ATTRIBUTE-VALUE-STRING THE-VALUE="My Title">
            <DEFINITION><ATTRIBUTE-DEFINITION-STRING-REF>title</ATTRIBUTE-DEFINITION-STRING-REF></DEFINITION>
          </ATTRIBUTE-VALUE-STRING>
        </VALUES>
      </SPEC-OBJECT>
    </SPEC-OBJECTS>
  </CORE-CONTENT>
</REQ-IF>`
	reqs, err := trace.ParseDOORS([]byte(xmlData))
	if err != nil {
		t.Fatalf("ParseDOORS: %v", err)
	}
	if len(reqs) != 1 {
		t.Fatalf("want 1 req, got %d", len(reqs))
	}
	if reqs[0].ID != "REQ-001" {
		t.Errorf("ID = %q", reqs[0].ID)
	}
	if reqs[0].Title != "My Title" {
		t.Errorf("Title = %q", reqs[0].Title)
	}
}

//fusa:test REQ-TRACE006
func TestParseDOORS_Empty(t *testing.T) {
	xmlData := `<?xml version="1.0"?>
<REQ-IF>
  <CORE-CONTENT>
    <SPEC-OBJECTS>
    </SPEC-OBJECTS>
  </CORE-CONTENT>
</REQ-IF>`
	reqs, err := trace.ParseDOORS([]byte(xmlData))
	if err != nil {
		t.Fatalf("ParseDOORS empty: %v", err)
	}
	if len(reqs) != 0 {
		t.Errorf("want 0 reqs, got %d", len(reqs))
	}
}

//fusa:test REQ-TRACE006
func TestParseDOORS_WithText(t *testing.T) {
	xmlData := `<?xml version="1.0"?>
<REQ-IF>
  <CORE-CONTENT>
    <SPEC-OBJECTS>
      <SPEC-OBJECT>
        <VALUES>
          <ATTRIBUTE-VALUE-STRING THE-VALUE="REQ-002">
            <DEFINITION><ATTRIBUTE-DEFINITION-STRING-REF>id</ATTRIBUTE-DEFINITION-STRING-REF></DEFINITION>
          </ATTRIBUTE-VALUE-STRING>
          <ATTRIBUTE-VALUE-STRING THE-VALUE="Title Two">
            <DEFINITION><ATTRIBUTE-DEFINITION-STRING-REF>title</ATTRIBUTE-DEFINITION-STRING-REF></DEFINITION>
          </ATTRIBUTE-VALUE-STRING>
          <ATTRIBUTE-VALUE-STRING THE-VALUE="Full body text">
            <DEFINITION><ATTRIBUTE-DEFINITION-STRING-REF>text</ATTRIBUTE-DEFINITION-STRING-REF></DEFINITION>
          </ATTRIBUTE-VALUE-STRING>
        </VALUES>
      </SPEC-OBJECT>
    </SPEC-OBJECTS>
  </CORE-CONTENT>
</REQ-IF>`
	reqs, err := trace.ParseDOORS([]byte(xmlData))
	if err != nil {
		t.Fatalf("ParseDOORS with text: %v", err)
	}
	if len(reqs) != 1 {
		t.Fatalf("want 1 req, got %d", len(reqs))
	}
	if reqs[0].Text != "Full body text" {
		t.Errorf("Text = %q", reqs[0].Text)
	}
}

//fusa:test REQ-TRACE006
func TestExportDOORS_RoundTrip(t *testing.T) {
	original := []trace.Requirement{
		{ID: "REQ-001", Title: "Authentication", Text: "The system shall authenticate users."},
		{ID: "REQ-002", Title: "Authorization"},
	}
	data, err := trace.ExportDOORS(original)
	if err != nil {
		t.Fatalf("ExportDOORS: %v", err)
	}
	if !strings.Contains(string(data), "REQ-001") {
		t.Error("exported data missing REQ-001")
	}
	if !strings.Contains(string(data), "REQ-IF") {
		t.Error("exported data missing REQ-IF root element")
	}

	parsed, err := trace.ParseDOORS(data)
	if err != nil {
		t.Fatalf("ParseDOORS after export: %v", err)
	}
	if len(parsed) != len(original) {
		t.Fatalf("want %d reqs after round-trip, got %d", len(original), len(parsed))
	}
	for i, r := range parsed {
		if r.ID != original[i].ID {
			t.Errorf("[%d] ID = %q, want %q", i, r.ID, original[i].ID)
		}
		if r.Title != original[i].Title {
			t.Errorf("[%d] Title = %q, want %q", i, r.Title, original[i].Title)
		}
	}
}

//fusa:test REQ-TRACE006
func TestParseDOORS_InvalidXML(t *testing.T) {
	_, err := trace.ParseDOORS([]byte("not xml at all"))
	if err == nil {
		t.Error("expected error for invalid XML")
	}
}

// ─── Polarion XML ─────────────────────────────────────────────────────────────

//fusa:test REQ-TRACE006
func TestParsePolarion_Basic(t *testing.T) {
	xmlData := `<?xml version="1.0"?>
<workitems>
  <workitem id="REQ-001">
    <title>Requirement Title</title>
    <description>Full requirement body</description>
  </workitem>
</workitems>`
	reqs, err := trace.ParsePolarion([]byte(xmlData))
	if err != nil {
		t.Fatalf("ParsePolarion: %v", err)
	}
	if len(reqs) != 1 {
		t.Fatalf("want 1 req, got %d", len(reqs))
	}
	if reqs[0].ID != "REQ-001" {
		t.Errorf("ID = %q", reqs[0].ID)
	}
	if reqs[0].Title != "Requirement Title" {
		t.Errorf("Title = %q", reqs[0].Title)
	}
	if reqs[0].Text != "Full requirement body" {
		t.Errorf("Text = %q", reqs[0].Text)
	}
}

//fusa:test REQ-TRACE006
func TestParsePolarion_WithCustomFields(t *testing.T) {
	xmlData := `<?xml version="1.0"?>
<workitems>
  <workitem id="REQ-002">
    <title>Safety Req</title>
    <customFields>
      <customField id="asil" value="ASIL-B"/>
    </customFields>
  </workitem>
</workitems>`
	reqs, err := trace.ParsePolarion([]byte(xmlData))
	if err != nil {
		t.Fatalf("ParsePolarion with custom fields: %v", err)
	}
	if len(reqs) != 1 {
		t.Fatalf("want 1 req, got %d", len(reqs))
	}
	if reqs[0].ASIL != "ASIL-B" {
		t.Errorf("ASIL = %q, want ASIL-B", reqs[0].ASIL)
	}
}

//fusa:test REQ-TRACE006
func TestExportPolarion_RoundTrip(t *testing.T) {
	original := []trace.Requirement{
		{ID: "REQ-001", Title: "Auth", Text: "Shall authenticate", ASIL: "ASIL-B"},
		{ID: "REQ-002", Title: "Logging"},
	}
	data, err := trace.ExportPolarion(original)
	if err != nil {
		t.Fatalf("ExportPolarion: %v", err)
	}
	if !strings.Contains(string(data), "workitems") {
		t.Error("exported data missing workitems root")
	}

	parsed, err := trace.ParsePolarion(data)
	if err != nil {
		t.Fatalf("ParsePolarion after export: %v", err)
	}
	if len(parsed) != len(original) {
		t.Fatalf("want %d reqs after round-trip, got %d", len(original), len(parsed))
	}
	if parsed[0].ASIL != "ASIL-B" {
		t.Errorf("ASIL round-trip = %q, want ASIL-B", parsed[0].ASIL)
	}
}

// ─── Codebeamer XML ───────────────────────────────────────────────────────────

//fusa:test REQ-TRACE006
func TestParseCodebeamer_Basic(t *testing.T) {
	xmlData := `<?xml version="1.0"?>
<tracker>
  <item id="1001">
    <name>REQ-001</name>
    <summary>Requirement title text</summary>
    <description>Full requirement body</description>
  </item>
</tracker>`
	reqs, err := trace.ParseCodebeamer([]byte(xmlData))
	if err != nil {
		t.Fatalf("ParseCodebeamer: %v", err)
	}
	if len(reqs) != 1 {
		t.Fatalf("want 1 req, got %d", len(reqs))
	}
	// id attr takes precedence
	if reqs[0].ID != "1001" {
		t.Errorf("ID = %q, want 1001", reqs[0].ID)
	}
	if reqs[0].Title != "Requirement title text" {
		t.Errorf("Title = %q", reqs[0].Title)
	}
	if reqs[0].Text != "Full requirement body" {
		t.Errorf("Text = %q", reqs[0].Text)
	}
}

//fusa:test REQ-TRACE006
func TestParseCodebeamer_WithCustomFields(t *testing.T) {
	xmlData := `<?xml version="1.0"?>
<tracker>
  <item id="1002">
    <name>REQ-002</name>
    <summary>Safety requirement</summary>
    <customFields>
      <field id="asil">ASIL-B</field>
      <field id="level">HLR</field>
    </customFields>
  </item>
</tracker>`
	reqs, err := trace.ParseCodebeamer([]byte(xmlData))
	if err != nil {
		t.Fatalf("ParseCodebeamer with fields: %v", err)
	}
	if len(reqs) != 1 {
		t.Fatalf("want 1 req, got %d", len(reqs))
	}
	if reqs[0].ASIL != "ASIL-B" {
		t.Errorf("ASIL = %q, want ASIL-B", reqs[0].ASIL)
	}
	if reqs[0].Level != "HLR" {
		t.Errorf("Level = %q, want HLR", reqs[0].Level)
	}
}

//fusa:test REQ-TRACE006
func TestExportCodebeamer_RoundTrip(t *testing.T) {
	original := []trace.Requirement{
		{ID: "REQ-001", Title: "First", Text: "Body", ASIL: "ASIL-B", Level: "HLR"},
		{ID: "REQ-002", Title: "Second"},
	}
	data, err := trace.ExportCodebeamer(original)
	if err != nil {
		t.Fatalf("ExportCodebeamer: %v", err)
	}
	if !strings.Contains(string(data), "tracker") {
		t.Error("exported data missing tracker root element")
	}

	parsed, err := trace.ParseCodebeamer(data)
	if err != nil {
		t.Fatalf("ParseCodebeamer after export: %v", err)
	}
	if len(parsed) != len(original) {
		t.Fatalf("want %d reqs after round-trip, got %d", len(original), len(parsed))
	}
	if parsed[0].ASIL != "ASIL-B" {
		t.Errorf("ASIL round-trip = %q, want ASIL-B", parsed[0].ASIL)
	}
	if parsed[0].Level != "HLR" {
		t.Errorf("Level round-trip = %q, want HLR", parsed[0].Level)
	}
}

// ─── Jama XML ─────────────────────────────────────────────────────────────────

//fusa:test REQ-TRACE006
func TestParseJama_Basic(t *testing.T) {
	xmlData := `<?xml version="1.0"?>
<items>
  <item id="REQ-001" itemType="TEXT">
    <name>Requirement title</name>
    <description>Full body text</description>
  </item>
</items>`
	reqs, err := trace.ParseJama([]byte(xmlData))
	if err != nil {
		t.Fatalf("ParseJama: %v", err)
	}
	if len(reqs) != 1 {
		t.Fatalf("want 1 req, got %d", len(reqs))
	}
	if reqs[0].ID != "REQ-001" {
		t.Errorf("ID = %q", reqs[0].ID)
	}
	if reqs[0].Title != "Requirement title" {
		t.Errorf("Title = %q", reqs[0].Title)
	}
	if reqs[0].Text != "Full body text" {
		t.Errorf("Text = %q", reqs[0].Text)
	}
}

//fusa:test REQ-TRACE006
func TestParseJama_WithFields(t *testing.T) {
	xmlData := `<?xml version="1.0"?>
<items>
  <item id="REQ-002" itemType="TEXT">
    <name>Safety req</name>
    <fields>
      <field id="asil" value="ASIL-B"/>
      <field id="level" value="LLR"/>
    </fields>
  </item>
</items>`
	reqs, err := trace.ParseJama([]byte(xmlData))
	if err != nil {
		t.Fatalf("ParseJama with fields: %v", err)
	}
	if len(reqs) != 1 {
		t.Fatalf("want 1 req, got %d", len(reqs))
	}
	if reqs[0].ASIL != "ASIL-B" {
		t.Errorf("ASIL = %q, want ASIL-B", reqs[0].ASIL)
	}
	if reqs[0].Level != "LLR" {
		t.Errorf("Level = %q, want LLR", reqs[0].Level)
	}
}

//fusa:test REQ-TRACE006
func TestExportJama_RoundTrip(t *testing.T) {
	original := []trace.Requirement{
		{ID: "REQ-001", Title: "Authentication", Text: "Shall auth users", ASIL: "ASIL-B", Level: "HLR"},
		{ID: "REQ-002", Title: "Logging"},
	}
	data, err := trace.ExportJama(original)
	if err != nil {
		t.Fatalf("ExportJama: %v", err)
	}
	if !strings.Contains(string(data), "items") {
		t.Error("exported data missing items root element")
	}

	parsed, err := trace.ParseJama(data)
	if err != nil {
		t.Fatalf("ParseJama after export: %v", err)
	}
	if len(parsed) != len(original) {
		t.Fatalf("want %d reqs after round-trip, got %d", len(original), len(parsed))
	}
	for i, r := range parsed {
		if r.ID != original[i].ID {
			t.Errorf("[%d] ID = %q, want %q", i, r.ID, original[i].ID)
		}
	}
	if parsed[0].ASIL != "ASIL-B" {
		t.Errorf("ASIL round-trip = %q, want ASIL-B", parsed[0].ASIL)
	}
}

//fusa:test REQ-TRACE006
func TestParseJama_Empty(t *testing.T) {
	xmlData := `<?xml version="1.0"?>
<items>
</items>`
	reqs, err := trace.ParseJama([]byte(xmlData))
	if err != nil {
		t.Fatalf("ParseJama empty: %v", err)
	}
	if len(reqs) != 0 {
		t.Errorf("want 0 reqs, got %d", len(reqs))
	}
}
