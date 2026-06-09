// Package trace — DOORS ReqIF and Polarion XML import/export.
package trace

import (
	"bytes"
	"encoding/xml"
	"fmt"
)

// ─── DOORS ReqIF ─────────────────────────────────────────────────────────────

// reqifRoot is the minimal ReqIF XML structure for parsing.
type reqifRoot struct {
	XMLName     xml.Name  `xml:"REQ-IF"`
	CoreContent reqifCore `xml:"CORE-CONTENT"`
}

type reqifCore struct {
	SpecObjects reqifSpecObjects `xml:"SPEC-OBJECTS"`
}

type reqifSpecObjects struct {
	Objects []reqifSpecObject `xml:"SPEC-OBJECT"`
}

type reqifSpecObject struct {
	Values reqifValues `xml:"VALUES"`
}

type reqifValues struct {
	Attrs []reqifAttrValue `xml:"ATTRIBUTE-VALUE-STRING"`
}

type reqifAttrValue struct {
	TheValue string `xml:"THE-VALUE,attr"`
}

// ParseDOORS parses a ReqIF XML byte slice and returns Requirement records.
// It collects ATTRIBUTE-VALUE-STRING THE-VALUE attributes per SPEC-OBJECT
// positionally: [0]=id, [1]=title, [2]=text (if present).
func ParseDOORS(data []byte) ([]Requirement, error) {
	var root reqifRoot
	if err := xml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("trace: parse DOORS ReqIF: %w", err)
	}
	var reqs []Requirement
	for _, obj := range root.CoreContent.SpecObjects.Objects {
		attrs := obj.Values.Attrs
		if len(attrs) == 0 {
			continue
		}
		req := Requirement{}
		if len(attrs) >= 1 {
			req.ID = attrs[0].TheValue
		}
		if len(attrs) >= 2 {
			req.Title = attrs[1].TheValue
		}
		if len(attrs) >= 3 {
			req.Text = attrs[2].TheValue
		}
		if req.ID == "" {
			continue
		}
		reqs = append(reqs, req)
	}
	return reqs, nil
}

// ExportDOORS serialises requirements as minimal ReqIF XML.
func ExportDOORS(reqs []Requirement) ([]byte, error) {
	type attrDef struct {
		Ref string `xml:"ATTRIBUTE-DEFINITION-STRING-REF"`
	}
	type attrValStr struct {
		TheValue string  `xml:"THE-VALUE,attr"`
		Def      attrDef `xml:"DEFINITION"`
	}
	type values struct {
		Attrs []attrValStr `xml:"ATTRIBUTE-VALUE-STRING"`
	}
	type specObj struct {
		Vals values `xml:"VALUES"`
	}
	type specObjs struct {
		Objects []specObj `xml:"SPEC-OBJECT"`
	}
	type coreContent struct {
		SpecObjects specObjs `xml:"SPEC-OBJECTS"`
	}
	type reqif struct {
		XMLName     xml.Name    `xml:"REQ-IF"`
		CoreContent coreContent `xml:"CORE-CONTENT"`
	}

	var objs []specObj
	for _, r := range reqs {
		attrs := []attrValStr{
			{TheValue: r.ID, Def: attrDef{Ref: "attr-id"}},
			{TheValue: r.Title, Def: attrDef{Ref: "attr-title"}},
		}
		if r.Text != "" {
			attrs = append(attrs, attrValStr{TheValue: r.Text, Def: attrDef{Ref: "attr-text"}})
		}
		objs = append(objs, specObj{Vals: values{Attrs: attrs}})
	}

	root := reqif{
		CoreContent: coreContent{
			SpecObjects: specObjs{Objects: objs},
		},
	}

	out, err := xml.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("trace: export DOORS ReqIF: %w", err)
	}
	var buf bytes.Buffer
	buf.WriteString(xml.Header)
	buf.Write(out)
	buf.WriteByte('\n')
	return buf.Bytes(), nil
}

// ─── Polarion XML ─────────────────────────────────────────────────────────────

type polarionWorkitems struct {
	XMLName   xml.Name           `xml:"workitems"`
	Workitems []polarionWorkitem `xml:"workitem"`
}

type polarionWorkitem struct {
	ID           string                `xml:"id,attr"`
	Title        string                `xml:"title"`
	Description  string                `xml:"description,omitempty"`
	CustomFields *polarionCustomFields `xml:"customFields,omitempty"`
}

type polarionCustomFields struct {
	Fields []polarionCustomField `xml:"customField"`
}

type polarionCustomField struct {
	ID    string `xml:"id,attr"`
	Value string `xml:"value,attr"`
}

// ParsePolarion parses Polarion workitems XML and returns Requirement records.
func ParsePolarion(data []byte) ([]Requirement, error) {
	var root polarionWorkitems
	if err := xml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("trace: parse Polarion XML: %w", err)
	}
	var reqs []Requirement
	for _, wi := range root.Workitems {
		if wi.ID == "" {
			continue
		}
		req := Requirement{
			ID:    wi.ID,
			Title: wi.Title,
			Text:  wi.Description,
		}
		if wi.CustomFields != nil {
			for _, cf := range wi.CustomFields.Fields {
				if cf.ID == "asil" {
					req.ASIL = cf.Value
				}
			}
		}
		reqs = append(reqs, req)
	}
	return reqs, nil
}

// ExportPolarion serialises requirements as Polarion XML.
func ExportPolarion(reqs []Requirement) ([]byte, error) {
	var items []polarionWorkitem
	for _, r := range reqs {
		wi := polarionWorkitem{
			ID:          r.ID,
			Title:       r.Title,
			Description: r.Text,
		}
		if r.ASIL != "" {
			wi.CustomFields = &polarionCustomFields{
				Fields: []polarionCustomField{{ID: "asil", Value: r.ASIL}},
			}
		}
		items = append(items, wi)
	}

	root := polarionWorkitems{Workitems: items}
	out, err := xml.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("trace: export Polarion XML: %w", err)
	}
	var buf bytes.Buffer
	buf.WriteString(xml.Header)
	buf.Write(out)
	buf.WriteByte('\n')
	return buf.Bytes(), nil
}
