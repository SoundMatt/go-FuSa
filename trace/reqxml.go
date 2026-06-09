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

// ─── Codebeamer XML ──────────────────────────────────────────────────────────

type codebeamerTracker struct {
	XMLName xml.Name         `xml:"tracker"`
	Items   []codebeamerItem `xml:"item"`
}

type codebeamerItem struct {
	ID           string                  `xml:"id,attr"`
	Name         string                  `xml:"name"`
	Summary      string                  `xml:"summary"`
	Description  string                  `xml:"description,omitempty"`
	CustomFields *codebeamerCustomFields `xml:"customFields,omitempty"`
}

type codebeamerCustomFields struct {
	Fields []codebeamerField `xml:"field"`
}

type codebeamerField struct {
	ID    string `xml:"id,attr"`
	Value string `xml:",chardata"`
}

// ParseCodebeamer parses a Codebeamer tracker XML export.
func ParseCodebeamer(data []byte) ([]Requirement, error) {
	var root codebeamerTracker
	if err := xml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("trace: parse Codebeamer XML: %w", err)
	}
	var reqs []Requirement
	for _, item := range root.Items {
		id := item.ID
		if id == "" {
			id = item.Name
		}
		if id == "" {
			continue
		}
		req := Requirement{
			ID:    id,
			Title: item.Summary,
			Text:  item.Description,
		}
		if item.CustomFields != nil {
			for _, f := range item.CustomFields.Fields {
				switch f.ID {
				case "asil":
					req.ASIL = f.Value
				case "level":
					req.Level = f.Value
				}
			}
		}
		reqs = append(reqs, req)
	}
	return reqs, nil
}

// ExportCodebeamer serialises requirements as Codebeamer tracker XML.
func ExportCodebeamer(reqs []Requirement) ([]byte, error) {
	var items []codebeamerItem
	for _, r := range reqs {
		item := codebeamerItem{
			ID:          r.ID,
			Name:        r.ID,
			Summary:     r.Title,
			Description: r.Text,
		}
		var fields []codebeamerField
		if r.ASIL != "" {
			fields = append(fields, codebeamerField{ID: "asil", Value: r.ASIL})
		}
		if r.Level != "" {
			fields = append(fields, codebeamerField{ID: "level", Value: r.Level})
		}
		if len(fields) > 0 {
			item.CustomFields = &codebeamerCustomFields{Fields: fields}
		}
		items = append(items, item)
	}

	root := codebeamerTracker{Items: items}
	out, err := xml.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("trace: export Codebeamer XML: %w", err)
	}
	var buf bytes.Buffer
	buf.WriteString(xml.Header)
	buf.Write(out)
	buf.WriteByte('\n')
	return buf.Bytes(), nil
}

// ─── Jama XML ─────────────────────────────────────────────────────────────────

type jamaItems struct {
	XMLName xml.Name   `xml:"items"`
	Items   []jamaItem `xml:"item"`
}

type jamaItem struct {
	ID       string      `xml:"id,attr"`
	ItemType string      `xml:"itemType,attr,omitempty"`
	Name     string      `xml:"name"`
	Desc     string      `xml:"description,omitempty"`
	Fields   *jamaFields `xml:"fields,omitempty"`
}

type jamaFields struct {
	Fields []jamaField `xml:"field"`
}

type jamaField struct {
	ID    string `xml:"id,attr"`
	Value string `xml:"value,attr"`
}

// ParseJama parses a Jama Connect XML export.
func ParseJama(data []byte) ([]Requirement, error) {
	var root jamaItems
	if err := xml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("trace: parse Jama XML: %w", err)
	}
	var reqs []Requirement
	for _, item := range root.Items {
		id := item.ID
		if id == "" {
			id = item.Name
		}
		if id == "" {
			continue
		}
		req := Requirement{
			ID:    id,
			Title: item.Name,
			Text:  item.Desc,
		}
		if item.Fields != nil {
			for _, f := range item.Fields.Fields {
				switch f.ID {
				case "asil":
					req.ASIL = f.Value
				case "level":
					req.Level = f.Value
				}
			}
		}
		reqs = append(reqs, req)
	}
	return reqs, nil
}

// ExportJama serialises requirements as Jama Connect XML.
func ExportJama(reqs []Requirement) ([]byte, error) {
	var items []jamaItem
	for _, r := range reqs {
		item := jamaItem{
			ID:   r.ID,
			Name: r.Title,
			Desc: r.Text,
		}
		var fields []jamaField
		if r.ASIL != "" {
			fields = append(fields, jamaField{ID: "asil", Value: r.ASIL})
		}
		if r.Level != "" {
			fields = append(fields, jamaField{ID: "level", Value: r.Level})
		}
		if len(fields) > 0 {
			item.Fields = &jamaFields{Fields: fields}
		}
		items = append(items, item)
	}

	root := jamaItems{Items: items}
	out, err := xml.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("trace: export Jama XML: %w", err)
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
