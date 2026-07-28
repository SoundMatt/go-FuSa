// Package sci produces the Software Configuration Index (SCI) required by
// DO-178C §11.16.
//
// The SCI is a formal inventory of all software lifecycle data items with
// SHA-256 checksums, lifecycle-data classification, and presence status.
// It can be written as JSON or Markdown.
package sci

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	fusa "github.com/SoundMatt/go-FuSa"
)

// SCIFile is the default output filename.
const SCIFile = "sci.json"

// DataClass classifies a lifecycle data item per DO-178C Table 1.
type DataClass string

const (
	ClassPlan           DataClass = "Plan"
	ClassDevelopment    DataClass = "Development"
	ClassVerification   DataClass = "Verification"
	ClassConfigMgt      DataClass = "Configuration Management"
	ClassQA             DataClass = "Quality Assurance"
	ClassAccomplishment DataClass = "Accomplishment Summary"
)

// Item is a single software lifecycle data item.
//
//fusa:req REQ-SCI001
type Item struct {
	Name    string    `json:"name"`
	File    string    `json:"file"`
	Class   DataClass `json:"class"`
	SHA256  string    `json:"sha256,omitempty"`
	Present bool      `json:"present"`
	Note    string    `json:"note,omitempty"`
}

// Artifact is the x-FuSa spec §9.3 `sci.json` canonical inventory row —
// file/hash/version, a project-relative projection of the richer Item
// model above, covering only present items (an absent item has no hash to
// report). Hash MUST be "sha256:"-prefixed (§2.7: a field named "hash",
// unlike a field named "sha256", carries the algo:value form).
//
//fusa:req REQ-SCI004
type Artifact struct {
	File    string `json:"file"`
	Hash    string `json:"hash"`
	Version string `json:"version,omitempty"`
}

// SCI is the complete Software Configuration Index.
//
//fusa:req REQ-SCI002
type SCI struct {
	// §3.1 common header.
	SchemaVersion string    `json:"schemaVersion"`
	Kind          string    `json:"kind"`
	Tool          string    `json:"tool"`
	ToolVersion   string    `json:"toolVersion"`
	Language      string    `json:"language"`
	GeneratedAt   time.Time `json:"generatedAt"`

	Project   string    `json:"project"`
	Version   string    `json:"version"`
	Generated time.Time `json:"generated"`
	Items     []Item    `json:"items"`

	// Artifacts is the x-FuSa spec §9.3 canonical projection of Items.
	Artifacts []Artifact `json:"artifacts"`
}

// catalog is the standard set of go-FuSa lifecycle data items.
var catalog = []struct {
	name  string
	file  string
	class DataClass
	note  string
}{
	{"Software Development Plan", "SAFETY_PLAN.md", ClassPlan, "DO-178C §11.1"},
	{"Software Verification Plan", "SVP.md", ClassPlan, "DO-178C §11.3"},
	{"Software Configuration Management Plan", "SCMP.md", ClassPlan, "DO-178C §11.4"},
	{"Software Quality Assurance Plan", "SQAP.md", ClassPlan, "DO-178C §11.5"},
	{"Requirements Manifest", ".fusa-reqs.json", ClassDevelopment, "DO-178C §11.9"},
	{"Project Configuration", ".fusa.json", ClassConfigMgt, "go-FuSa project config"},
	{"SBOM (SPDX 3.0.1)", "sbom.json", ClassConfigMgt, "DO-178C §11.15, NTIA SBOM"},
	{"Build Provenance", "provenance.json", ClassConfigMgt, "SLSA L2"},
	{"Artifact Manifest", "manifest.json", ClassConfigMgt, "go-FuSa release"},
	{"Test Evidence Bundle", ".fusa-evidence.json", ClassVerification, "DO-178C §11.14"},
	{"Vulnerability Report", "vuln.json", ClassVerification, "ISO 21434 / OSV"},
	{"FMEA Table", "fmea.json", ClassVerification, "DO-178C §11.9 (safety analysis)"},
	{"TARA Report", "tara.json", ClassVerification, "ISO 21434 §9"},
	{"TARA Markdown", "tara.md", ClassVerification, "ISO 21434 §9"},
	{"Boundary Diagram", "boundary.mermaid", ClassVerification, "DO-178C §11.10 (architecture)"},
	{"Cyber Report", "cyber-report.json", ClassVerification, "ISO 21434 §11"},
	{"Tool Qualification Report", "qualify-report.json", ClassQA, "DO-178C §12 / DO-330"},
	{"Safety Case", "safety-case.json", ClassAccomplishment, "DO-178C §11.20 (SAS input)"},
	{"Software Accomplishment Summary", "sas.md", ClassAccomplishment, "DO-178C §11.20"},
	{"Audit Pack", "audit-pack.zip", ClassConfigMgt, "go-FuSa audit bundle"},
	{"Problem Reports", ".fusa-problems.json", ClassQA, "DO-178C §11.17"},
	{"IEC 62443 Config", ".fusa-iec62443.json", ClassConfigMgt, "IEC 62443-4-1"},
	{"CODEOWNERS", ".github/CODEOWNERS", ClassConfigMgt, "SLSA L3 review evidence"},
	{"CI Workflow", ".github/workflows/ci.yml", ClassConfigMgt, "DO-178C §12.2 (tool env)"},
	{"Incident Response Plan", "INCIDENT-RESPONSE.md", ClassPlan, "IEC 62443-4-2 CR 6.2.1"},
	{"Security Policy", "SECURITY.md", ClassQA, "IEC 62443-4-2 CR 6.2"},
}

// Build scans projectRoot and returns a populated SCI.
//
//fusa:req REQ-SCI001
func Build(projectRoot, project, version string) (*SCI, error) {
	now := time.Now().UTC()
	sci := &SCI{
		SchemaVersion: fusa.SchemaVersion(),
		Kind:          "sci",
		Tool:          "go-FuSa",
		ToolVersion:   fusa.Version,
		Language:      "go",
		GeneratedAt:   now,
		Project:       project,
		Version:       version,
		Generated:     now,
	}
	for _, c := range catalog {
		item := Item{
			Name:  c.name,
			File:  c.file,
			Class: c.class,
			Note:  c.note,
		}
		path := fusa.ResolveDoc(projectRoot, c.file)
		if path == "" {
			path = filepath.Join(projectRoot, filepath.FromSlash(c.file))
		}
		if data, err := os.ReadFile(path); err == nil {
			item.Present = true
			h := sha256.Sum256(data)
			item.SHA256 = hex.EncodeToString(h[:])
			sci.Artifacts = append(sci.Artifacts, Artifact{
				File:    c.file,
				Hash:    "sha256:" + item.SHA256,
				Version: version,
			})
		}
		sci.Items = append(sci.Items, item)
	}
	return sci, nil
}

// LoadReport reads a persisted SCI from path (typically sci.json).
//
//fusa:req REQ-SCI005
func LoadReport(path string) (*SCI, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s SCI
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("%w: %s: %s", fusa.ErrInvalidConfig, path, err)
	}
	return &s, nil
}

// SaveJSON writes the SCI as indented JSON to path.
//
//fusa:req REQ-SCI002
func SaveJSON(path string, sci *SCI) error {
	data, err := json.MarshalIndent(sci, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o640)
}

// Render writes the SCI in the requested format ("json" or "markdown") to w.
//
//fusa:req REQ-SCI003
func Render(w io.Writer, sci *SCI, format string) error {
	switch format {
	case "json", "":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(sci)
	case "markdown":
		return renderMarkdown(w, sci)
	default:
		return fmt.Errorf("sci: unsupported format %q", format)
	}
}

func renderMarkdown(w io.Writer, sci *SCI) error {
	present, total := 0, len(sci.Items)
	for _, it := range sci.Items {
		if it.Present {
			present++
		}
	}

	fmt.Fprintf(w, "# Software Configuration Index\n\n")
	fmt.Fprintf(w, "**Project:** %s  \n", sci.Project)
	fmt.Fprintf(w, "**Version:** %s  \n", sci.Version)
	fmt.Fprintf(w, "**Generated:** %s  \n", sci.Generated.Format(time.RFC3339))
	fmt.Fprintf(w, "**Completeness:** %d / %d items present\n\n", present, total)
	fmt.Fprintf(w, "_Produced by go-FuSa — DO-178C §11.16_\n\n")

	classes := []DataClass{ClassPlan, ClassDevelopment, ClassVerification, ClassConfigMgt, ClassQA, ClassAccomplishment}
	for _, class := range classes {
		var rows []Item
		for _, it := range sci.Items {
			if it.Class == class {
				rows = append(rows, it)
			}
		}
		if len(rows) == 0 {
			continue
		}
		fmt.Fprintf(w, "## %s\n\n", class)
		fmt.Fprintf(w, "| Item | File | Present | SHA-256 | Note |\n")
		fmt.Fprintf(w, "|---|---|:---:|---|---|\n")
		for _, it := range rows {
			status := "✗"
			if it.Present {
				status = "✓"
			}
			hash := it.SHA256
			if len(hash) > 12 {
				hash = hash[:12] + "…"
			}
			fmt.Fprintf(w, "| %s | `%s` | %s | `%s` | %s |\n",
				it.Name, it.File, status, hash, it.Note)
		}
		fmt.Fprintln(w)
	}
	return nil
}
