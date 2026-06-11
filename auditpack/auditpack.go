// Package auditpack bundles all go-FuSa evidence artifacts into a single
// ZIP archive for submission to safety auditors (v0.13).
//
// Pack collects the standard evidence files present in a project root,
// computes SHA-256 digests, writes them into audit-pack.zip, and includes
// an AUDIT-MANIFEST.json inside the archive.
//
// Activate the engine rule by importing this package for its side effects:
//
//	import _ "github.com/SoundMatt/go-FuSa/auditpack"
package auditpack

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/config"
	"github.com/SoundMatt/go-FuSa/engine"
)

// AuditPackFile is the default output filename.
const AuditPackFile = "audit-pack.zip"

// AuditManifestEntry records a single file in the audit pack.
//
//fusa:req REQ-AUDIT002
type AuditManifestEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// AuditManifest is the index of all files in the audit pack (§8).
// It carries the §3.1 common header (kind: "audit-manifest").
type AuditManifest struct {
	SchemaVersion string               `json:"schemaVersion"`
	Kind          string               `json:"kind"`
	Tool          string               `json:"tool"`
	ToolVersion   string               `json:"toolVersion"`
	Language      string               `json:"language"`
	GeneratedAt   time.Time            `json:"generatedAt"`
	Module        string               `json:"module"`
	Files         []AuditManifestEntry `json:"files"`
}

// EvidenceFiles is the ordered list of evidence file names that Pack collects.
//
//fusa:req REQ-AUDIT001
var EvidenceFiles = []string{
	".fusa.json",
	".fusa-reqs.json",
	".fusa-evidence.json",
	"check-report.json",
	"fmea.json",
	"fmea.csv",
	"boundary.mermaid",
	"boundary.dot",
	"safety-case.json",
	"safety-case.md",
	"safety-case.mermaid",
	"sbom.json",
	"provenance.json",
	"artifact-manifest.json",
	"qualify-report.json",
	"vuln.json",
}

// Pack bundles all present evidence files from projectRoot into a ZIP archive
// at outputPath. It returns the AuditManifest describing what was packed.
//
//fusa:req REQ-AUDIT001
//fusa:req REQ-AUDIT002
//fusa:req REQ-AUDIT004
func Pack(projectRoot, outputPath string) (*AuditManifest, error) {
	module := readModule(projectRoot)
	manifest := &AuditManifest{
		SchemaVersion: fusa.SpecVersion,
		Kind:          "audit-manifest",
		Tool:          "go-FuSa",
		ToolVersion:   fusa.Version,
		Language:      "go",
		GeneratedAt:   time.Now().UTC(),
		Module:        module,
	}

	// Hash all evidence files that are present; skip absent ones.
	// Open-and-hash in a single step avoids a TOCTOU race (CWE-362).
	type fileEntry struct {
		name string
		path string
	}
	var present []fileEntry
	for _, name := range EvidenceFiles {
		path := filepath.Join(projectRoot, name)
		entry, err := hashFile(path, name)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("auditpack: hash %s: %w", name, err)
		}
		manifest.Files = append(manifest.Files, entry)
		present = append(present, fileEntry{name: name, path: path})
	}

	// Create ZIP
	f, err := os.Create(outputPath)
	if err != nil {
		return nil, fmt.Errorf("auditpack: create %s: %w", outputPath, err)
	}
	defer func() { _ = f.Close() }()

	zw := zip.NewWriter(f)
	defer func() { _ = zw.Close() }()

	// Write evidence files into ZIP
	for _, fe := range present {
		if addErr := addFileToZip(zw, fe.path, fe.name); addErr != nil {
			return nil, fmt.Errorf("auditpack: add %s: %w", fe.name, addErr)
		}
	}

	// Write AUDIT-MANIFEST.json last
	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("auditpack: marshal manifest: %w", err)
	}
	manifestJSON = append(manifestJSON, '\n')
	mw, err := zw.Create("AUDIT-MANIFEST.json")
	if err != nil {
		return nil, fmt.Errorf("auditpack: create manifest entry: %w", err)
	}
	if _, err := mw.Write(manifestJSON); err != nil {
		return nil, fmt.Errorf("auditpack: write manifest: %w", err)
	}

	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("auditpack: close zip: %w", err)
	}
	return manifest, nil
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func hashFile(path, name string) (AuditManifestEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return AuditManifestEntry{}, err
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return AuditManifestEntry{}, err
	}
	return AuditManifestEntry{
		Path:   name,
		SHA256: hex.EncodeToString(h.Sum(nil)),
		Size:   n,
	}, nil
}

func addFileToZip(zw *zip.Writer, path, name string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	w, err := zw.Create(name)
	if err != nil {
		return err
	}
	_, err = io.Copy(w, f)
	return err
}

func readModule(root string) string {
	data, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return ""
	}
	for _, line := range splitLines(string(data)) {
		line = trimSpace(line)
		if len(line) > 7 && line[:7] == "module " {
			return trimSpace(line[7:])
		}
	}
	return ""
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t' || s[0] == '\r') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}

// ─── engine rule ─────────────────────────────────────────────────────────────

func init() {
	engine.Default.MustRegister(&auditPack001Rule{})
}

type auditPack001Rule struct{}

func (r *auditPack001Rule) ID() string { return "AUDITPACK001" }
func (r *auditPack001Rule) Description() string {
	return "audit-pack.zip absent — run 'gofusa audit-pack' to bundle all evidence for auditors"
}

//fusa:req REQ-AUDIT003
func (r *auditPack001Rule) Run(_ context.Context, projectRoot string, cfg *config.Config) ([]fusa.Finding, error) {
	if _, err := os.Stat(filepath.Join(projectRoot, AuditPackFile)); err == nil {
		return nil, nil
	}
	return []fusa.Finding{{
		RuleID:      "AUDITPACK001",
		Severity:    fusa.SeverityInfo,
		Message:     "audit-pack.zip not found — run 'gofusa audit-pack' to bundle all evidence artifacts",
		Location:    fusa.Location{File: AuditPackFile},
		Remediation: "Run: gofusa audit-pack",
	}}, nil
}
