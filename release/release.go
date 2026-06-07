// Package release provides SBOM and build provenance generation for go-FuSa
// projects (v0.6).
//
// BuildSBOM parses go.mod and go.sum to produce a Software Bill of Materials.
// BuildProvenance records the current build environment including VCS state.
// HashFiles computes SHA-256 checksums for a set of artifact files.
//
// Activate the engine rules by importing this package for its side effects:
//
//	import _ "github.com/SoundMatt/go-FuSa/release"
package release

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/config"
	"github.com/SoundMatt/go-FuSa/engine"
)

// File name constants for release artefacts.
const (
	SBOMFile       = "sbom.json"
	ProvenanceFile = "provenance.json"
	ManifestFile   = "artifact-manifest.json"
)

// Component is a dependency entry in the SBOM.
type Component struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Hash    string `json:"hash,omitempty"` // h1: hash from go.sum
}

// SBOM is a go-FuSa Software Bill of Materials.
type SBOM struct {
	Format      string      `json:"format"`
	GeneratedAt time.Time   `json:"generatedAt"`
	Module      string      `json:"module"`
	GoVersion   string      `json:"goVersion"`
	Components  []Component `json:"components"`
}

// Provenance records the build environment for audit purposes.
type Provenance struct {
	Format      string    `json:"format"`
	GeneratedAt time.Time `json:"generatedAt"`
	Module      string    `json:"module"`
	GoVersion   string    `json:"goVersion"`
	GOOS        string    `json:"goos"`
	GOARCH      string    `json:"goarch"`
	VCSRevision string    `json:"vcsRevision,omitempty"`
	VCSModified bool      `json:"vcsModified"`
}

// Artifact is a file path paired with its SHA-256 checksum.
type Artifact struct {
	Path string `json:"path"`
	Hash string `json:"sha256"`
}

// Manifest lists the hashes of released artifact files.
type Manifest struct {
	Format      string     `json:"format"`
	GeneratedAt time.Time  `json:"generatedAt"`
	Artifacts   []Artifact `json:"artifacts"`
}

// BuildSBOM generates an SBOM by parsing go.mod and go.sum in projectRoot.
func BuildSBOM(projectRoot string) (*SBOM, error) {
	modPath, err := readModulePath(filepath.Join(projectRoot, "go.mod"))
	if err != nil {
		return nil, fmt.Errorf("release: read go.mod: %w", err)
	}
	goVersion, err := readGoVersion(filepath.Join(projectRoot, "go.mod"))
	if err != nil {
		return nil, fmt.Errorf("release: read go version from go.mod: %w", err)
	}
	components, err := readComponents(projectRoot)
	if err != nil {
		return nil, err
	}
	return &SBOM{
		Format:      "go-FuSa SBOM v1",
		GeneratedAt: time.Now().UTC(),
		Module:      modPath,
		GoVersion:   goVersion,
		Components:  components,
	}, nil
}

// BuildProvenance records the current build environment for projectRoot.
// ctx is used for the optional git subprocess calls.
func BuildProvenance(ctx context.Context, projectRoot string) (*Provenance, error) {
	modPath, err := readModulePath(filepath.Join(projectRoot, "go.mod"))
	if err != nil {
		return nil, fmt.Errorf("release: read go.mod: %w", err)
	}
	revision, modified := vcsInfo(ctx, projectRoot)
	return &Provenance{
		Format:      "go-FuSa Provenance v1",
		GeneratedAt: time.Now().UTC(),
		Module:      modPath,
		GoVersion:   runtime.Version(),
		GOOS:        runtime.GOOS,
		GOARCH:      runtime.GOARCH,
		VCSRevision: revision,
		VCSModified: modified,
	}, nil
}

// HashFiles computes SHA-256 checksums for each path in paths.
func HashFiles(paths []string) ([]Artifact, error) {
	artifacts := make([]Artifact, 0, len(paths))
	for _, p := range paths {
		h, err := hashFile(p)
		if err != nil {
			return nil, err
		}
		artifacts = append(artifacts, Artifact{Path: p, Hash: h})
	}
	return artifacts, nil
}

// SaveJSON writes v as indented JSON to path.
func SaveJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("release: marshal: %w", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		return fmt.Errorf("release: write %s: %w", path, err)
	}
	return nil
}

// ─── internal helpers ──────────────────────────────────────────────────────────

func readModulePath(gomod string) (string, error) {
	f, err := os.Open(gomod)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "module ")), nil
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("no module directive in %s", gomod)
}

func readGoVersion(gomod string) (string, error) {
	f, err := os.Open(gomod)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "go ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "go ")), nil
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "", nil
}

func readComponents(projectRoot string) ([]Component, error) {
	requires, err := parseRequires(filepath.Join(projectRoot, "go.mod"))
	if err != nil {
		return nil, err
	}
	hashes, err := parseSumHashes(filepath.Join(projectRoot, "go.sum"))
	if err != nil {
		return nil, err
	}
	components := make([]Component, 0, len(requires))
	for _, r := range requires {
		c := Component{Name: r[0], Version: r[1]}
		if h, ok := hashes[r[0]+" "+r[1]]; ok {
			c.Hash = h
		}
		components = append(components, c)
	}
	return components, nil
}

func parseRequires(gomod string) ([][2]string, error) {
	f, err := os.Open(gomod)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("release: open %s: %w", gomod, err)
	}
	defer func() { _ = f.Close() }()

	var results [][2]string
	inRequire := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "require (" {
			inRequire = true
			continue
		}
		if inRequire && line == ")" {
			inRequire = false
			continue
		}
		if strings.HasPrefix(line, "require ") {
			parts := strings.Fields(strings.TrimPrefix(line, "require "))
			if len(parts) >= 2 {
				results = append(results, [2]string{parts[0], parts[1]})
			}
			continue
		}
		if inRequire && line != "" && !strings.HasPrefix(line, "//") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				results = append(results, [2]string{parts[0], parts[1]})
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("release: scan %s: %w", gomod, err)
	}
	return results, nil
}

func parseSumHashes(gosum string) (map[string]string, error) {
	hashes := make(map[string]string)
	f, err := os.Open(gosum)
	if err != nil {
		if os.IsNotExist(err) {
			return hashes, nil
		}
		return nil, fmt.Errorf("release: open %s: %w", gosum, err)
	}
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Fields(sc.Text())
		if len(parts) != 3 {
			continue
		}
		mod, ver, hash := parts[0], parts[1], parts[2]
		if strings.HasSuffix(ver, "/go.mod") {
			continue
		}
		hashes[mod+" "+ver] = hash
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("release: scan %s: %w", gosum, err)
	}
	return hashes, nil
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("release: hash %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("release: hash %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func vcsInfo(ctx context.Context, dir string) (revision string, modified bool) {
	rev, err := runGit(ctx, dir, "rev-parse", "HEAD")
	if err != nil {
		return "", false
	}
	revision = strings.TrimSpace(rev)
	status, err := runGit(ctx, dir, "status", "--porcelain")
	if err != nil {
		return revision, false
	}
	modified = strings.TrimSpace(status) != ""
	return revision, modified
}

func runGit(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return out.String(), nil
}

// ─── Engine rules ──────────────────────────────────────────────────────────────

func init() {
	engine.Default.MustRegister(&ruleSBOMPresent{})
	engine.Default.MustRegister(&ruleProvenancePresent{})
}

type ruleSBOMPresent struct{}

func (r *ruleSBOMPresent) ID() string { return "RELEASE001" }
func (r *ruleSBOMPresent) Description() string {
	return "Project should have an sbom.json Software Bill of Materials."
}

func (r *ruleSBOMPresent) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	_, err := os.Stat(filepath.Join(projectRoot, SBOMFile))
	if err == nil {
		return nil, nil
	}
	if os.IsNotExist(err) {
		return []fusa.Finding{{
			RuleID:      r.ID(),
			Severity:    fusa.SeverityWarning,
			Message:     "no sbom.json Software Bill of Materials found",
			Location:    fusa.Location{File: SBOMFile},
			Remediation: "run 'gofusa release' to generate the SBOM",
		}}, nil
	}
	return nil, err
}

type ruleProvenancePresent struct{}

func (r *ruleProvenancePresent) ID() string { return "RELEASE002" }
func (r *ruleProvenancePresent) Description() string {
	return "Project should have a provenance.json build provenance record."
}

func (r *ruleProvenancePresent) Run(_ context.Context, projectRoot string, _ *config.Config) ([]fusa.Finding, error) {
	_, err := os.Stat(filepath.Join(projectRoot, ProvenanceFile))
	if err == nil {
		return nil, nil
	}
	if os.IsNotExist(err) {
		return []fusa.Finding{{
			RuleID:      r.ID(),
			Severity:    fusa.SeverityWarning,
			Message:     "no provenance.json build provenance record found",
			Location:    fusa.Location{File: ProvenanceFile},
			Remediation: "run 'gofusa release' to generate the provenance record",
		}}, nil
	}
	return nil, err
}
