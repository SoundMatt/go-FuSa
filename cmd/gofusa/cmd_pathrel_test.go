package main

// cmd_pathrel_test.go covers x-FuSa spec §4's project-relative MUST for
// fmea.json/tara.json under the common, day-to-day invocation shape:
// `gofusa fmea`/`gofusa tara` run from the project root with --dir omitted
// (which resolves to os.Getwd(), an absolute path) — exactly the case that
// previously produced absolute entries[].file / threats[].location.file
// (go-FuSa#59).

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	fusa "github.com/SoundMatt/go-FuSa"
)

//fusa:test REQ-LOC-REL003
func TestRunFmea_DirOmitted_EntryFileIsRelative(t *testing.T) {
	dir := t.TempDir()
	src := "package main\n\n//fusa:req REQ-001\nfunc SafetyFunc() error { return nil }\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(cwd) }()
	if chErr := os.Chdir(dir); chErr != nil {
		t.Fatal(chErr)
	}

	var out, errBuf bytes.Buffer
	// --dir intentionally omitted: this is the common invocation shape the
	// bug reproduced under.
	if code := runFmea(nil, &out, &errBuf); code != fusa.ExitOK {
		t.Fatalf("runFmea: exit %d, stderr: %s", code, errBuf.String())
	}

	data, err := os.ReadFile(filepath.Join(dir, "fmea.json"))
	if err != nil {
		t.Fatalf("read fmea.json: %v", err)
	}
	var report struct {
		Entries []struct {
			File string `json:"file"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("unmarshal fmea.json: %v", err)
	}
	if len(report.Entries) == 0 {
		t.Fatal("expected at least one entry")
	}
	for _, e := range report.Entries {
		if filepath.IsAbs(e.File) {
			t.Errorf("entries[].file = %q, want project-relative (§4 MUST)", e.File)
		}
	}
}

//fusa:test REQ-LOC-REL002
func TestRunTara_DirOmitted_ThreatLocationIsRelative(t *testing.T) {
	dir := t.TempDir()
	src := "package main\n\nimport \"crypto/md5\"\n\nfunc Hash(b []byte) [16]byte { return md5.Sum(b) }\n"
	if err := os.WriteFile(filepath.Join(dir, "weak.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(cwd) }()
	if chErr := os.Chdir(dir); chErr != nil {
		t.Fatal(chErr)
	}

	var out, errBuf bytes.Buffer
	if code := runTara(nil, &out, &errBuf); code != fusa.ExitOK {
		t.Fatalf("runTara: exit %d, stderr: %s", code, errBuf.String())
	}

	data, err := os.ReadFile(filepath.Join(dir, "tara.json"))
	if err != nil {
		t.Fatalf("read tara.json: %v", err)
	}
	var report struct {
		Threats []struct {
			Location struct {
				File string `json:"file"`
			} `json:"location"`
			SourceFile string `json:"sourceFile"`
		} `json:"threats"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("unmarshal tara.json: %v", err)
	}
	if len(report.Threats) == 0 {
		t.Fatal("expected at least one threat")
	}
	for _, th := range report.Threats {
		if filepath.IsAbs(th.Location.File) {
			t.Errorf("threats[].location.file = %q, want project-relative (§4 MUST)", th.Location.File)
		}
		if filepath.IsAbs(th.SourceFile) {
			t.Errorf("threats[].sourceFile = %q, want project-relative (§4 MUST)", th.SourceFile)
		}
		if strings.Contains(th.Location.File, "\\") {
			t.Errorf("threats[].location.file = %q, want forward-slash separators", th.Location.File)
		}
	}
}
