package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	fusa "github.com/SoundMatt/go-FuSa"
)

//fusa:test REQ-CLI-COMP-001
func TestRunComp_Text_NoExceedances(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\nfunc ok() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	code := runComp([]string{"--dir", dir}, &out, &bytes.Buffer{})
	if code != fusa.ExitOK {
		t.Errorf("exit %d, want %d; output: %s", code, fusa.ExitOK, out.String())
	}
	if !strings.Contains(out.String(), "Exceeding threshold: 0") {
		t.Errorf("expected 'Exceeding threshold: 0' in output: %s", out.String())
	}
}

//fusa:test REQ-CLI-COMP-001
func TestRunComp_Text_WithExceedances(t *testing.T) {
	dir := t.TempDir()
	src := `package main
func big(x int) int {
	if x==1{return 1}; if x==2{return 2}; if x==3{return 3}
	if x==4{return 4}; if x==5{return 5}; if x==6{return 6}
	if x==7{return 7}; if x==8{return 8}; if x==9{return 9}
	if x==10{return 10}; if x==11{return 11}
	return 0
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	code := runComp([]string{"--dir", dir}, &out, &bytes.Buffer{})
	if code != fusa.ExitGateFail {
		t.Errorf("exit %d, want %d (gate fail)", code, fusa.ExitGateFail)
	}
	if !strings.Contains(out.String(), "big") {
		t.Errorf("expected function name in output: %s", out.String())
	}
}

//fusa:test REQ-CLI-COMP-001
func TestRunComp_JSON(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\nfunc ok() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	code := runComp([]string{"--dir", dir, "--format", "json"}, &out, &bytes.Buffer{})
	if code != fusa.ExitOK {
		t.Fatalf("exit %d, want 0; output: %s", code, out.String())
	}
	var rep struct {
		Kind      string `json:"kind"`
		Threshold int    `json:"threshold"`
		Total     int    `json:"total"`
		Exceeding int    `json:"exceeding"`
	}
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("unmarshal: %v; raw: %s", err, out.String())
	}
	if rep.Kind != "comp-report" {
		t.Errorf("kind = %q, want comp-report", rep.Kind)
	}
	if rep.Threshold != 10 {
		t.Errorf("threshold = %d, want 10", rep.Threshold)
	}
	if rep.Exceeding != 0 {
		t.Errorf("exceeding = %d, want 0", rep.Exceeding)
	}
}

//fusa:test REQ-CLI-COMP-001
func TestRunComp_DALFlag(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\nfunc ok() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	code := runComp([]string{"--dir", dir, "--dal", "DAL-A", "--format", "json"}, &out, &bytes.Buffer{})
	if code != fusa.ExitOK {
		t.Fatalf("exit %d: %s", code, out.String())
	}
	var rep struct {
		Threshold int `json:"threshold"`
	}
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if rep.Threshold != 4 {
		t.Errorf("threshold = %d, want 4 for DAL-A", rep.Threshold)
	}
}

//fusa:test REQ-CLI-COMP-001
func TestRunComp_ThresholdOverride(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\nfunc ok() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	code := runComp([]string{"--dir", dir, "--threshold", "5", "--format", "json"}, &out, &bytes.Buffer{})
	if code != fusa.ExitOK {
		t.Fatalf("exit %d: %s", code, out.String())
	}
	var rep struct {
		Threshold int `json:"threshold"`
	}
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if rep.Threshold != 5 {
		t.Errorf("threshold = %d, want 5", rep.Threshold)
	}
}

//fusa:test REQ-CLI-COMP-001
func TestRunComp_BadFormat(t *testing.T) {
	var out, errOut bytes.Buffer
	code := runComp([]string{"--format", "html"}, &out, &errOut)
	if code != fusa.ExitUsage {
		t.Errorf("exit %d, want %d for bad format", code, fusa.ExitUsage)
	}
}

//fusa:test REQ-CLI-COMP-001
func TestRunComp_BadFlag(t *testing.T) {
	var out, errOut bytes.Buffer
	code := runComp([]string{"--invalid-flag"}, &out, &errOut)
	if code != fusa.ExitUsage {
		t.Errorf("exit %d, want %d for bad flag", code, fusa.ExitUsage)
	}
}

//fusa:test REQ-CLI-COMP-001
func TestRunComp_OutputFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\nfunc ok() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	outFile := filepath.Join(dir, "comp-report.json")
	code := runComp([]string{"--dir", dir, "--format", "json", "--output", outFile}, &bytes.Buffer{}, &bytes.Buffer{})
	if code != fusa.ExitOK {
		t.Fatalf("exit %d", code)
	}
	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if !strings.Contains(string(data), "comp-report") {
		t.Errorf("output file missing kind field: %s", data)
	}
}
