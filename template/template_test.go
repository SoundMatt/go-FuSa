package template_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/SoundMatt/go-FuSa/template"
)

func TestGenerate_SafetyPlan(t *testing.T) {
	dir := t.TempDir()
	if err := template.Generate(dir, template.TypeSafetyPlan); err != nil {
		t.Fatalf("Generate SafetyPlan: %v", err)
	}
	assertFile(t, filepath.Join(dir, "SAFETY_PLAN.md"))
}

func TestGenerate_TestEvidence(t *testing.T) {
	dir := t.TempDir()
	if err := template.Generate(dir, template.TypeTestEvidence); err != nil {
		t.Fatalf("Generate TestEvidence: %v", err)
	}
	assertFile(t, filepath.Join(dir, "TEST_EVIDENCE.md"))
}

func TestGenerate_HARA(t *testing.T) {
	dir := t.TempDir()
	if err := template.Generate(dir, template.TypeHARA); err != nil {
		t.Fatalf("Generate HARA: %v", err)
	}
	assertFile(t, filepath.Join(dir, "HARA.md"))
}

func TestGenerate_SDP(t *testing.T) {
	dir := t.TempDir()
	if err := template.Generate(dir, template.TypeSDP); err != nil {
		t.Fatalf("Generate SDP: %v", err)
	}
	assertFile(t, filepath.Join(dir, "SAFETY_PLAN.md"))
}

func TestGenerate_SVP(t *testing.T) {
	dir := t.TempDir()
	if err := template.Generate(dir, template.TypeSVP); err != nil {
		t.Fatalf("Generate SVP: %v", err)
	}
	assertFile(t, filepath.Join(dir, "SVP.md"))
}

func TestGenerate_SCMP(t *testing.T) {
	dir := t.TempDir()
	if err := template.Generate(dir, template.TypeSCMP); err != nil {
		t.Fatalf("Generate SCMP: %v", err)
	}
	assertFile(t, filepath.Join(dir, "SCMP.md"))
}

func TestGenerate_SQAP(t *testing.T) {
	dir := t.TempDir()
	if err := template.Generate(dir, template.TypeSQAP); err != nil {
		t.Fatalf("Generate SQAP: %v", err)
	}
	assertFile(t, filepath.Join(dir, "SQAP.md"))
}

func TestGenerate_All(t *testing.T) {
	dir := t.TempDir()
	if err := template.Generate(dir, template.TypeAll); err != nil {
		t.Fatalf("Generate All: %v", err)
	}
	for _, name := range []string{"SAFETY_PLAN.md", "TEST_EVIDENCE.md", "HARA.md", "SVP.md", "SCMP.md", "SQAP.md"} {
		assertFile(t, filepath.Join(dir, name))
	}
}

func TestGenerate_UnknownType(t *testing.T) {
	if err := template.Generate(t.TempDir(), "unknown"); err == nil {
		t.Error("Generate unknown type: expected error, got nil")
	}
}

func TestGenerate_AlreadyExists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "SAFETY_PLAN.md")
	if err := os.WriteFile(path, []byte("existing"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := template.Generate(dir, template.TypeSafetyPlan); err == nil {
		t.Error("Generate existing file: expected error, got nil")
	}
}

func TestGenerate_CreatesDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "docs", "safety")
	// dir does not exist yet
	if err := template.Generate(dir, template.TypeHARA); err != nil {
		t.Fatalf("Generate into new dir: %v", err)
	}
	assertFile(t, filepath.Join(dir, "HARA.md"))
}

func assertFile(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Errorf("file not created: %s: %v", path, err)
		return
	}
	if info.Size() == 0 {
		t.Errorf("file is empty: %s", path)
	}
}
