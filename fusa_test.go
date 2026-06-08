package fusa_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	fusa "github.com/SoundMatt/go-FuSa"
)

//fusa:test REQ-ERR001
func TestErrNoConfig_Wrappable(t *testing.T) {
	if fusa.ErrNoConfig == nil {
		t.Fatal("ErrNoConfig must not be nil")
	}
	wrapped := fmt.Errorf("context: %w", fusa.ErrNoConfig)
	if !errors.Is(wrapped, fusa.ErrNoConfig) {
		t.Error("ErrNoConfig: errors.Is must work on wrapped error")
	}
}

//fusa:test REQ-ERR002
func TestErrInvalidConfig_Wrappable(t *testing.T) {
	if fusa.ErrInvalidConfig == nil {
		t.Fatal("ErrInvalidConfig must not be nil")
	}
	wrapped := fmt.Errorf("context: %w", fusa.ErrInvalidConfig)
	if !errors.Is(wrapped, fusa.ErrInvalidConfig) {
		t.Error("ErrInvalidConfig: errors.Is must work on wrapped error")
	}
}

//fusa:test REQ-ERR003
func TestErrCheckFailed_Wrappable(t *testing.T) {
	if fusa.ErrCheckFailed == nil {
		t.Fatal("ErrCheckFailed must not be nil")
	}
	wrapped := fmt.Errorf("context: %w", fusa.ErrCheckFailed)
	if !errors.Is(wrapped, fusa.ErrCheckFailed) {
		t.Error("ErrCheckFailed: errors.Is must work on wrapped error")
	}
}

//fusa:test REQ-NF001
func TestNoExternalDependencies(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller: could not determine source file path")
	}
	root := filepath.Dir(file)
	data, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	content := string(data)
	if strings.Contains(content, "\nrequire ") || strings.Contains(content, "\nrequire(") {
		t.Error("go.mod must not declare external dependencies (zero-dep design)")
	}
}
