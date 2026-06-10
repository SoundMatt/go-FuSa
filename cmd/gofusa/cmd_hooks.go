package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	fusa "github.com/SoundMatt/go-FuSa"
)

const preCommitScript = `#!/bin/sh
# go-FuSa pre-commit hook — installed by: gofusa hooks install
set -e
if command -v gofusa >/dev/null 2>&1; then
  gofusa check --strict
else
  echo "gofusa: not found in PATH; skipping safety check" >&2
fi
`

//fusa:req REQ-CLI-HOOKS001
func runHooks(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa hooks", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: gofusa hooks <subcommand> [flags]\n\n")
		fmt.Fprintf(stderr, "Manage git hooks for go-FuSa integration.\n\n")
		fmt.Fprintf(stderr, "Subcommands:\n")
		fmt.Fprintf(stderr, "  install   Install pre-commit hook into .git/hooks/\n")
		fmt.Fprintf(stderr, "  remove    Remove the go-FuSa pre-commit hook\n")
		fmt.Fprintf(stderr, "  show      Print the hook script to stdout\n\n")
		fmt.Fprintf(stderr, "Flags:\n")
		fs.PrintDefaults()
	}

	dir := fs.String("dir", "", "project root directory (default: current directory)")
	if code := parseFlags(fs, args); code != 0 {
		return code
	}
	if fs.NArg() == 0 {
		fs.Usage()
		return fusa.ExitRuntime
	}

	projectRoot := *dir
	if projectRoot == "" {
		var err error
		projectRoot, err = os.Getwd()
		if err != nil {
			fmt.Fprintf(stderr, "gofusa hooks: get working directory: %v\n", err)
			return fusa.ExitRuntime
		}
	}

	hookPath := filepath.Join(projectRoot, ".git", "hooks", "pre-commit")

	switch fs.Arg(0) {
	case "install":
		return hooksInstall(hookPath, stdout, stderr)
	case "remove":
		return hooksRemove(hookPath, stdout, stderr)
	case "show":
		fmt.Fprint(stdout, preCommitScript)
		return fusa.ExitOK
	default:
		fmt.Fprintf(stderr, "gofusa hooks: unknown subcommand %q\n", fs.Arg(0))
		fs.Usage()
		return fusa.ExitRuntime
	}
}

func hooksInstall(hookPath string, stdout, stderr io.Writer) int {
	if _, err := os.Stat(hookPath); err == nil {
		fmt.Fprintf(stderr, "gofusa hooks: %s already exists; remove it first or use 'gofusa hooks remove'\n", hookPath)
		return fusa.ExitUsage
	}
	hooksDir := filepath.Dir(hookPath)
	if err := os.MkdirAll(hooksDir, 0o750); err != nil {
		fmt.Fprintf(stderr, "gofusa hooks: create hooks dir: %v\n", err)
		return fusa.ExitRuntime
	}
	if err := os.WriteFile(hookPath, []byte(preCommitScript), 0o750); err != nil {
		fmt.Fprintf(stderr, "gofusa hooks: write hook: %v\n", err)
		return fusa.ExitRuntime
	}
	fmt.Fprintf(stdout, "go-FuSa pre-commit hook installed: %s\n", hookPath)
	fmt.Fprintf(stdout, "Hook runs 'gofusa check --strict' on every commit.\n")
	return fusa.ExitOK
}

func hooksRemove(hookPath string, stdout, stderr io.Writer) int {
	if err := os.Remove(hookPath); err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(stderr, "gofusa hooks: hook not found: %s\n", hookPath)
			return fusa.ExitUsage
		}
		fmt.Fprintf(stderr, "gofusa hooks: remove hook: %v\n", err)
		return fusa.ExitRuntime
	}
	fmt.Fprintf(stdout, "go-FuSa pre-commit hook removed: %s\n", hookPath)
	return fusa.ExitOK
}
