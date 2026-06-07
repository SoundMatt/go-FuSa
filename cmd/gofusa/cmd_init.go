package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/SoundMatt/go-FuSa/config"
	"github.com/SoundMatt/go-FuSa/template"
)

func runInit(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: gofusa init [flags]\n\n")
		fmt.Fprintf(stderr, "Initialise a go-FuSa configuration in the project root.\n\n")
		fmt.Fprintf(stderr, "Flags:\n")
		fs.PrintDefaults()
	}

	var (
		dir      = fs.String("dir", "", "project root directory (default: current directory)")
		module   = fs.String("module", "", "Go module path (default: read from go.mod)")
		name     = fs.String("name", "", "project name (default: directory name)")
		standard = fs.String("standard", "generic", "safety standard: ISO26262 IEC61508 ISO21434 DO178C generic")
		docs     = fs.Bool("docs", false, "generate starter safety documentation templates")
	)
	if err := fs.Parse(args); err != nil {
		return 1
	}

	projectRoot := *dir
	if projectRoot == "" {
		var err error
		projectRoot, err = os.Getwd()
		if err != nil {
			fmt.Fprintf(stderr, "gofusa init: get working directory: %v\n", err)
			return 1
		}
	}

	cfgPath := filepath.Join(projectRoot, config.ConfigFile)
	if _, err := os.Stat(cfgPath); err == nil {
		fmt.Fprintf(stderr, "gofusa init: %s already exists; delete it to reinitialise\n", cfgPath)
		return 1
	}

	modPath := *module
	if modPath == "" {
		var err error
		modPath, err = readModulePath(filepath.Join(projectRoot, "go.mod"))
		if err != nil && !os.IsNotExist(err) {
			fmt.Fprintf(stderr, "gofusa init: read go.mod: %v\n", err)
			return 1
		}
	}

	projectName := *name
	if projectName == "" {
		projectName = filepath.Base(projectRoot)
	}

	cfg := config.Default(modPath, projectName)
	cfg.Project.Standard = config.Standard(*standard)

	if err := config.Save(cfgPath, cfg); err != nil {
		fmt.Fprintf(stderr, "gofusa init: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "Created %s\n", cfgPath)

	if *docs {
		docsDir := filepath.Join(projectRoot, "docs", "safety")
		if err := template.Generate(docsDir, template.TypeAll); err != nil {
			fmt.Fprintf(stderr, "gofusa init: generate templates: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "Generated safety templates in %s\n", docsDir)
	}

	return 0
}

// readModulePath parses the module path from a go.mod file.
func readModulePath(gomod string) (string, error) {
	data, err := os.ReadFile(gomod)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "module ")), nil
		}
	}
	return "", fmt.Errorf("no module directive in %s", gomod)
}
