package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"

	fusa "github.com/SoundMatt/go-FuSa"
)

//fusa:req REQ-CLI004
func runVersion(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gofusa version", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "text", "output format: text or json")
	if code := parseFlags(fs, args); code != 0 {
		return code
	}

	switch *format {
	case "text", "":
		if _, err := fmt.Fprintln(stdout, "gofusa", fusa.Version); err != nil {
			return fusa.ExitRuntime
		}
	case "json":
		v := struct {
			Tool        string `json:"tool"`
			Version     string `json:"version"`
			SpecVersion string `json:"specVersion"`
		}{
			Tool:        "go-FuSa",
			Version:     fusa.Version,
			SpecVersion: fusa.SpecVersion,
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(v); err != nil {
			return fusa.ExitRuntime
		}
	default:
		return usageErrorf(stderr, "version", "unknown format %q (text or json)", *format)
	}
	return fusa.ExitOK
}
