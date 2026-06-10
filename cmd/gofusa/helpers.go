package main

import (
	"flag"
	"fmt"
	"io"

	fusa "github.com/SoundMatt/go-FuSa"
)

// parseFlags parses a command's flag set and returns fusa.ExitUsage on error.
// Use in place of the inline `if err := fs.Parse(args); err != nil { return 1 }` pattern.
func parseFlags(fs *flag.FlagSet, args []string) int {
	if err := fs.Parse(args); err != nil {
		return fusa.ExitUsage
	}
	return fusa.ExitOK
}

// usageErrorf prints a usage-error message to stderr and returns ExitUsage (2).
func usageErrorf(stderr io.Writer, cmd, format string, a ...any) int {
	fmt.Fprintf(stderr, "gofusa %s: %s\n", cmd, fmt.Sprintf(format, a...))
	return fusa.ExitUsage
}

// runtimeErrorf prints a runtime-error message to stderr and returns ExitRuntime (3).
func runtimeErrorf(stderr io.Writer, cmd, format string, a ...any) int {
	fmt.Fprintf(stderr, "gofusa %s: %s\n", cmd, fmt.Sprintf(format, a...))
	return fusa.ExitRuntime
}
