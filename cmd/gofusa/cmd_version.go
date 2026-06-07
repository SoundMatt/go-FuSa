package main

import (
	"fmt"
	"io"

	fusa "github.com/SoundMatt/go-FuSa"
)

func runVersion(w io.Writer) int {
	if _, err := fmt.Fprintln(w, "gofusa", fusa.Version); err != nil {
		return 1
	}
	return 0
}
