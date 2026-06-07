package main

import (
	"fmt"
	"io"

	fusa "github.com/SoundMatt/go-FuSa"
)

func runVersion(w io.Writer) int {
	fmt.Fprintln(w, "gofusa", fusa.Version)
	return 0
}
