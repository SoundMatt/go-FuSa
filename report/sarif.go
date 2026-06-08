package report

import (
	"io"

	fusa "github.com/SoundMatt/go-FuSa"
	"github.com/SoundMatt/go-FuSa/sarif"
)

//fusa:req REQ-SARIF003
func renderSARIF(w io.Writer, r *Report) error {
	return sarif.Render(w, r.Findings, fusa.Version)
}
