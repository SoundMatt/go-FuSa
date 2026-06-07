package report

import (
	"encoding/json"
	"fmt"
	"io"
)

func renderJSON(w io.Writer, r *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("report: json encode: %w", err)
	}
	return nil
}
