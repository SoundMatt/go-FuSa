package runtime

import (
	"fmt"
	"sync"
	"time"
)

// DiagLevel is the severity level of a diagnostic entry.
type DiagLevel int

const (
	// DiagInfo is an informational observation.
	DiagInfo DiagLevel = iota
	// DiagWarning indicates a condition that should be investigated.
	DiagWarning
	// DiagError indicates a recoverable fault.
	DiagError
	// DiagCritical indicates a non-recoverable fault requiring safe-state action.
	DiagCritical
)

// String returns a human-readable name for the level.
func (l DiagLevel) String() string {
	switch l {
	case DiagInfo:
		return "INFO"
	case DiagWarning:
		return "WARNING"
	case DiagError:
		return "ERROR"
	case DiagCritical:
		return "CRITICAL"
	default:
		return fmt.Sprintf("DiagLevel(%d)", int(l))
	}
}

// Diagnostic is a single diagnostic event.
type Diagnostic struct {
	ID        string
	Level     DiagLevel
	Message   string
	Timestamp time.Time
}

// DiagManager is a concurrency-safe ring buffer for Diagnostic events.
// When the buffer is full, the oldest entries are discarded.
type DiagManager struct {
	mu      sync.RWMutex
	entries []Diagnostic
	max     int
}

// NewDiagManager creates a DiagManager capped at maxEntries.
// If maxEntries is <= 0, a default of 1000 is used.
//
//fusa:req REQ-RUNTIME004
func NewDiagManager(maxEntries int) *DiagManager {
	if maxEntries <= 0 {
		maxEntries = 1000
	}
	return &DiagManager{max: maxEntries}
}

// Record appends a diagnostic event. If the buffer is full, the oldest
// entry is evicted.
func (d *DiagManager) Record(id string, level DiagLevel, message string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.entries = append(d.entries, Diagnostic{
		ID:        id,
		Level:     level,
		Message:   message,
		Timestamp: time.Now(),
	})
	if len(d.entries) > d.max {
		d.entries = d.entries[len(d.entries)-d.max:]
	}
}

// Diagnostics returns a snapshot copy of all buffered entries, oldest first.
func (d *DiagManager) Diagnostics() []Diagnostic {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]Diagnostic, len(d.entries))
	copy(out, d.entries)
	return out
}

// Clear removes all buffered diagnostics.
func (d *DiagManager) Clear() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.entries = d.entries[:0]
}

// Count returns the number of buffered diagnostic entries.
func (d *DiagManager) Count() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.entries)
}
