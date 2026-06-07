package runtime

import (
	"fmt"
	"sync"
	"time"
)

// Heartbeat monitors that Beat is called within each interval period.
// When an interval elapses without a beat, onMissed is called with the
// running count of consecutive missed beats.
type Heartbeat struct {
	interval time.Duration
	onMissed func(missed int)
	mu       sync.Mutex
	lastBeat time.Time
	missed   int
	stopCh   chan struct{}
	running  bool
}

// NewHeartbeat creates a Heartbeat that checks every interval and calls
// onMissed when a beat is not received within that period.
func NewHeartbeat(interval time.Duration, onMissed func(missed int)) *Heartbeat {
	return &Heartbeat{
		interval: interval,
		onMissed: onMissed,
	}
}

// Start begins heartbeat monitoring. Returns an error if already running.
func (h *Heartbeat) Start() error {
	h.mu.Lock()
	if h.running {
		h.mu.Unlock()
		return fmt.Errorf("runtime: heartbeat already running")
	}
	h.stopCh = make(chan struct{})
	h.lastBeat = time.Now()
	h.missed = 0
	h.running = true
	stopCh := h.stopCh
	h.mu.Unlock()

	go func() {
		ticker := time.NewTicker(h.interval)
		defer ticker.Stop()
		for {
			select {
			case <-stopCh:
				return
			case <-ticker.C:
				h.mu.Lock()
				beatAge := time.Since(h.lastBeat)
				if beatAge > h.interval {
					h.missed++
					missed := h.missed
					h.mu.Unlock()
					h.onMissed(missed)
				} else {
					h.missed = 0
					h.mu.Unlock()
				}
			}
		}
	}()
	return nil
}

// Stop halts heartbeat monitoring. Safe to call when not running.
func (h *Heartbeat) Stop() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.running {
		return
	}
	close(h.stopCh)
	h.running = false
}

// Beat signals liveness, resetting the missed-beat counter.
func (h *Heartbeat) Beat() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.lastBeat = time.Now()
	h.missed = 0
}

// IsRunning reports whether the heartbeat is active.
func (h *Heartbeat) IsRunning() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.running
}
