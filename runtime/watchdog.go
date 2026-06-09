// Package runtime provides reusable runtime safety patterns for go-FuSa
// projects (v0.7).
//
// Watchdog monitors that a periodic Kick is received within a timeout window.
// Heartbeat monitors that Beat is called at a regular interval.
// StateManager tracks a system's safe-state machine.
// DiagManager records a bounded ring of diagnostic events.
// FaultMonitor counts per-fault occurrences and fires a callback at threshold.
package runtime

import (
	"fmt"
	"sync"
	"time"
)

// Watchdog monitors that Kick is called within a timeout window.
// If the window expires without a kick, onExpiry is called once per check interval.
// Goroutines started by Start use select on a stop channel, satisfying ANA001.
type Watchdog struct {
	interval time.Duration
	timeout  time.Duration
	onExpiry func()
	mu       sync.Mutex
	lastKick time.Time
	stopCh   chan struct{}
	running  bool
}

// NewWatchdog creates a Watchdog that checks every interval and calls onExpiry
// when more than timeout has elapsed since the last Kick.
//
//fusa:req REQ-RUNTIME001
func NewWatchdog(interval, timeout time.Duration, onExpiry func()) *Watchdog {
	return &Watchdog{
		interval: interval,
		timeout:  timeout,
		onExpiry: onExpiry,
	}
}

// Start begins watchdog monitoring. Returns an error if already running.
func (w *Watchdog) Start() error {
	w.mu.Lock()
	if w.running {
		w.mu.Unlock()
		return fmt.Errorf("runtime: watchdog already running")
	}
	w.stopCh = make(chan struct{})
	w.lastKick = time.Now()
	w.running = true
	stopCh := w.stopCh
	w.mu.Unlock()

	go func() {
		ticker := time.NewTicker(w.interval)
		defer ticker.Stop()
		for {
			select {
			case <-stopCh:
				return
			case <-ticker.C:
				w.mu.Lock()
				expired := time.Since(w.lastKick) > w.timeout
				w.mu.Unlock()
				if expired {
					w.onExpiry()
				}
			}
		}
	}()
	return nil
}

// Stop halts watchdog monitoring. Safe to call when not running.
func (w *Watchdog) Stop() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.running {
		return
	}
	close(w.stopCh)
	w.running = false
}

// Kick resets the watchdog timer. Should be called periodically by the
// monitored component to signal liveness.
func (w *Watchdog) Kick() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.lastKick = time.Now()
}

// IsRunning reports whether the watchdog is active.
func (w *Watchdog) IsRunning() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.running
}
