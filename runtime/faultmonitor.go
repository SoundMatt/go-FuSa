package runtime

import "sync"

// FaultMonitor counts per-fault occurrences and fires a callback when a
// configurable threshold is reached. Thread-safe.
type FaultMonitor struct {
	mu         sync.Mutex
	counts     map[string]int
	thresholds map[string]int
	onFault    func(id string, count int)
}

// NewFaultMonitor creates a FaultMonitor. onFault is called (without holding
// the internal lock) when a fault's count reaches or exceeds its threshold.
// onFault may be nil.
func NewFaultMonitor(onFault func(id string, count int)) *FaultMonitor {
	return &FaultMonitor{
		counts:     make(map[string]int),
		thresholds: make(map[string]int),
		onFault:    onFault,
	}
}

// SetThreshold configures the count at which onFault fires for faultID.
// A threshold of 0 disables callback firing for that fault.
func (f *FaultMonitor) SetThreshold(faultID string, threshold int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.thresholds[faultID] = threshold
}

// Record increments the counter for faultID and fires onFault if the
// threshold has been reached or exceeded.
func (f *FaultMonitor) Record(faultID string) {
	f.mu.Lock()
	f.counts[faultID]++
	count := f.counts[faultID]
	threshold, hasThreshold := f.thresholds[faultID]
	f.mu.Unlock()

	if hasThreshold && threshold > 0 && count >= threshold && f.onFault != nil {
		f.onFault(faultID, count)
	}
}

// Reset sets the counter for faultID back to zero.
func (f *FaultMonitor) Reset(faultID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.counts[faultID] = 0
}

// Count returns the current counter value for faultID.
func (f *FaultMonitor) Count(faultID string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.counts[faultID]
}
