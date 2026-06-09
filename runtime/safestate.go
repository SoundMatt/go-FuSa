package runtime

import (
	"fmt"
	"sync"
)

// State represents a system safe-state level. Higher values indicate higher severity.
type State int

const (
	// StateOperational is the normal operating state.
	StateOperational State = iota
	// StateDegraded indicates reduced capability; system remains functional.
	StateDegraded
	// StateSafeStop indicates the system has entered a safe hold state.
	StateSafeStop
	// StateEmergencyStop is the terminal fault state. No further transitions are permitted.
	StateEmergencyStop
)

// String returns a human-readable name for the state.
func (s State) String() string {
	switch s {
	case StateOperational:
		return "OPERATIONAL"
	case StateDegraded:
		return "DEGRADED"
	case StateSafeStop:
		return "SAFE_STOP"
	case StateEmergencyStop:
		return "EMERGENCY_STOP"
	default:
		return fmt.Sprintf("State(%d)", int(s))
	}
}

// StateManager manages safe-state transitions and notifies an onChange callback.
// StateEmergencyStop is a terminal state; no transitions out of it are permitted.
type StateManager struct {
	mu       sync.RWMutex
	state    State
	onChange func(from, to State)
}

// NewStateManager creates a StateManager starting in StateOperational.
// onChange is called after each successful state transition; it may be nil.
//
//fusa:req REQ-RUNTIME003
func NewStateManager(onChange func(from, to State)) *StateManager {
	return &StateManager{
		state:    StateOperational,
		onChange: onChange,
	}
}

// State returns the current safe state.
func (m *StateManager) State() State {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

// Transition moves the system to the target state.
// Returns an error if the current state is StateEmergencyStop (terminal)
// or if to equals the current state (no-op).
func (m *StateManager) Transition(to State) error {
	m.mu.Lock()
	from := m.state
	if from == StateEmergencyStop {
		m.mu.Unlock()
		return fmt.Errorf("runtime: cannot transition out of %s", StateEmergencyStop)
	}
	if from == to {
		m.mu.Unlock()
		return nil
	}
	m.state = to
	m.mu.Unlock()

	if m.onChange != nil {
		m.onChange(from, to)
	}
	return nil
}
