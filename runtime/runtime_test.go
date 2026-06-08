package runtime_test

import (
	"sync/atomic"
	"testing"
	"time"

	fusaruntime "github.com/SoundMatt/go-FuSa/runtime"
)

// ─── Watchdog ─────────────────────────────────────────────────────────────────

func TestWatchdog_ExpiryFires(t *testing.T) {
	var fired atomic.Bool
	wd := fusaruntime.NewWatchdog(5*time.Millisecond, 10*time.Millisecond, func() {
		fired.Store(true)
	})
	if err := wd.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer wd.Stop()

	// Do not kick — wait for expiry.
	deadline := time.Now().Add(200 * time.Millisecond)
	for !fired.Load() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !fired.Load() {
		t.Error("Watchdog: onExpiry not called within deadline")
	}
}

func TestWatchdog_KickPreventsExpiry(t *testing.T) {
	var fired atomic.Bool
	interval := 10 * time.Millisecond
	timeout := 50 * time.Millisecond
	wd := fusaruntime.NewWatchdog(interval, timeout, func() {
		fired.Store(true)
	})
	if err := wd.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer wd.Stop()

	// Kick frequently for 100ms — well within the timeout.
	deadline := time.Now().Add(100 * time.Millisecond)
	for time.Now().Before(deadline) {
		wd.Kick()
		time.Sleep(5 * time.Millisecond)
	}
	if fired.Load() {
		t.Error("Watchdog: onExpiry should not fire when kicked regularly")
	}
}

func TestWatchdog_StartTwice(t *testing.T) {
	wd := fusaruntime.NewWatchdog(10*time.Millisecond, 50*time.Millisecond, func() {})
	if err := wd.Start(); err != nil {
		t.Fatalf("first Start: %v", err)
	}
	defer wd.Stop()
	if err := wd.Start(); err == nil {
		t.Error("second Start: expected error")
	}
}

func TestWatchdog_IsRunning(t *testing.T) {
	wd := fusaruntime.NewWatchdog(10*time.Millisecond, 50*time.Millisecond, func() {})
	if wd.IsRunning() {
		t.Error("IsRunning should be false before Start")
	}
	if err := wd.Start(); err != nil {
		t.Fatal(err)
	}
	if !wd.IsRunning() {
		t.Error("IsRunning should be true after Start")
	}
	wd.Stop()
	if wd.IsRunning() {
		t.Error("IsRunning should be false after Stop")
	}
}

// ─── Heartbeat ────────────────────────────────────────────────────────────────

func TestHeartbeat_MissedCallbackFires(t *testing.T) {
	var missed atomic.Int32
	hb := fusaruntime.NewHeartbeat(20*time.Millisecond, func(n int) {
		missed.Store(int32(n))
	})
	if err := hb.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer hb.Stop()

	// Do not beat — wait for missed callback.
	deadline := time.Now().Add(200 * time.Millisecond)
	for missed.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if missed.Load() == 0 {
		t.Error("Heartbeat: onMissed not called within deadline")
	}
}

func TestHeartbeat_RegularBeatSuppressesCallback(t *testing.T) {
	var missed atomic.Int32
	hb := fusaruntime.NewHeartbeat(50*time.Millisecond, func(n int) {
		missed.Store(int32(n))
	})
	if err := hb.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer hb.Stop()

	deadline := time.Now().Add(150 * time.Millisecond)
	for time.Now().Before(deadline) {
		hb.Beat()
		time.Sleep(10 * time.Millisecond)
	}
	if missed.Load() > 0 {
		t.Errorf("Heartbeat: onMissed should not fire when beat is regular, got %d", missed.Load())
	}
}

func TestHeartbeat_StartTwice(t *testing.T) {
	hb := fusaruntime.NewHeartbeat(50*time.Millisecond, func(int) {})
	if err := hb.Start(); err != nil {
		t.Fatalf("first Start: %v", err)
	}
	defer hb.Stop()
	if err := hb.Start(); err == nil {
		t.Error("second Start: expected error")
	}
}

func TestHeartbeat_IsRunning(t *testing.T) {
	hb := fusaruntime.NewHeartbeat(50*time.Millisecond, func(int) {})
	if hb.IsRunning() {
		t.Error("IsRunning should be false before Start")
	}
	if err := hb.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !hb.IsRunning() {
		t.Error("IsRunning should be true after Start")
	}
	hb.Stop()
	if hb.IsRunning() {
		t.Error("IsRunning should be false after Stop")
	}
}

// ─── StateManager ─────────────────────────────────────────────────────────────

func TestStateManager_InitialState(t *testing.T) {
	sm := fusaruntime.NewStateManager(nil)
	if sm.State() != fusaruntime.StateOperational {
		t.Errorf("initial state = %v, want OPERATIONAL", sm.State())
	}
}

func TestStateManager_Transition(t *testing.T) {
	var from, to fusaruntime.State
	sm := fusaruntime.NewStateManager(func(f, t2 fusaruntime.State) {
		from, to = f, t2
	})
	if err := sm.Transition(fusaruntime.StateDegraded); err != nil {
		t.Fatalf("Transition: %v", err)
	}
	if sm.State() != fusaruntime.StateDegraded {
		t.Errorf("state = %v, want DEGRADED", sm.State())
	}
	if from != fusaruntime.StateOperational || to != fusaruntime.StateDegraded {
		t.Errorf("onChange called with (%v, %v), want (OPERATIONAL, DEGRADED)", from, to)
	}
}

func TestStateManager_EmergencyStopIsTerminal(t *testing.T) {
	sm := fusaruntime.NewStateManager(nil)
	if err := sm.Transition(fusaruntime.StateEmergencyStop); err != nil {
		t.Fatalf("Transition to EMERGENCY_STOP: %v", err)
	}
	if err := sm.Transition(fusaruntime.StateOperational); err == nil {
		t.Error("Transition from EMERGENCY_STOP: expected error")
	}
}

func TestStateManager_SameStatIsNoop(t *testing.T) {
	var callCount int
	sm := fusaruntime.NewStateManager(func(_, _ fusaruntime.State) { callCount++ })
	if err := sm.Transition(fusaruntime.StateOperational); err != nil {
		t.Fatalf("no-op transition returned error: %v", err)
	}
	if callCount != 0 {
		t.Error("onChange should not fire for no-op same-state transition")
	}
}

func TestStateString(t *testing.T) {
	cases := []struct {
		state fusaruntime.State
		want  string
	}{
		{fusaruntime.StateOperational, "OPERATIONAL"},
		{fusaruntime.StateDegraded, "DEGRADED"},
		{fusaruntime.StateSafeStop, "SAFE_STOP"},
		{fusaruntime.StateEmergencyStop, "EMERGENCY_STOP"},
	}
	for _, c := range cases {
		if c.state.String() != c.want {
			t.Errorf("State(%d).String() = %q, want %q", c.state, c.state.String(), c.want)
		}
	}
}

// ─── DiagManager ──────────────────────────────────────────────────────────────

func TestDiagManager_RecordAndRetrieve(t *testing.T) {
	dm := fusaruntime.NewDiagManager(10)
	dm.Record("D001", fusaruntime.DiagWarning, "voltage low")
	dm.Record("D002", fusaruntime.DiagError, "sensor fault")

	entries := dm.Diagnostics()
	if len(entries) != 2 {
		t.Fatalf("Diagnostics: got %d entries, want 2", len(entries))
	}
	if entries[0].ID != "D001" || entries[0].Level != fusaruntime.DiagWarning {
		t.Errorf("entries[0] = %+v", entries[0])
	}
	if entries[1].ID != "D002" || entries[1].Level != fusaruntime.DiagError {
		t.Errorf("entries[1] = %+v", entries[1])
	}
}

func TestDiagManager_RingEviction(t *testing.T) {
	dm := fusaruntime.NewDiagManager(3)
	for range 5 {
		dm.Record("ID", fusaruntime.DiagInfo, "msg")
	}
	if dm.Count() != 3 {
		t.Errorf("Count = %d after 5 records with max=3, want 3", dm.Count())
	}
}

func TestDiagManager_Clear(t *testing.T) {
	dm := fusaruntime.NewDiagManager(10)
	dm.Record("X", fusaruntime.DiagInfo, "msg")
	dm.Clear()
	if dm.Count() != 0 {
		t.Errorf("Count after Clear = %d, want 0", dm.Count())
	}
}

func TestDiagLevelString(t *testing.T) {
	cases := []struct {
		l    fusaruntime.DiagLevel
		want string
	}{
		{fusaruntime.DiagInfo, "INFO"},
		{fusaruntime.DiagWarning, "WARNING"},
		{fusaruntime.DiagError, "ERROR"},
		{fusaruntime.DiagCritical, "CRITICAL"},
	}
	for _, c := range cases {
		if c.l.String() != c.want {
			t.Errorf("DiagLevel(%d).String() = %q, want %q", c.l, c.l.String(), c.want)
		}
	}
}

// ─── FaultMonitor ─────────────────────────────────────────────────────────────

func TestFaultMonitor_ThresholdFires(t *testing.T) {
	var firedID string
	var firedCount int
	fm := fusaruntime.NewFaultMonitor(func(id string, count int) {
		firedID = id
		firedCount = count
	})
	fm.SetThreshold("overtemp", 3)
	fm.Record("overtemp")
	fm.Record("overtemp")
	if firedID != "" {
		t.Error("callback should not fire before threshold")
	}
	fm.Record("overtemp")
	if firedID != "overtemp" || firedCount != 3 {
		t.Errorf("callback: id=%q count=%d, want overtemp/3", firedID, firedCount)
	}
}

func TestFaultMonitor_NoThreshold_NoCallback(t *testing.T) {
	var fired bool
	fm := fusaruntime.NewFaultMonitor(func(string, int) { fired = true })
	fm.Record("fault-without-threshold")
	fm.Record("fault-without-threshold")
	if fired {
		t.Error("callback should not fire when no threshold is set")
	}
}

func TestFaultMonitor_Reset(t *testing.T) {
	fm := fusaruntime.NewFaultMonitor(nil)
	fm.Record("f")
	fm.Record("f")
	fm.Reset("f")
	if fm.Count("f") != 0 {
		t.Errorf("Count after Reset = %d, want 0", fm.Count("f"))
	}
}

func TestFaultMonitor_Count(t *testing.T) {
	fm := fusaruntime.NewFaultMonitor(nil)
	if fm.Count("x") != 0 {
		t.Error("Count for unseen fault should be 0")
	}
	fm.Record("x")
	fm.Record("x")
	if fm.Count("x") != 2 {
		t.Errorf("Count = %d, want 2", fm.Count("x"))
	}
}
