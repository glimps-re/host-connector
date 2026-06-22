package handler

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/glimps-re/connector-integration/sdk"
	"github.com/glimps-re/connector-integration/sdk/events"
)

// statusRecorder captures lifecycle status events pushed to the manager.
type statusRecorder struct {
	events.NoopEventHandler
	mu       sync.Mutex
	statuses []events.ConnectorLifecycleStatus
}

func (r *statusRecorder) NotifyStatus(_ context.Context, status events.ConnectorLifecycleStatus) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.statuses = append(r.statuses, status)
	return nil
}

func (r *statusRecorder) got() []events.ConnectorLifecycleStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]events.ConnectorLifecycleStatus(nil), r.statuses...)
}

// blockingMonitor blocks Close until release is closed, simulating an in-flight
// drain that takes time to complete.
type blockingMonitor struct {
	release chan struct{}
	closed  chan struct{}
}

func newBlockingMonitor() *blockingMonitor {
	return &blockingMonitor{release: make(chan struct{}), closed: make(chan struct{})}
}

func (m *blockingMonitor) Start()           {}
func (m *blockingMonitor) Add(string) error { return nil }
func (m *blockingMonitor) Close() error {
	<-m.release
	close(m.closed)
	return nil
}

// withRecorder swaps the package-level eventHandler for the test and restores it.
func withRecorder(t *testing.T) *statusRecorder {
	t.Helper()
	prev := eventHandler
	rec := &statusRecorder{}
	eventHandler = rec
	t.Cleanup(func() { eventHandler = prev })
	return rec
}

func (h *Handler) currentState() connectorState {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.state
}

func waitState(t *testing.T, h *Handler, want connectorState) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if h.currentState() == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("state = %s, want %s", h.currentState(), want)
}

func TestHandler_Stop_AsyncDrain(t *testing.T) {
	rec := withRecorder(t)
	mon := newBlockingMonitor()
	h := &Handler{state: stateStarted, monitor: mon}

	done := make(chan struct{})
	go func() {
		if err := h.Stop(context.Background()); err != nil {
			t.Errorf("Stop() error = %v", err)
		}
		close(done)
	}()

	// Stop must return without waiting for the (blocked) drain.
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Stop() did not return while drain was in progress")
	}

	if got := h.Status(); got != sdk.Stopping {
		t.Fatalf("Status() = %v, want Stopping", got)
	}
	if got := h.currentState(); got != stateStopping {
		t.Fatalf("state = %s, want stopping", got)
	}

	// Let the drain finish.
	close(mon.release)
	waitState(t, h, stateStopped)

	if got := h.Status(); got != sdk.Stopped {
		t.Fatalf("Status() = %v, want Stopped", got)
	}
	if h.monitor != nil || !h.needSetup {
		t.Fatalf("expected monitor cleared and needSetup set after drain")
	}

	want := []events.ConnectorLifecycleStatus{events.StatusStopping, events.StatusStopped}
	got := rec.got()
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("statuses = %v, want %v", got, want)
	}
}

func TestHandler_Configure_RejectedUnlessStopped(t *testing.T) {
	for _, st := range []connectorState{stateStarted, stateStopping} {
		t.Run(st.String(), func(t *testing.T) {
			withRecorder(t)
			h := &Handler{state: st}
			err := h.Configure(context.Background(), json.RawMessage(`{}`))
			if err == nil {
				t.Fatalf("Configure() while %s: expected error, got nil", st)
			}
		})
	}
}

func TestHandler_Start_RejectedWhileStopping(t *testing.T) {
	withRecorder(t)
	h := &Handler{state: stateStopping}
	if err := h.Start(context.Background()); err == nil {
		t.Fatal("Start() while stopping: expected error, got nil")
	}
}

func TestHandler_Stop_IdempotentWhenNotStarted(t *testing.T) {
	rec := withRecorder(t)
	h := &Handler{state: stateStopped}
	if err := h.Stop(context.Background()); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	if !h.wantStopped {
		t.Fatal("wantStopped should be set")
	}
	if got := rec.got(); len(got) != 0 {
		t.Fatalf("no status expected when already stopped, got %v", got)
	}
}
