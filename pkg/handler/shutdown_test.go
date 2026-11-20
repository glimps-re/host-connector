package handler

import (
	"context"
	"os"
	"testing"

	"github.com/glimps-re/connector-integration/sdk"
)

// An order of the console whose context is already cancelled still stops the
// connector completely: the work directory is removed, nothing is left running.
func TestHandler_StopWithACancelledContextClosesEverything(t *testing.T) {
	h := newRunningHandler(t, validConf(t, t.TempDir()))
	work := h.Conn.GetWorkDir()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := h.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if h.Status() != sdk.Stopped || h.Conn != nil || h.monitor != nil {
		t.Errorf("status %v, conn %v, monitor %v: want everything stopped", h.Status(), h.Conn, h.monitor)
	}
	if _, err := os.Stat(work); !os.IsNotExist(err) {
		t.Errorf("the work directory is still there: %v", err)
	}
}

func TestHandler_ShutdownReturnsWhatTheStopDid(t *testing.T) {
	h := newRunningHandler(t, validConf(t, t.TempDir()))
	summary, err := h.Shutdown(t.Context(), context.WithoutCancel(t.Context()))
	if err != nil {
		t.Fatal(err)
	}
	if !summary.WorkDirRemoved || summary.Abandoned != 0 || summary.StillRunning != 0 {
		t.Errorf("summary = %+v, want a clean stop", summary)
	}
}
