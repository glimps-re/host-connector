//go:build !windows

package cli

import (
	"context"
	"errors"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/glimps-re/connector-integration/sdk"
	"github.com/glimps-re/host-connector/pkg/scanner"
	"github.com/spf13/cobra"
)

func TestSignalContext_theFirstSignalCancelsAndIsNamed(t *testing.T) {
	receivedSignal.Store("")
	ctx, cancel := signalContext()
	defer cancel()
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("SIGTERM did not cancel the context")
	}
	if got, _ := receivedSignal.Load().(string); got != "terminated" {
		t.Errorf("signal = %q, want terminated", got)
	}
}

func TestShutdownContexts_boundsStartWhenTheParentEnds(t *testing.T) {
	parent, cancel := context.WithCancel(t.Context())
	drain, closing, release := shutdownContexts(parent, 400*time.Millisecond, 100*time.Millisecond)
	defer release()
	if drain.Err() != nil || closing.Err() != nil {
		t.Fatal("the bounds must not start before the parent ends")
	}
	cancel()
	select {
	case <-drain.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("drain never ended")
	}
	if closing.Err() != nil {
		t.Error("closing must outlast drain")
	}
	select {
	case <-closing.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("closing never ended")
	}
}

// Past shutdown_timeout plus the grace, the process is ended with code 1; a stop
// that finished disarms the guard.
func TestShutdownContexts_theGuardEndsTheProcessOnlyIfTheStopHangs(t *testing.T) {
	prevExit, prevGrace := exitProcess, exitGrace
	t.Cleanup(func() { exitProcess, exitGrace = prevExit, prevGrace })
	exitGrace = 50 * time.Millisecond
	var code atomic.Int64
	code.Store(-1)
	exitProcess = func(c int) { code.Store(int64(c)) }

	parent, cancel := context.WithCancel(t.Context())
	_, _, release := shutdownContexts(parent, 50*time.Millisecond, 25*time.Millisecond)
	cancel()
	time.Sleep(400 * time.Millisecond)
	if code.Load() != 1 {
		t.Errorf("exit code = %d, want 1 once the stop hung", code.Load())
	}
	release()

	code.Store(-1)
	parent2, cancel2 := context.WithCancel(t.Context())
	_, _, release2 := shutdownContexts(parent2, 50*time.Millisecond, 25*time.Millisecond)
	cancel2()
	release2()
	time.Sleep(400 * time.Millisecond)
	if code.Load() != -1 {
		t.Errorf("exit code = %d, want the guard disarmed by a finished stop", code.Load())
	}
}

func TestRunStop_recordsAnOverrunAndTheSummary(t *testing.T) {
	prevTimes := stopTimes
	t.Cleanup(func() { stopTimes = prevTimes })
	stopTimes.total, stopTimes.drain = 10*time.Second, 5*time.Second
	overran.Store(false)
	t.Cleanup(func() { overran.Store(false) })
	runStop(t.Context(), func(_, closing context.Context) scanner.ShutdownSummary {
		return scanner.ShutdownSummary{StillRunning: 2}
	})
	if !overran.Load() {
		t.Error("files still running at the end of the stop must be an overrun (exit code 1)")
	}
	overran.Store(false)
	runStop(t.Context(), func(_, _ context.Context) scanner.ShutdownSummary {
		return scanner.ShutdownSummary{WorkDirRemoved: true}
	})
	if overran.Load() {
		t.Error("a clean stop must not be an overrun")
	}
}

// The bounds carry a real Deadline once the stop begins, counted from the
// signal: the session plugin reserves part of what is left of it for its JSON
// fallbacks.
func TestShutdownContexts_theBoundsHaveADeadlineFromTheSignal(t *testing.T) {
	parent, cancel := context.WithCancel(t.Context())
	drain, closing, release := shutdownContexts(parent, 8*time.Second, 4*time.Second)
	defer release()
	if _, ok := closing.Deadline(); ok {
		t.Error("no deadline can exist before the stop begins")
	}
	at := time.Now().Add(-time.Second)
	signalAt.Store(&at)
	t.Cleanup(func() { signalAt.Store(nil) })
	cancel()
	waitUntil(t, func() bool { _, ok := closing.Deadline(); return ok })
	d1, _ := drain.Deadline()
	d2, _ := closing.Deadline()
	if got := d1.Sub(at); got != 4*time.Second {
		t.Errorf("drain deadline = signal + %s, want 4s", got)
	}
	if got := d2.Sub(at); got != 8*time.Second {
		t.Errorf("closing deadline = signal + %s, want 8s", got)
	}
	// A context made from it sees the deadline too.
	derived, stop := context.WithTimeout(closing, time.Hour)
	defer stop()
	if dd, _ := derived.Deadline(); !dd.Equal(d2) {
		t.Errorf("derived deadline = %s, want %s", dd, d2)
	}
}

func TestShutdownContexts_aStopThatStartsAtOnceHasItsDeadlinesAtOnce(t *testing.T) {
	parent, cancel := context.WithCancel(t.Context())
	cancel()
	_, closing, release := shutdownContexts(parent, 8*time.Second, 4*time.Second)
	defer release()
	if _, ok := closing.Deadline(); !ok {
		t.Error("the deadline must exist when the stop starts at once")
	}
}

func TestLateContext_reportsADeadlineExceeded(t *testing.T) {
	c := newLateContext()
	defer c.release()
	c.arm(time.Now().Add(20 * time.Millisecond))
	<-c.Done()
	if !errors.Is(c.Err(), context.DeadlineExceeded) {
		t.Errorf("Err() = %v, want DeadlineExceeded", c.Err())
	}
}

func waitUntil(t *testing.T, cond func() bool) {
	t.Helper()
	for range 200 {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met in time")
}

func TestResolveShutdownTimes(t *testing.T) {
	prevCfg, prevTimes := hostConfig.ShutdownTimeout, stopTimes
	t.Cleanup(func() { hostConfig.ShutdownTimeout, stopTimes = prevCfg, prevTimes })
	monitor := &cobra.Command{Use: "monitoring"}
	other := &cobra.Command{Use: "version"}
	hostConfig.ShutdownTimeout = sdk.Duration(time.Second)
	if err := resolveShutdownTimes(monitor, nil); err == nil {
		t.Error("a timeout under 2s must refuse the commands that run the connector")
	}
	if err := resolveShutdownTimes(other, nil); err != nil {
		t.Errorf("version must not care about shutdown_timeout: %v", err)
	}
	hostConfig.ShutdownTimeout = sdk.Duration(30 * time.Second)
	if err := resolveShutdownTimes(monitor, nil); err != nil || stopTimes.total != 30*time.Second || stopTimes.drain != 15*time.Second {
		t.Errorf("times = %+v, error %v, want 30s and 15s", stopTimes, err)
	}
}
