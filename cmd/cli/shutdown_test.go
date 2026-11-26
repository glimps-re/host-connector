//go:build !windows

package cli

import (
	"context"
	"errors"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/glimps-re/connector-integration/sdk"
	"github.com/glimps-re/host-connector/pkg/scanner"
	"github.com/spf13/cobra"
)

func TestSignalContext_theFirstSignalCancelsAndIsNamed(t *testing.T) {
	isolateStop(t)
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
	isolateStop(t)
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

// guardWait bounds how long a test waits for an event that must happen.
const guardWait = 10 * time.Second

// stopIsolation is what a test of the stop runs in: the exit of the process
// is recorded, never done, and the clock of the guard can be taken over.
type stopIsolation struct {
	// exit receives the code of every exit asked for.
	exit chan int
}

// isolateStop makes a test safe to call shutdownContexts or runStop: it saves
// exitProcess, armGuard, exitGrace and signalAt, restores them when the test
// ends, clears signalAt (an earlier test, or the signal of the process, must not
// move the bounds of this one) and replaces exitProcess so that no test can reach
// os.Exit.
func isolateStop(t *testing.T) *stopIsolation {
	t.Helper()
	prevExit, prevArm, prevGrace := exitProcess, armGuard, exitGrace
	prevSignal := signalAt.Load()
	t.Cleanup(func() {
		exitProcess, armGuard, exitGrace = prevExit, prevArm, prevGrace
		signalAt.Store(prevSignal)
	})
	signalAt.Store(nil)
	iso := &stopIsolation{exit: make(chan int, 8)}
	exitProcess = func(c int) {
		select {
		case iso.exit <- c:
		default:
		}
	}
	return iso
}

// exited returns the code of an exit asked for, if there was one.
func (iso *stopIsolation) exited() (int, bool) {
	select {
	case c := <-iso.exit:
		return c, true
	default:
		return 0, false
	}
}

// guardRun is a guard started with the clock taken over: what the guard would run
// at its time, and the delay it was given.
type guardRun struct {
	fire  func()
	delay time.Duration
}

// manualGuard takes over the clock of the guard: shutdownContexts then arms a
// guard that only runs when the test says so. The timer it returns is a real one
// that never fires in the test (shutdownContexts stores it and stops it).
func (iso *stopIsolation) manualGuard(t *testing.T) chan guardRun {
	t.Helper()
	armed := make(chan guardRun, 1)
	armGuard = func(d time.Duration, fire func()) *time.Timer {
		armed <- guardRun{fire: fire, delay: d}
		timer := time.NewTimer(time.Hour)
		t.Cleanup(func() { timer.Stop() })
		return timer
	}
	return armed
}

func waitGuard(t *testing.T, armed chan guardRun) guardRun {
	t.Helper()
	select {
	case g := <-armed:
		return g
	case <-time.After(guardWait):
		t.Fatal("the guard was not armed")
		return guardRun{}
	}
}

// The guard is armed for shutdown_timeout plus the grace, counted from the
// signal when there is one, from the stop otherwise: a signal long past gives a
// delay that is over already. The delay is compared with a window, since the
// guard counts from the moment the stop starts, a few microseconds after the
// test chose its times.
func TestShutdownContexts_theGuardCountsFromTheSignal(t *testing.T) {
	const grace = time.Second
	tests := []struct {
		name      string
		signalAgo time.Duration
		total     time.Duration
	}{
		{"from the stop itself", 0, 50 * time.Millisecond},
		{"from a signal 30 s ago: 30 s are left", 30 * time.Second, time.Minute},
		{"a signal long past: the guard is due at once", time.Hour, 50 * time.Millisecond},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iso := isolateStop(t)
			armed := iso.manualGuard(t)
			exitGrace = grace
			if tt.signalAgo > 0 {
				at := time.Now().Add(-tt.signalAgo)
				signalAt.Store(&at)
			}
			parent, cancel := context.WithCancel(t.Context())
			_, _, release := shutdownContexts(parent, tt.total, tt.total/2)
			defer release()
			cancel()
			g := waitGuard(t, armed)
			low, high := tt.total+grace/2-tt.signalAgo, tt.total+grace-tt.signalAgo
			if g.delay <= low || g.delay > high {
				t.Errorf("the guard is armed for %v, want in (%v, %v]", g.delay, low, high)
			}
			if tt.signalAgo == time.Hour && g.delay > 0 {
				t.Errorf("delay = %v, want a guard due at once", g.delay)
			}
		})
	}
}

// A stop that hangs is ended with code 1 when the guard's time comes.
func TestShutdownContexts_theGuardEndsTheProcessIfTheStopHangs(t *testing.T) {
	iso := isolateStop(t)
	armed := iso.manualGuard(t)
	parent, cancel := context.WithCancel(t.Context())
	_, _, release := shutdownContexts(parent, 50*time.Millisecond, 25*time.Millisecond)
	defer release()
	cancel()
	g := waitGuard(t, armed)
	g.fire()
	if code, ok := iso.exited(); !ok || code != 1 {
		t.Errorf("exit = %d (asked: %v), want code 1 once the stop hung", code, ok)
	}
}

// A stop that finished disarms the guard: even if its time comes, it does not
// end the process.
func TestShutdownContexts_aFinishedStopDisarmsTheGuard(t *testing.T) {
	iso := isolateStop(t)
	armed := iso.manualGuard(t)
	parent, cancel := context.WithCancel(t.Context())
	_, _, release := shutdownContexts(parent, 50*time.Millisecond, 25*time.Millisecond)
	cancel()
	g := waitGuard(t, armed)
	release()
	g.fire()
	if code, ok := iso.exited(); ok {
		t.Errorf("exit = %d, want the guard disarmed by a finished stop", code)
	}
}

// With the real clock: a stop that hangs ends the process, and the test waits for
// that event instead of for a delay.
func TestShutdownContexts_theGuardFiresWithTheRealClock(t *testing.T) {
	iso := isolateStop(t)
	exitGrace = 20 * time.Millisecond
	parent, cancel := context.WithCancel(t.Context())
	_, _, release := shutdownContexts(parent, 20*time.Millisecond, 10*time.Millisecond)
	defer release()
	cancel()
	select {
	case c := <-iso.exit:
		if c != 1 {
			t.Errorf("exit code = %d, want 1", c)
		}
	case <-time.After(guardWait):
		t.Fatal("the guard never ended the process of a stop that hangs")
	}
}

func TestRunStop_recordsAnOverrunAndTheSummary(t *testing.T) {
	isolateStop(t)
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
	isolateStop(t)
	parent, cancel := context.WithCancel(t.Context())
	drain, closing, release := shutdownContexts(parent, 8*time.Second, 4*time.Second)
	defer release()
	if _, ok := closing.Deadline(); ok {
		t.Error("no deadline can exist before the stop begins")
	}
	at := time.Now().Add(-time.Second)
	signalAt.Store(&at)
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
	isolateStop(t)
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

func TestWaitConsole(t *testing.T) {
	closed := make(chan struct{})
	close(closed)
	tests := []struct {
		name     string
		done     <-chan struct{}
		deadline time.Time
		want     bool
	}{
		{"ended", closed, time.Now().Add(time.Minute), true},
		{"ended after the deadline", closed, time.Now().Add(-time.Second), true},
		{"never ends, deadline passed", make(chan struct{}), time.Now().Add(-time.Second), false},
		{"never ends, short deadline", make(chan struct{}), time.Now().Add(50 * time.Millisecond), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			start := time.Now()
			if got := waitConsole(tt.done, tt.deadline); got != tt.want {
				t.Errorf("waitConsole() = %v, want %v", got, tt.want)
			}
			if took := time.Since(start); took > 2*time.Second {
				t.Errorf("waitConsole() took %s, want it bounded by the deadline", took)
			}
		})
	}
}

func TestConsoleDeadline_countsFromTheSignal(t *testing.T) {
	prevTimes, prevSignal := stopTimes, signalAt.Load()
	t.Cleanup(func() { stopTimes = prevTimes; signalAt.Store(prevSignal) })
	stopTimes.total = 8 * time.Second
	at := time.Now().Add(-5 * time.Second)
	signalAt.Store(&at)
	if got, want := consoleDeadline(), at.Add(8*time.Second); !got.Equal(want) {
		t.Errorf("consoleDeadline() = %v, want %v", got, want)
	}
}

func TestConsoleDeadline_withoutASignalCountsFromNow(t *testing.T) {
	prevTimes, prevSignal := stopTimes, signalAt.Load()
	t.Cleanup(func() { stopTimes = prevTimes; signalAt.Store(prevSignal) })
	stopTimes.total = 8 * time.Second
	signalAt.Store(nil)
	before := time.Now()
	got := consoleDeadline()
	if got.Before(before.Add(8*time.Second)) || got.After(time.Now().Add(8*time.Second)) {
		t.Errorf("consoleDeadline() = %v, want 8s after now", got)
	}
}

func TestWaitConsole_aConsoleLoopThatNeverEndsDoesNotHoldTheExit(t *testing.T) {
	never := make(chan struct{})
	start := time.Now()
	if waitConsole(never, start.Add(100*time.Millisecond)) {
		t.Fatal("waitConsole() = true for a loop that never ends")
	}
	if took := time.Since(start); took < 90*time.Millisecond || took > 2*time.Second {
		t.Errorf("waitConsole() returned after %s, want about the deadline", took)
	}
}
