package cli

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/glimps-re/host-connector/pkg/scanner"
	"github.com/spf13/cobra"
)

var (
	// exitGrace is how long past shutdown_timeout the process is left to exit by
	// itself before it is forced; replaced in tests.
	exitGrace = time.Second
	// receivedSignal is the name of the signal that started the stop, "" if none.
	receivedSignal atomic.Value
	// overran is set when a stop did not finish within shutdown_timeout.
	overran atomic.Bool
	// exitProcess forces the end of the process; replaced in tests.
	exitProcess = os.Exit
	// signalAt is when the signal arrived: the bounds of the stop are counted
	// from it.
	signalAt atomic.Pointer[time.Time]
	// stopTimes are the durations of a stop, validated once at start.
	stopTimes struct{ total, drain time.Duration }
)

// signalContext returns a context cancelled by the first SIGINT or SIGTERM. The
// signals are given back to the system right then, so a second one ends the
// process at once.
func signalContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case sig := <-sigs:
			receivedSignal.Store(sig.String())
			now := time.Now()
			signalAt.Store(&now)
			signal.Stop(sigs)
			cancel()
		case <-ctx.Done():
			signal.Stop(sigs)
		}
	}()
	return ctx, cancel
}

// stopper stops what a command started, within the two bounds it is given.
type stopper func(drain, closing context.Context) scanner.ShutdownSummary

// lateContext is a context whose deadline is set once the stop begins, not when
// it is made: what the stop hands it to (the plugins, which reserve part of the
// time left for their fallbacks) must see a real Deadline. Contexts derived from
// it before the deadline is set report Canceled when it ends, not
// DeadlineExceeded: use Deadline() to know the time that was given.
type lateContext struct {
	context.Context
	cancel context.CancelFunc

	mu       sync.Mutex
	deadline time.Time
	timer    *time.Timer
}

func newLateContext() *lateContext {
	ctx, cancel := context.WithCancel(context.Background())
	return &lateContext{Context: ctx, cancel: cancel}
}

func (c *lateContext) Deadline() (time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.deadline, !c.deadline.IsZero()
}

// Err reports context.DeadlineExceeded once the deadline has ended the context.
func (c *lateContext) Err() error {
	err := c.Context.Err()
	if err == nil {
		return nil
	}
	if deadline, ok := c.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return err
}

func (c *lateContext) arm(deadline time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadline = deadline
	c.timer = time.AfterFunc(time.Until(deadline), c.cancel)
}

func (c *lateContext) release() {
	c.mu.Lock()
	if c.timer != nil {
		c.timer.Stop()
	}
	c.mu.Unlock()
	c.cancel()
}

// shutdownContexts returns the two bounds of a stop: drain for the files being
// processed, closing for what follows. Their deadlines are set when parent is
// cancelled, counted from the signal. It also logs the reception of the signal
// and arms the guard that ends the process shortly after total if nothing else
// did. release must be called when the stop is over.
func shutdownContexts(parent context.Context, total, drainFor time.Duration) (drain, closing context.Context, release func()) {
	d, c := newLateContext(), newLateContext()
	var finished atomic.Bool
	grace, exit := exitGrace, exitProcess
	var guard atomic.Pointer[time.Timer]
	var once sync.Once
	arm := func() {
		once.Do(func() {
			start := time.Now()
			if at := signalAt.Load(); at != nil {
				start = *at
			}
			d.arm(start.Add(drainFor))
			c.arm(start.Add(total))
			sig, _ := receivedSignal.Load().(string)
			logger.Info("stop requested, closing", slog.String("signal", sig),
				slog.Duration("drain", drainFor), slog.Duration("closing", total),
				slog.String("note", "a second signal stops immediately"))
			guard.Store(time.AfterFunc(time.Until(start.Add(total+grace)), func() {
				if finished.Load() {
					return
				}
				logger.Error("stop forced: a plugin did not return within shutdown_timeout")
				exit(1)
			}))
		})
	}
	stopAfterParent := context.AfterFunc(parent, arm)
	if parent.Err() != nil {
		arm() // the stop starts at once: its deadlines must exist before it does
	}
	return d, c, func() {
		finished.Store(true)
		stopAfterParent()
		if g := guard.Load(); g != nil {
			g.Stop()
		}
		d.release()
		c.release()
	}
}

// runStop is the one way every command stops: signal or end of work, console
// order excepted. It logs a summary and records whether the delay was kept.
func runStop(parent context.Context, stop stopper) {
	drain, closing, release := shutdownContexts(parent, stopTimes.total, stopTimes.drain)
	defer release()
	start := time.Now()
	summary := stop(drain, closing)
	took := time.Since(start)
	if closing.Err() != nil || summary.StillRunning > 0 {
		overran.Store(true)
	}
	logger.Info("stop finished",
		slog.Int("files_abandoned", summary.Abandoned),
		slog.Int("files_still_running", summary.StillRunning),
		slog.Int("plugins_in_error", summary.PluginErrors),
		slog.Bool("work_dir_removed", summary.WorkDirRemoved),
		slog.Duration("duration", took))
}

func stopHandler(drain, closing context.Context) scanner.ShutdownSummary {
	summary, err := hostHandler.Shutdown(drain, closing)
	if err != nil {
		logger.Error("error stopping connector", slog.String("error", err.Error()))
	}
	hostHandler.Close()
	return summary
}

func stopScan(drain, closing context.Context) scanner.ShutdownSummary {
	return hostHandler.Conn.Shutdown(drain, closing)
}

// longRunning are the commands that stop on a signal.
var longRunning = map[string]bool{"agent": true, "monitoring": true, "scan": true}

// resolveShutdownTimes validates shutdown_timeout once, before a command that
// runs the connector starts, and keeps the durations of the stop.
func resolveShutdownTimes(cmd *cobra.Command, _ []string) error {
	if !longRunning[cmd.Name()] {
		return nil
	}
	total, drain, err := hostConfig.ShutdownDurations()
	if err != nil {
		return err
	}
	stopTimes.total, stopTimes.drain = total, drain
	return nil
}
