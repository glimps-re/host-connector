package handler

import (
	"context"
	"errors"
	"log/slog"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type countingHandler struct {
	slog.Handler
	writes atomic.Int64
	delay  time.Duration
}

func (c *countingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (c *countingHandler) Handle(context.Context, slog.Record) error {
	time.Sleep(c.delay)
	c.writes.Add(1)
	return nil
}

func (c *countingHandler) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *countingHandler) WithGroup(string) slog.Handler      { return c }

func countingLogger(t *testing.T, delay time.Duration) *countingHandler {
	t.Helper()
	ch := &countingHandler{delay: delay}
	prev := logger
	logger = slog.New(ch)
	t.Cleanup(func() { logger = prev })
	return ch
}

func fastReminder(t *testing.T) {
	t.Helper()
	prev := rejectReminderEvery
	rejectReminderEvery = time.Millisecond
	t.Cleanup(func() { rejectReminderEvery = prev })
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestReminderClose_noLogWriteAfterClose(t *testing.T) {
	fastReminder(t)
	ch := countingLogger(t, 0)
	h := new(Handler)
	h.startRejectReminder("a rejected configuration")
	waitFor(t, "the first reminders", func() bool { return ch.writes.Load() >= 3 })
	h.Close()
	atClose := ch.writes.Load()
	time.Sleep(40 * time.Millisecond)
	if got := ch.writes.Load(); got != atClose {
		t.Errorf("the reminder wrote %d log line(s) after Close returned", got-atClose)
	}
}

func TestReminderClose_twiceInARow(t *testing.T) {
	fastReminder(t)
	countingLogger(t, 0)
	h := new(Handler)
	h.Close()
	h.startRejectReminder("x")
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.Close()
		h.Close()
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a second Close blocked")
	}
}

func TestReminderClose_returnsQuicklyWhenTheReminderIsMidTick(t *testing.T) {
	fastReminder(t)
	ch := countingLogger(t, 20*time.Millisecond)
	h := new(Handler)
	h.startRejectReminder("x")
	waitFor(t, "a tick in progress", func() bool { return ch.writes.Load() >= 1 })
	start := time.Now()
	h.Close()
	if d := time.Since(start); d > time.Second {
		t.Errorf("Close took %v with a reminder in the middle of a tick", d)
	}
}

func TestReminderClose_doesNotDeadlockWhenTheTickWaitsForTheLock(t *testing.T) {
	fastReminder(t)
	ch := countingLogger(t, 0)
	h := new(Handler)
	h.startRejectReminder("x")
	waitFor(t, "a first reminder", func() bool { return ch.writes.Load() >= 1 })
	h.remindMu.Lock()
	time.Sleep(10 * time.Millisecond) // the next tick is now waiting for the lock
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.Close()
	}()
	time.Sleep(10 * time.Millisecond)
	h.remindMu.Unlock()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close deadlocked against a reminder waiting for remindMu")
	}
}

func TestReminderClose_rejectResolveRejectLeavesNoGoroutine(t *testing.T) {
	recordEvents(t)
	fastReminder(t)
	countingLogger(t, 0)
	runtime.GC()
	time.Sleep(20 * time.Millisecond)
	before := runtime.NumGoroutine()
	h := new(Handler)
	ctx := t.Context()
	h.notifyRejected(ctx, errors.New("first rejection"), rejectedNotApplied)
	h.resolveRejected(ctx)
	h.notifyRejected(ctx, errors.New("second rejection"), rejectedNotApplied)
	h.notifyRejected(ctx, errors.New("third rejection while pending"), rejectedNotApplied)
	h.Close()
	waitFor(t, "the reminder goroutines to exit", func() bool { return runtime.NumGoroutine() <= before+1 })
}

func TestReminderClose_concurrentStartsAndClosesAreSafe(t *testing.T) {
	fastReminder(t)
	countingLogger(t, 0)
	h := new(Handler)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 20 {
				h.startRejectReminder("x")
				h.stopRejectReminder()
			}
		})
	}
	wg.Wait()
	h.Close()
}
