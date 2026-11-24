//go:build linux

// Package wait polls a condition for the e2e harness and its fakes.
package wait

import (
	"testing"
	"time"
)

func WaitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	Poll(t, what, cond, nil, nil)
}

// Poll waits for cond up to a minute. When exited is not nil and gets closed
// meanwhile, the process ended: a connector that refused its configuration
// would otherwise be waited for until the deadline.
func Poll(t *testing.T, what string, cond func() bool, exited <-chan struct{}, exitErr func() error) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for !cond() {
		select {
		case <-exited:
			if cond() {
				return
			}
			t.Fatalf("the process ended (%v) while waiting for %s", exitErr(), what)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
