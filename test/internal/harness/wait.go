//go:build linux

package harness

import (
	"fmt"
	"testing"
	"time"
)

// WaitFor waits for the condition, and fails at once if the process ended
// meanwhile: a connector that refused its configuration would otherwise be
// waited for until the deadline.
func (in *Instance) WaitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	if err := in.poll(time.Minute, in.exited, cond); err != nil {
		t.Fatalf("%v while waiting for %s", err, what)
	}
}

// WaitAck waits for the console to acknowledge the task and returns its error
// text.
func (in *Instance) WaitAck(t *testing.T, taskID string) string {
	t.Helper()
	var errText string
	in.WaitFor(t, "the acknowledgement of "+taskID, func() bool {
		var acked bool
		errText, acked = in.Console.Ack(taskID)
		return acked
	})
	return errText
}

// poll calls cond until it holds, for at most limit. It returns an error when
// limit passes, or when exited is closed (the process ended) and cond still
// does not hold. A nil exited is never closed.
func (in *Instance) poll(limit time.Duration, exited <-chan struct{}, cond func() bool) error {
	deadline := time.Now().Add(limit)
	for !cond() {
		select {
		case <-exited:
			if cond() {
				return nil
			}
			return fmt.Errorf("the process ended (%w)", in.exitErr)
		default:
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout after %s", limit)
		}
		time.Sleep(200 * time.Millisecond)
	}
	return nil
}
