//go:build linux

package harness

import (
	"sync"
	"testing"

	"github.com/glimps-re/host-connector/test/internal/wait"
)

// WaitFor waits for the condition like wait.WaitFor, and fails at
// once if the process ended meanwhile: a connector that refused its
// configuration would otherwise be waited for until the deadline.
func (in *Instance) WaitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	wait.Poll(t, what, cond, in.exited, func() error { return in.exitErr })
}

// maxLogSize bounds the log of a process the harness keeps; past it the
// oldest lines are dropped.
const maxLogSize = 8 << 20

// syncBuffer is the log of a process, read while the process still writes it.
type syncBuffer struct {
	mu        sync.Mutex
	buf       []byte
	truncated bool
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	if len(b.buf) > maxLogSize {
		b.buf = append([]byte(nil), b.buf[len(b.buf)-maxLogSize/2:]...)
		b.truncated = true
	}
	return len(p), nil
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.truncated {
		return "[the start of the log was dropped]\n" + string(b.buf)
	}
	return string(b.buf)
}
