//go:build linux

package harness

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	hcquarantine "github.com/glimps-re/host-connector/pkg/quarantine"
	"github.com/glimps-re/host-connector/test/internal/fakes/gmalware"
)

// LockOf is the container the connector writes for the file at path holding
// content.
func (in *Instance) LockOf(path string, content []byte) string {
	return filepath.Join(in.Quarantine, hcquarantine.ComputeCacheID(path, gmalware.SHA256Hex(content))+".lock")
}

// AwaitQuarantine waits for the file at path to be quarantined: its container
// is there and the file left its place.
func (in *Instance) AwaitQuarantine(t *testing.T, path string, content []byte) {
	t.Helper()
	lock := in.LockOf(path, content)
	in.WaitFor(t, "the quarantine of "+path, func() bool { return !in.Gone(lock) && in.Gone(path) })
}

// RestoreFile restores through the console the quarantined file that was at
// path with content. Its answer must be empty when wantAckErr is, else contain
// it; once the restore is accepted, it is declared to the checker of OUTPUT.
func (in *Instance) RestoreFile(t *testing.T, path string, content []byte, wantAckErr string) {
	t.Helper()
	in.task(t, "restore", map[string]string{"id": hcquarantine.ComputeCacheID(path, gmalware.SHA256Hex(content))}, wantAckErr)
	if wantAckErr == "" {
		in.Expect.Release(path, content)
	}
}

// DropAt writes a file anywhere below INPUT, creating its folders. The content
// appears at once, written aside out of INPUT (in the test folders, on the same
// file system) then renamed: a rescan must never read a half-written file,
// which would be another content.
func DropAt(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	aside := filepath.Join(t.TempDir(), filepath.Base(path))
	Write(t, aside, content)
	if err := os.Rename(aside, path); err != nil {
		t.Fatal(err)
	}
}

func (in *Instance) needConsole(t *testing.T) {
	t.Helper()
	if in.Console == nil {
		t.Fatal("a console task needs Agent")
	}
}

// task pushes a console task and checks its answer: empty when wantAckErr is,
// else containing it.
func (in *Instance) task(t *testing.T, action string, content any, wantAckErr string) {
	t.Helper()
	in.needConsole(t)
	got := in.WaitAck(t, in.Console.Push(t, action, content))
	switch {
	case wantAckErr == "" && got != "":
		t.Fatalf("%s refused: %s", action, got)
	case wantAckErr != "" && !strings.Contains(got, wantAckErr):
		t.Fatalf("%s answered %q, want an error containing %q", action, got, wantAckErr)
	}
}
