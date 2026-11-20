package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/glimps-re/connector-integration/sdk"
	"github.com/glimps-re/host-connector/pkg/config"
	"github.com/glimps-re/host-connector/pkg/quarantine"
)

// Modes for the directory permission checks. Named constants: they are the
// subject of the test, not file creation modes.
const (
	modeOwnerOnly     fs.FileMode = 0o700
	modeGroupWritable fs.FileMode = 0o770
)

func TestCheckQuarantineLocation(t *testing.T) {
	base := t.TempDir()
	if err := os.Chmod(base, modeOwnerOnly); err != nil {
		t.Fatal(err)
	}
	watched := filepath.Join(base, "in")
	moveDest := filepath.Join(base, "out")
	work := filepath.Join(base, "work")
	for _, dir := range []string{watched, moveDest, work} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	groupWritable := filepath.Join(base, "group-writable")
	if err := os.Mkdir(groupWritable, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(groupWritable, modeGroupWritable); err != nil {
		t.Fatal(err)
	}
	safe := filepath.Join(base, "safe")
	if err := os.Mkdir(safe, 0o700); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		location string
		wantErr  bool
		wantText string
		wantIs   error
	}{
		{name: "absent directory is created later", location: filepath.Join(base, "q-absent")},
		{name: "owned, mode 0700", location: safe},
		{name: "writable by the group", location: groupWritable, wantErr: true, wantIs: quarantine.ErrUnsafeLocation, wantText: "chmod 700"},
		{name: "equal to a monitored path", location: watched, wantErr: true, wantText: "monitored path"},
		{name: "under a monitored path", location: filepath.Join(watched, "quarantine"), wantErr: true, wantText: "monitored path"},
		{name: "contains a monitored path", location: base, wantErr: true, wantText: "monitored path"},
		{name: "under move.destination", location: filepath.Join(moveDest, "q"), wantErr: true, wantText: "move.destination"},
		{name: "equal to move.destination", location: moveDest, wantErr: true, wantText: "move.destination"},
		{name: "under the work directory is fine", location: filepath.Join(work, "q")},
		{name: "equal to the work directory", location: work, wantErr: true, wantText: "work directory"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conf := &config.Config{}
			conf.Actions.Quarantine = true
			conf.Quarantine.Location = tt.location
			conf.Paths = []string{watched}
			conf.Move.Destination = moveDest
			conf.WorkDir = work
			err := checkQuarantineLocation(conf)
			if (err != nil) != tt.wantErr {
				t.Fatalf("checkQuarantineLocation() error = %v, wantErr %t", err, tt.wantErr)
			}
			if err == nil {
				return
			}
			if tt.wantText != "" && !strings.Contains(err.Error(), tt.wantText) {
				t.Errorf("error %q misses %q", err, tt.wantText)
			}
			if tt.wantIs != nil && !errors.Is(err, tt.wantIs) {
				t.Errorf("error = %v, want %v", err, tt.wantIs)
			}
		})
	}

	t.Run("quarantine action off: nothing checked", func(t *testing.T) {
		conf := &config.Config{}
		conf.Quarantine.Location = watched
		conf.Paths = []string{watched}
		if err := checkQuarantineLocation(conf); err != nil {
			t.Errorf("checkQuarantineLocation() error = %v", err)
		}
	})
}

func TestApply_unsafeQuarantineLocationRefusedAndRunningConfigKept(t *testing.T) {
	rec := recordEvents(t)
	good := validConf(t, t.TempDir())
	h := newRunningHandler(t, good)
	conn := h.Conn

	bad := validConf(t, t.TempDir())
	bad.Actions.Quarantine = true
	bad.Quarantine.Location = bad.Paths[0]
	if err := h.Configure(t.Context(), rawConf(t, bad)); err == nil {
		t.Fatal("Configure() error = nil, want a refusal")
	}
	if h.Conn != conn {
		t.Error("the running connector must be left in place")
	}
	if got := len(rec.find("error", HostConfigRejected)); got != 1 {
		t.Errorf("host-config-rejected events = %d, want 1", got)
	}
}

func quarantinedLocks(t *testing.T, dir string) []string {
	t.Helper()
	locks, err := filepath.Glob(filepath.Join(dir, "*.lock"))
	if err != nil {
		t.Fatal(err)
	}
	return locks
}

func TestApply_step4FailureRollsBackQuarantineCompletely(t *testing.T) {
	recordEvents(t)
	watched := t.TempDir()
	oldDir := filepath.Join(t.TempDir(), "old-quarantine")
	oldDB := filepath.Join(t.TempDir(), "old.db")
	good := validConf(t, watched)
	good.Actions.Quarantine = true
	good.Quarantine.Location = oldDir
	good.Quarantine.Registry = oldDB
	good.Quarantine.Password = "old password"
	h := newRunningHandler(t, good)

	sample := filepath.Join(t.TempDir(), "sample.bin")
	content := []byte("a quarantined sample")
	if err := os.WriteFile(sample, content, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	_, id, err := h.Quarantiner.Quarantine(t.Context(), sample, hex.EncodeToString(sum[:]), []string{"m"})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(sample); err != nil {
		t.Fatal(err)
	}

	next := validConf(t, watched)
	next.Actions.Quarantine = true
	next.Quarantine.Location = filepath.Join(t.TempDir(), "new-quarantine")
	next.Quarantine.Registry = filepath.Join(t.TempDir(), "new.db")
	next.Quarantine.Password = "new password"

	failStartOnce(t)
	if err = h.Configure(t.Context(), rawConf(t, next)); err == nil {
		t.Fatal("Configure() error = nil, want the step 4 failure")
	}
	if got := h.Status(); got != sdk.Started {
		t.Errorf("Status() = %v, want Started after the rollback", got)
	}
	if locks := quarantinedLocks(t, oldDir); len(locks) != 1 {
		t.Errorf("locks in the old quarantine = %v, want the one lock back", locks)
	}
	if locks := quarantinedLocks(t, next.Quarantine.Location); len(locks) != 0 {
		t.Errorf("locks in the new quarantine = %v, want none", locks)
	}
	if h.qConf.Location != oldDir || h.qConf.LockPassword != "old password" {
		t.Errorf("h.qConf = %+v, want the previous configuration", h.qConf)
	}
	if err = h.Quarantiner.Restore(t.Context(), id); err != nil {
		t.Errorf("Restore() with the previous password error = %v", err)
	}
}

func TestApply_step4FailureWithFailingRollbackStopsEverything(t *testing.T) {
	recordEvents(t)
	good := validConf(t, t.TempDir())
	h := newRunningHandler(t, good)
	failStart(t, 0)
	next := validConf(t, t.TempDir())
	if err := h.Configure(t.Context(), rawConf(t, next)); err == nil {
		t.Fatal("Configure() error = nil")
	}
	if got := h.Status(); got != sdk.Stopped {
		t.Errorf("Status() = %v, want Stopped", got)
	}
	if h.Conn != nil || h.monitor != nil {
		t.Error("nothing must stay built after a complete stop")
	}
	if err := h.Start(t.Context()); err == nil {
		t.Error("Start() error = nil, want the failure to persist without panic")
	}
}

type incompleteRollbackQuarantiner struct{ fakeQuarantiner }

func (*incompleteRollbackQuarantiner) Reconfigure(context.Context, quarantine.Config) error {
	return fmt.Errorf("move failed: %w: a.lock", quarantine.ErrRollbackIncomplete)
}

func TestApply_incompleteQuarantineRollbackStopsEverything(t *testing.T) {
	rec := recordEvents(t)
	watched := t.TempDir()
	good := validConf(t, watched)
	good.Actions.Quarantine = true
	good.Quarantine.Location = filepath.Join(t.TempDir(), "old")
	h := newRunningHandler(t, good)
	original := h.Quarantiner
	t.Cleanup(func() { _ = original.Close() })
	h.Quarantiner = &incompleteRollbackQuarantiner{}

	next := validConf(t, watched)
	next.Actions.Quarantine = true
	next.Quarantine.Location = filepath.Join(t.TempDir(), "new")
	if err := h.Configure(t.Context(), rawConf(t, next)); !errors.Is(err, quarantine.ErrRollbackIncomplete) {
		t.Fatalf("Configure() error = %v, want ErrRollbackIncomplete", err)
	}
	if h.Status() != sdk.Stopped {
		t.Error("an incomplete quarantine rollback must stop the connector, not replay the previous configuration")
	}
	events := rec.find("error", HostConfigRejected)
	if len(events) != 1 || !strings.Contains(events[0].msg, "STOPPED") || strings.Contains(events[0].msg, "stays in service") {
		t.Errorf("events = %v", events)
	}
}
