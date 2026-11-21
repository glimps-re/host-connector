package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/glimps-re/connector-integration/sdk"
	"github.com/glimps-re/connector-integration/sdk/events"
	"github.com/glimps-re/host-connector/pkg/quarantine"
	quarantineMock "github.com/glimps-re/host-connector/pkg/quarantine/mock"
	"github.com/glimps-re/host-connector/pkg/scanner"
)

type bindingsQuarantiner struct {
	quarantineMock.QuarantineMock
	dir  string
	hook func(ctx context.Context, id, dest, sha256 string)
}

func (b *bindingsQuarantiner) SetWorkDir(dir string) { b.dir = dir }
func (b *bindingsQuarantiner) SetUnregisteredRestoreHook(f func(ctx context.Context, id, dest, sha256 string)) {
	b.hook = f
}

func TestNotifyUnregisteredRestore_raisesOneWarningAndOneEvent(t *testing.T) {
	rec := recordEvents(t)
	logs := captureHandlerLogs(t)

	notifyUnregisteredRestore(t.Context(), "abc", "/dest/f.bin", "deadbeef")

	got := rec.find("error", HostQuarantineRestoreUnregistered)
	if len(got) != 1 {
		t.Fatalf("events = %d, want 1", len(got))
	}
	for _, want := range []string{"abc", "/dest/f.bin", "deadbeef"} {
		if !strings.Contains(got[0].msg, want) {
			t.Errorf("event message %q lacks %q", got[0].msg, want)
		}
	}
	if len(rec.find("resolution", HostQuarantineRestoreUnregistered)) != 0 {
		t.Error("the event must never be resolved")
	}
	if !strings.Contains(logs.String(), "without a registry entry") {
		t.Errorf("console warning missing: %q", logs.String())
	}
}

var restoreEventKeys = []events.ErrorEventType{HostQuarantineRestoreUnmarkFailed, HostQuarantineRestoreNotRegistered, HostQuarantineRestoreLockKept}

func TestNotifyRestoreRegistry(t *testing.T) {
	lockKept := errors.Join(quarantine.ErrRestoredLockKept, errors.New("permission denied"))
	tests := []struct {
		name string
		err  error
		want []events.ErrorEventType
	}{
		{"the registry could not be put back", errors.Join(errors.New("exists"), quarantine.ErrRestoreRollbackFailed), []events.ErrorEventType{HostQuarantineRestoreUnmarkFailed}},
		{"restored but not registered", errors.Join(quarantine.ErrRestoredNotRegistered, errors.New("db locked")), []events.ErrorEventType{HostQuarantineRestoreNotRegistered}},
		{"the container is kept", lockKept, []events.ErrorEventType{HostQuarantineRestoreLockKept}},
		{"not registered and the container is kept", errors.Join(lockKept, quarantine.ErrRestoredNotRegistered), []events.ErrorEventType{HostQuarantineRestoreNotRegistered, HostQuarantineRestoreLockKept}},
		{"any other failure", errors.New("destination already exists"), nil},
		{"no failure", nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := recordEvents(t)
			captureHandlerLogs(t)
			notifyRestoreRegistry(t.Context(), "abc", tt.err)
			for _, key := range restoreEventKeys {
				want := 0
				if slices.Contains(tt.want, key) {
					want = 1
				}
				if got := len(rec.find("error", key)); got != want {
					t.Errorf("events %q = %d, want %d", key, got, want)
				}
				if len(rec.find("resolution", key)) != 0 {
					t.Errorf("event %q must never be resolved", key)
				}
			}
		})
	}
}

// The console says what a restoration left at the level that fits: a container
// that stays is a success to deal with later (a warning), the rest disagrees with
// the files (an error).
func TestNotifyRestoreRegistry_consoleLevels(t *testing.T) {
	lockKept := errors.Join(quarantine.ErrRestoredLockKept, errors.New("permission denied"))
	tests := []struct {
		name string
		err  error
		want []string
	}{
		{"the container is kept", lockKept, []string{"WARN"}},
		{"the registry could not be put back", errors.Join(errors.New("exists"), quarantine.ErrRestoreRollbackFailed), []string{"ERROR"}},
		{"not registered", errors.Join(quarantine.ErrRestoredNotRegistered, errors.New("db")), []string{"ERROR"}},
		{"not registered and the container is kept", errors.Join(lockKept, quarantine.ErrRestoredNotRegistered), []string{"ERROR", "WARN"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recordEvents(t)
			logs := captureHandlerLogs(t)
			notifyRestoreRegistry(t.Context(), "abc", tt.err)
			lines := strings.Split(strings.TrimSpace(logs.String()), "\n")
			got := make([]string, 0, len(lines))
			for _, line := range lines {
				var entry struct {
					Level string `json:"level"`
				}
				if err := json.Unmarshal([]byte(line), &entry); err != nil {
					t.Fatalf("log line %q: %v", line, err)
				}
				got = append(got, entry.Level)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("console levels = %v, want %v", got, tt.want)
			}
		})
	}
}

// Handler.Restore raises the events of what the restoration left, once each; a file
// that is restored with its container kept is a success.
func TestHandler_Restore_raisesTheEventsOfWhatTheRestorationLeft(t *testing.T) {
	lockKept := errors.Join(quarantine.ErrRestoredLockKept, errors.New("permission denied"))
	tests := []struct {
		name    string
		err     error
		want    []events.ErrorEventType
		wantErr bool
		warn    string
	}{
		{"rollback failed", errors.Join(errors.New("exists"), quarantine.ErrRestoreRollbackFailed), []events.ErrorEventType{HostQuarantineRestoreUnmarkFailed}, true, ""},
		{"not registered", errors.Join(quarantine.ErrRestoredNotRegistered, errors.New("db")), []events.ErrorEventType{HostQuarantineRestoreNotRegistered}, true, ""},
		{"the container is kept", lockKept, []events.ErrorEventType{HostQuarantineRestoreLockKept}, false, "remove it by hand"},
		{"not registered and the container is kept", errors.Join(lockKept, quarantine.ErrRestoredNotRegistered), []events.ErrorEventType{HostQuarantineRestoreNotRegistered, HostQuarantineRestoreLockKept}, true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := recordEvents(t)
			logs := captureHandlerLogs(t)
			h := &Handler{Quarantiner: &quarantineMock.QuarantineMock{
				RestoreMock: func(context.Context, string) error { return tt.err },
			}}
			err := h.Restore(t.Context(), sdk.RestoreActionContent{ID: "abc"})
			if (err != nil) != tt.wantErr {
				t.Fatalf("Restore() = %v, want an error: %t", err, tt.wantErr)
			}
			if err != nil && !errors.Is(err, tt.err) {
				t.Errorf("Restore() = %v, want the error of the quarantine", err)
			}
			for _, key := range restoreEventKeys {
				want := 0
				if slices.Contains(tt.want, key) {
					want = 1
				}
				if got := len(rec.find("error", key)); got != want {
					t.Errorf("events %q = %d, want %d", key, got, want)
				}
			}
			if tt.warn != "" && !strings.Contains(logs.String(), tt.warn) {
				t.Errorf("no warning %q: %s", tt.warn, logs)
			}
		})
	}
}

func TestHandler_bindQuarantine(t *testing.T) {
	t.Run("the work dir and the hook reach a quarantine that takes them", func(t *testing.T) {
		q := &bindingsQuarantiner{}
		h := &Handler{Quarantiner: q}
		h.bindQuarantine("/private/work")
		if q.dir != "/private/work" || q.hook == nil {
			t.Errorf("bindings = dir %q, hook set %t", q.dir, q.hook != nil)
		}
	})
	t.Run("a quarantine that does not take them, or none, is left alone", func(t *testing.T) {
		h := &Handler{Quarantiner: &quarantineMock.QuarantineMock{}}
		h.bindQuarantine("/x")
		h = &Handler{}
		h.bindQuarantine("/x")
	})
}

// A second application that changes a quarantine setting runs Reconfigure: the
// work dir of the connector must still protect the restorations afterwards.
func TestApply_theWorkDirStaysProtectedAfterAReconfigureOfTheQuarantine(t *testing.T) {
	recordEvents(t)
	watched, location := t.TempDir(), filepath.Join(t.TempDir(), "quarantine")
	first := validConf(t, watched)
	first.Actions.Quarantine = true
	first.Quarantine.Location = location
	first.Quarantine.Password = "one"
	h := newRunningHandler(t, first)
	t.Cleanup(func() {
		if err := h.Quarantiner.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})

	second := validConf(t, watched)
	second.Actions.Quarantine = true
	second.Quarantine.Location = location
	second.Quarantine.Password = "two"
	if err := h.Configure(t.Context(), rawConf(t, second)); err != nil {
		t.Fatalf("Configure() error = %v", err)
	}

	inWork := filepath.Join(h.Conn.GetWorkDir(), "extract-leftover.bin")
	if err := os.WriteFile(inWork, []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Clean(inWork))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("content"))
	_, id, err := h.Quarantiner.Quarantine(t.Context(), inWork, f, hex.EncodeToString(sum[:]), []string{"m"})
	if cerr := f.Close(); cerr != nil {
		t.Fatal(cerr)
	}
	if err != nil {
		t.Fatalf("Quarantine() error = %v", err)
	}
	if err = os.Remove(inWork); err != nil {
		t.Fatal(err)
	}
	err = h.Quarantiner.Restore(t.Context(), id)
	if err == nil || !strings.Contains(err.Error(), "work directory") {
		t.Fatalf("Restore() = %v, want it refused: the destination is in the work directory", err)
	}
	if _, statErr := os.Stat(inWork); statErr == nil {
		t.Error("something was restored in the work directory")
	}
}

type countingQuarantiner struct {
	quarantine.Quarantiner
	reconfigures atomic.Int32
}

func (c *countingQuarantiner) Reconfigure(ctx context.Context, conf quarantine.Config) error {
	c.reconfigures.Add(1)
	return c.Quarantiner.Reconfigure(ctx, conf)
}

func TestApply_anUnchangedQuarantineIsNotReconfigured(t *testing.T) {
	recordEvents(t)
	watched, location := t.TempDir(), filepath.Join(t.TempDir(), "quarantine")
	conf := func(password string) []byte {
		c := validConf(t, watched)
		c.Actions.Quarantine = true
		c.Quarantine.Location = location
		c.Quarantine.Password = password
		return rawConf(t, c)
	}
	first := validConf(t, watched)
	first.Actions.Quarantine = true
	first.Quarantine.Location = location
	first.Quarantine.Password = "one"
	h := newRunningHandler(t, first)
	running := h.Quarantiner
	t.Cleanup(func() {
		if err := running.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
	counting := &countingQuarantiner{Quarantiner: running}
	h.Quarantiner = counting

	if err := h.Configure(t.Context(), conf("one")); err != nil {
		t.Fatalf("Configure() error = %v", err)
	}
	if n := counting.reconfigures.Load(); n != 0 {
		t.Errorf("Reconfigure called %d times for an application that changes nothing in the quarantine, want 0", n)
	}
	if err := h.Configure(t.Context(), conf("two")); err != nil {
		t.Fatalf("Configure() error = %v", err)
	}
	if n := counting.reconfigures.Load(); n != 1 {
		t.Errorf("Reconfigure called %d times after a change of the password, want 1", n)
	}
}

// The work dir is bound as soon as the connector is made: an application that
// fails later leaves no quarantine that would restore into the work dir.
func TestApply_theWorkDirIsBoundEvenWhenTheApplicationFailsLater(t *testing.T) {
	recordEvents(t)
	captureHandlerLogs(t)
	q := &bindingsQuarantiner{}
	q.ReconfigureMock = func(context.Context, quarantine.Config) error { return nil }
	h := &Handler{Quarantiner: q, stopped: true}
	h.validatePlugins = func([]scanner.PluginConfig, *scanner.ValidationContext) error { return nil }
	conf := validConf(t, t.TempDir())
	conf.Actions.Quarantine = true
	conf.Quarantine.Location = filepath.Join(t.TempDir(), "quarantine")
	conf.PluginsConfig = writePluginsFile(t, "bogus:\n  file: bogus.so\n")
	if err := h.setup(t.Context(), conf); err == nil {
		t.Fatal("setup() succeeded, want the load of the plugin to fail")
	}
	if q.dir == "" || q.hook == nil {
		t.Errorf("bindings after a failed application = dir %q, hook set %t, want them bound", q.dir, q.hook != nil)
	}
}
