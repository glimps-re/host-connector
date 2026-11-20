package quarantine

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// Modes for the directory permission checks. Named constants: they are the
// subject of the test, not file creation modes.
const (
	modeOwnerOnly      fs.FileMode = 0o700
	modeGroupReadable  fs.FileMode = 0o750
	modeGroupWritable  fs.FileMode = 0o770
	modeOthersWritable fs.FileMode = 0o702
)

func newReconfigureHandler(t *testing.T, cfg Config) *QuarantineHandler {
	t.Helper()
	q, err := NewQuarantineHandler(t.Context(), cfg)
	if err != nil {
		t.Fatalf("NewQuarantineHandler() error = %v", err)
	}
	t.Cleanup(func() {
		if e := q.Close(); e != nil {
			t.Errorf("Close() error = %v", e)
		}
	})
	return q
}

func quarantineSample(t *testing.T, q *QuarantineHandler, name string) (src, id string, content []byte) {
	t.Helper()
	content = []byte("content of " + name)
	src = filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(src, content, 0o600); err != nil {
		t.Fatal(err)
	}
	_, id, err := q.Quarantine(t.Context(), src, sha256Hex(content), []string{"m"})
	if err != nil {
		t.Fatalf("Quarantine(%s) error = %v", name, err)
	}
	return src, id, content
}

func TestReconfigure_failedMoveRestoresEverything(t *testing.T) {
	oldDir := filepath.Join(t.TempDir(), "old")
	oldDB := filepath.Join(t.TempDir(), "old.db")
	q := newReconfigureHandler(t, Config{Location: oldDir, RegistryLocation: oldDB, LockPassword: "old password"})
	_, id1, _ := quarantineSample(t, q, "a.bin")
	_, id2, _ := quarantineSample(t, q, "b.bin")
	_, id3, _ := quarantineSample(t, q, "c.bin")
	ids := []string{id1, id2, id3}

	newDir := filepath.Join(t.TempDir(), "new")
	newDB := filepath.Join(t.TempDir(), "new.db")
	// A directory where the second lock must land makes its move fail halfway.
	obstacle := filepath.Join(newDir, id2+".lock")
	if err := os.MkdirAll(obstacle, 0o700); err != nil {
		t.Fatal(err)
	}
	before := map[string]string{}
	for _, id := range ids {
		entry, err := q.registry.Get(t.Context(), id)
		if err != nil {
			t.Fatal(err)
		}
		before[id] = entry.QuarantineLocation
	}
	locker := q.locker

	err := q.Reconfigure(t.Context(), Config{Location: newDir, RegistryLocation: newDB, LockPassword: "new password"})
	if err == nil {
		t.Fatal("Reconfigure() error = nil, want the move failure")
	}
	for _, id := range ids {
		if _, statErr := os.Stat(filepath.Join(oldDir, id+".lock")); statErr != nil {
			t.Errorf("%s.lock must be back in the old location: %v", id, statErr)
		}
		if _, statErr := os.Stat(filepath.Join(newDir, id+".lock")); statErr == nil && id != id2 {
			t.Errorf("%s.lock must not stay in the new location", id)
		}
		entry, getErr := q.registry.Get(t.Context(), id)
		if getErr != nil || entry.QuarantineLocation != before[id] {
			t.Errorf("registry entry %s = %+v (err %v), want the original location %q", id, entry, getErr, before[id])
		}
	}
	if _, statErr := os.Stat(newDB); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("the abandoned registry file must be removed (stat error = %v)", statErr)
	}
	if q.location != oldDir || q.locker != locker || q.registry.GetLocation() != oldDB {
		t.Error("a failed Reconfigure must leave location, locker and registry unchanged")
	}

	// The old password is still the one in service: a file quarantined now
	// restores.
	src, id4, content := quarantineSample(t, q, "d.bin")
	if err = os.Remove(src); err != nil {
		t.Fatal(err)
	}
	if err = q.Restore(t.Context(), id4); err != nil {
		t.Fatalf("Restore() after a failed Reconfigure error = %v", err)
	}
	if got, readErr := os.ReadFile(filepath.Clean(src)); readErr != nil || string(got) != string(content) {
		t.Errorf("restored content = %q (err %v)", got, readErr)
	}
}

func TestReconfigure_successSwitchesEverything(t *testing.T) {
	oldDir := filepath.Join(t.TempDir(), "old")
	oldDB := filepath.Join(t.TempDir(), "old.db")
	q := newReconfigureHandler(t, Config{Location: oldDir, RegistryLocation: oldDB, LockPassword: "same"})
	src, id, content := quarantineSample(t, q, "a.bin")
	if err := os.Remove(src); err != nil {
		t.Fatal(err)
	}

	newDir := filepath.Join(t.TempDir(), "new")
	newDB := filepath.Join(t.TempDir(), "new.db")
	if err := q.Reconfigure(t.Context(), Config{Location: newDir, RegistryLocation: newDB, LockPassword: "same"}); err != nil {
		t.Fatalf("Reconfigure() error = %v", err)
	}
	info, err := os.Stat(newDir)
	if err != nil {
		t.Fatalf("the new location must exist: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("new location mode = %04o, want 0700", perm)
	}
	if q.registry.GetLocation() != newDB {
		t.Errorf("registry location = %q, want %q", q.registry.GetLocation(), newDB)
	}
	entry, err := q.registry.Get(t.Context(), id)
	if err != nil || entry.QuarantineLocation != filepath.Join(newDir, id+".lock") {
		t.Errorf("entry = %+v (err %v), want the new lock location", entry, err)
	}
	if err = q.Restore(t.Context(), id); err != nil {
		t.Fatalf("Restore() after Reconfigure error = %v", err)
	}
	if got, readErr := os.ReadFile(filepath.Clean(src)); readErr != nil || string(got) != string(content) {
		t.Errorf("restored content = %q (err %v)", got, readErr)
	}
}

func TestReconfigure_failureRemovesCreatedDirectory(t *testing.T) {
	oldDir := filepath.Join(t.TempDir(), "old")
	q := newReconfigureHandler(t, Config{Location: oldDir, LockPassword: "p"})
	quarantineSample(t, q, "a.bin")
	// An unknown format fails before anything is touched.
	newDir := filepath.Join(t.TempDir(), "new")
	if err := q.Reconfigure(t.Context(), Config{Location: newDir, LockPassword: "p", Format: "rar"}); !errors.Is(err, ErrUnknownFormat) {
		t.Fatalf("Reconfigure() error = %v, want ErrUnknownFormat", err)
	}
	if _, err := os.Stat(newDir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("no directory must be created for a refused configuration (stat error = %v)", err)
	}
	// A failure after the directory was created removes it.
	failing := &QuarantineHandler{
		location: oldDir,
		locker:   q.locker,
		registry: &registryMock{
			GetLocationMock: func() string { return "file::memory:" },
			GetMock: func(context.Context, string) (*Entry, error) {
				return nil, errors.New("registry unavailable")
			},
		},
	}
	created := filepath.Join(t.TempDir(), "created")
	if err := failing.Reconfigure(t.Context(), Config{Location: created, LockPassword: "p"}); err == nil {
		t.Fatal("Reconfigure() error = nil, want the registry failure")
	}
	if _, err := os.Stat(created); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the directory created for a failed Reconfigure must be removed (stat error = %v)", err)
	}
	if _, err := os.Stat(filepath.Join(oldDir, filepath.Base(lockOf(t, oldDir)))); err != nil {
		t.Errorf("the lock file must still be in the old location: %v", err)
	}
}

func lockOf(t *testing.T, dir string) string {
	t.Helper()
	entries, err := filepath.Glob(filepath.Join(dir, "*.lock"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("locks in %s = %v (err %v)", dir, entries, err)
	}
	return entries[0]
}

func TestCheckLocation(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("ownership checks need a non-root account")
	}
	base := t.TempDir()
	safe := filepath.Join(base, "safe")
	if err := os.Mkdir(safe, 0o700); err != nil {
		t.Fatal(err)
	}
	groupWritable := filepath.Join(base, "group")
	if err := os.Mkdir(groupWritable, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(groupWritable, modeGroupWritable); err != nil {
		t.Fatal(err)
	}
	othersWritable := filepath.Join(base, "others")
	if err := os.Mkdir(othersWritable, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(othersWritable, modeOthersWritable); err != nil {
		t.Fatal(err)
	}
	readableByGroup := filepath.Join(base, "readable")
	if err := os.Mkdir(readableByGroup, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(readableByGroup, modeGroupReadable); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(base, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		dir      string
		wantErr  bool
		wantText []string
	}{
		{name: "absent is created later", dir: filepath.Join(base, "absent")},
		{name: "owned, mode 0700", dir: safe},
		{name: "readable by the group is accepted", dir: readableByGroup},
		{name: "writable by the group", dir: groupWritable, wantErr: true, wantText: []string{groupWritable, "chown", "chmod 700"}},
		{name: "writable by others", dir: othersWritable, wantErr: true, wantText: []string{othersWritable, "chmod 700"}},
		{name: "not a directory", dir: file, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckLocation(tt.dir)
			if (err != nil) != tt.wantErr {
				t.Fatalf("CheckLocation() error = %v, wantErr %t", err, tt.wantErr)
			}
			if err == nil {
				return
			}
			if !errors.Is(err, ErrUnsafeLocation) {
				t.Errorf("error = %v, want ErrUnsafeLocation", err)
			}
			for _, text := range tt.wantText {
				if !strings.Contains(err.Error(), text) {
					t.Errorf("error %q misses %q", err, text)
				}
			}
		})
	}
}

func TestReconfigure_concurrentWithQuarantineAndRestore(t *testing.T) {
	oldDir := filepath.Join(t.TempDir(), "a")
	q := newReconfigureHandler(t, Config{Location: oldDir, LockPassword: "p"})
	dirs := []string{filepath.Join(t.TempDir(), "b"), filepath.Join(t.TempDir(), "c"), oldDir}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	var failures atomic.Int32
	for w := range 3 {
		wg.Go(func() {
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				name := fmt.Sprintf("w%d-%d.bin", w, i)
				content := []byte("content " + name)
				src := filepath.Join(t.TempDir(), name)
				if err := os.WriteFile(src, content, 0o600); err != nil {
					failures.Add(1)
					return
				}
				_, id, err := q.Quarantine(t.Context(), src, sha256Hex(content), []string{"m"})
				if err != nil {
					failures.Add(1)
					t.Errorf("Quarantine() error = %v", err)
					return
				}
				if err = os.Remove(src); err != nil {
					failures.Add(1)
					return
				}
				if err = q.Restore(t.Context(), id); err != nil {
					failures.Add(1)
					t.Errorf("Restore() error = %v", err)
					return
				}
			}
		})
	}
	regDir := t.TempDir()
	for i := range 6 {
		// A new registry file each time: the registry is replaced under load.
		registry := filepath.Join(regDir, fmt.Sprintf("reg-%d.db", i))
		if err := q.Reconfigure(t.Context(), Config{Location: dirs[i%3], RegistryLocation: registry, LockPassword: "p"}); err != nil {
			t.Errorf("Reconfigure() error = %v", err)
		}
	}
	close(stop)
	wg.Wait()
	if failures.Load() != 0 {
		t.Fatal("operations failed while Reconfigure ran")
	}
	for _, dir := range dirs {
		if dir == q.location {
			continue
		}
		if locks, _ := filepath.Glob(filepath.Join(dir, "*.lock")); len(locks) != 0 {
			t.Errorf("orphan lock files in %s: %v", dir, locks)
		}
	}
}

func TestReconfigure_cancelledMidwayRollsBackUsingDetachedContext(t *testing.T) {
	oldDir := filepath.Join(t.TempDir(), "old")
	oldDB := filepath.Join(t.TempDir(), "old.db")
	q := newReconfigureHandler(t, Config{Location: oldDir, RegistryLocation: oldDB, LockPassword: "p"})
	ids := make([]string, 0, 3)
	for _, n := range []string{"a", "b", "c"} {
		_, id, _ := quarantineSample(t, q, n+".bin")
		ids = append(ids, id)
	}
	newDir := filepath.Join(t.TempDir(), "new")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := q.Reconfigure(ctx, Config{Location: newDir, LockPassword: "p"}); err == nil {
		t.Fatal("Reconfigure() with a cancelled context: error = nil")
	}
	for _, id := range ids {
		if _, err := os.Stat(filepath.Join(oldDir, id+".lock")); err != nil {
			t.Errorf("%s.lock must be where it was: %v", id, err)
		}
		entry, err := q.registry.Get(t.Context(), id)
		if err != nil || entry.QuarantineLocation != filepath.Join(oldDir, id+".lock") {
			t.Errorf("entry %s = %+v (err %v), want the old location", id, entry, err)
		}
	}
}

func TestReconfigure_rollbackIncompleteIsReported(t *testing.T) {
	oldDir := filepath.Join(t.TempDir(), "old")
	if err := os.MkdirAll(oldDir, 0o700); err != nil {
		t.Fatal(err)
	}
	names := []string{"a.lock", "b.lock"}
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(oldDir, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	sets := 0
	reg := &registryMock{
		GetLocationMock: func() string { return "file::memory:" },
		GetMock: func(_ context.Context, id string) (*Entry, error) {
			if id == "b" {
				return nil, errors.New("registry unavailable")
			}
			return &Entry{ID: id}, nil
		},
		SetMock: func(context.Context, *Entry) error {
			sets++
			// The first lock has just been moved: something takes its place.
			return os.MkdirAll(filepath.Join(oldDir, "a.lock"), 0o700)
		},
	}
	q := &QuarantineHandler{location: oldDir, locker: &tarLocker{Password: "p"}, registry: reg}
	err := q.Reconfigure(t.Context(), Config{Location: filepath.Join(t.TempDir(), "new"), LockPassword: "p"})
	if !errors.Is(err, ErrRollbackIncomplete) {
		t.Fatalf("Reconfigure() error = %v, want ErrRollbackIncomplete", err)
	}
	if sets == 0 {
		t.Fatal("the hook did not run")
	}
}

func TestReconfigure_refusesToOverwriteAndKeepsExistingFile(t *testing.T) {
	oldDir := filepath.Join(t.TempDir(), "old")
	q := newReconfigureHandler(t, Config{Location: oldDir, LockPassword: "p"})
	_, id, _ := quarantineSample(t, q, "a.bin")
	newDir := filepath.Join(t.TempDir(), "new")
	if err := os.MkdirAll(newDir, 0o700); err != nil {
		t.Fatal(err)
	}
	existing := filepath.Join(newDir, id+".lock")
	if err := os.WriteFile(existing, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := q.Reconfigure(t.Context(), Config{Location: newDir, LockPassword: "p"}); err == nil {
		t.Fatal("Reconfigure() error = nil, want a refusal to overwrite")
	}
	if got, err := os.ReadFile(filepath.Clean(existing)); err != nil || string(got) != "precious" {
		t.Errorf("existing file = %q (err %v), want it intact", got, err)
	}
	if _, err := os.Stat(filepath.Join(oldDir, id+".lock")); err != nil {
		t.Errorf("the lock must stay in the old directory: %v", err)
	}
}

func TestReconfigure_nestedDirectoriesRefused(t *testing.T) {
	oldDir := filepath.Join(t.TempDir(), "old")
	q := newReconfigureHandler(t, Config{Location: oldDir, LockPassword: "p"})
	_, id, _ := quarantineSample(t, q, "a.bin")
	for name, dir := range map[string]string{"inside": filepath.Join(oldDir, "sub"), "parent": filepath.Dir(oldDir)} {
		if err := q.Reconfigure(t.Context(), Config{Location: dir, LockPassword: "p"}); err == nil {
			t.Errorf("%s: Reconfigure() error = nil, want a refusal", name)
		}
	}
	if q.location != oldDir {
		t.Error("the location must not change")
	}
	if _, err := os.Stat(filepath.Join(oldDir, id+".lock")); err != nil {
		t.Errorf("the lock must not move: %v", err)
	}
}

func TestReconfigure_missingOldDirectoryHasNothingToMove(t *testing.T) {
	oldDir := filepath.Join(t.TempDir(), "old")
	q := newReconfigureHandler(t, Config{Location: oldDir, LockPassword: "p"})
	if err := os.Remove(oldDir); err != nil {
		t.Fatal(err)
	}
	if err := q.Reconfigure(t.Context(), Config{Location: filepath.Join(t.TempDir(), "new"), LockPassword: "p"}); err != nil {
		t.Errorf("Reconfigure() error = %v, want the change accepted", err)
	}
}

func TestReconfigure_sameRegistryRollbackRestoresEntries(t *testing.T) {
	oldDir := filepath.Join(t.TempDir(), "old")
	oldDB := filepath.Join(t.TempDir(), "same.db")
	q := newReconfigureHandler(t, Config{Location: oldDir, RegistryLocation: oldDB, LockPassword: "p"})
	_, id1, _ := quarantineSample(t, q, "a.bin")
	_, id2, _ := quarantineSample(t, q, "b.bin")
	newDir := filepath.Join(t.TempDir(), "new")
	if err := os.MkdirAll(filepath.Join(newDir, id2+".lock"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(newDir, id1+".lock"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := q.Reconfigure(t.Context(), Config{Location: newDir, RegistryLocation: oldDB, LockPassword: "p"}); err == nil {
		t.Fatal("Reconfigure() error = nil")
	}
	for _, id := range []string{id1, id2} {
		entry, err := q.registry.Get(t.Context(), id)
		if err != nil || entry.QuarantineLocation != filepath.Join(oldDir, id+".lock") {
			t.Errorf("entry %s = %+v (err %v), want the old location", id, entry, err)
		}
	}
}

func TestReconfigure_removesEveryCreatedLevel(t *testing.T) {
	oldDir := filepath.Join(t.TempDir(), "old")
	q := newReconfigureHandler(t, Config{Location: oldDir, LockPassword: "p"})
	_, id, _ := quarantineSample(t, q, "a.bin")
	base := t.TempDir()
	newDir := filepath.Join(base, "q1", "q2")
	if err := os.MkdirAll(newDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(newDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Dir(newDir)); err != nil {
		t.Fatal(err)
	}
	failing := &QuarantineHandler{location: oldDir, locker: q.locker, registry: &registryMock{
		GetLocationMock: func() string { return "file::memory:" },
		GetMock:         func(context.Context, string) (*Entry, error) { return nil, errors.New("registry unavailable") },
	}}
	if err := failing.Reconfigure(t.Context(), Config{Location: newDir, LockPassword: "p"}); err == nil {
		t.Fatal("error = nil")
	}
	if _, err := os.Stat(filepath.Join(base, "q1")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("every level created must be removed (stat error = %v)", err)
	}
	_ = id
}

func TestReconfigure_backToThePreviousRegistryMergesAndOtherExistingOnesAreRefused(t *testing.T) {
	dirA := filepath.Join(t.TempDir(), "a")
	dirB := filepath.Join(t.TempDir(), "b")
	regA := filepath.Join(t.TempDir(), "a.db")
	regB := filepath.Join(t.TempDir(), "b.db")
	q := newReconfigureHandler(t, Config{Location: dirA, RegistryLocation: regA, LockPassword: "p"})
	if err := q.Reconfigure(t.Context(), Config{Location: dirB, RegistryLocation: regB, LockPassword: "p"}); err != nil {
		t.Fatal(err)
	}
	src, id, content := quarantineSample(t, q, "later.bin")
	if err := os.Remove(src); err != nil {
		t.Fatal(err)
	}
	// regA still exists, stale: it is the registry just left, so it is refreshed.
	if err := q.Reconfigure(t.Context(), Config{Location: dirA, RegistryLocation: regA, LockPassword: "p"}); err != nil {
		t.Fatalf("Reconfigure() back to the previous registry error = %v", err)
	}
	if err := q.Restore(t.Context(), id); err != nil {
		t.Fatalf("Restore() of an entry written meanwhile error = %v", err)
	}
	if got, err := os.ReadFile(filepath.Clean(src)); err != nil || string(got) != string(content) {
		t.Errorf("restored = %q (err %v)", got, err)
	}
	// An unrelated registry that already holds entries is refused.
	other := filepath.Join(t.TempDir(), "other.db")
	pre, err := newSQLiteRegistry(t.Context(), other)
	if err != nil {
		t.Fatal(err)
	}
	if err = pre.Set(t.Context(), &Entry{ID: "x", SHA256: "s"}); err != nil {
		t.Fatal(err)
	}
	if err = pre.Close(); err != nil {
		t.Fatal(err)
	}
	if err = q.Reconfigure(t.Context(), Config{Location: dirA, RegistryLocation: other, LockPassword: "p"}); err == nil {
		t.Error("Reconfigure() into an unrelated non-empty registry: error = nil")
	}
}
