package quarantine

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// testDeadline is how long a test waits for what must not hang.
const testDeadline = 10 * time.Second

// flakyRegistry is a registry whose writes can be made to fail, or to hang until
// their context ends or release is closed, and that records them.
type flakyRegistry struct {
	quarantineRegistry
	mu      sync.Mutex
	failAt  map[int]error // the n-th call of Set (from 1) fails with this error
	hangAt  map[int]bool  // the n-th call of Set (from 1) hangs
	release chan struct{} // closed by the test: frees the calls that hang
	sets    []Entry
}

func (r *flakyRegistry) Set(ctx context.Context, e *Entry) error {
	r.mu.Lock()
	r.sets = append(r.sets, *e)
	n := len(r.sets)
	err := r.failAt[n]
	hang := r.hangAt[n]
	r.mu.Unlock()
	if hang {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-r.release:
			return errors.New("released")
		}
	}
	if err != nil {
		return err
	}
	return r.quarantineRegistry.Set(ctx, e)
}

// hangingOn wraps the registry of q so that its n-th write hangs; the writes that
// hang are freed when the test ends.
func hangingOn(t *testing.T, q *QuarantineHandler, n int) {
	t.Helper()
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	q.registry = &flakyRegistry{quarantineRegistry: q.registry, hangAt: map[int]bool{n: true}, release: release}
}

// quarantined quarantines a sample and deletes it, as the removal does: what a
// restoration brings back is then to be put at a free name.
func quarantined(t *testing.T, q *QuarantineHandler, name, content string) (path, id string) {
	t.Helper()
	path = writeSample(t, name, []byte(content))
	_, id, err := quarantinePath(t.Context(), t, q, path, sha256Hex([]byte(content)), []string{"m"})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	return path, id
}

func assertNotRestored(t *testing.T, q *QuarantineHandler, id string) {
	t.Helper()
	entry, err := q.registry.Get(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	if entry.Restored() || entry.QuarantineLocation == "" {
		t.Errorf("entry = %+v, want it as quarantined: not marked restored, still located", entry)
	}
}

func assertContent(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(filepath.Clean(path))
	if err != nil || string(got) != want {
		t.Errorf("%s = %q (%v), want %q", path, got, err, want)
	}
}

func assertNoTemp(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), TempPrefix) {
			t.Errorf("temporary file %q left behind", e.Name())
		}
	}
}

func TestRestore_neverReplacesAFileThatIsThere(t *testing.T) {
	q, dir := newE2EHandler(t, FormatTar)
	path, id := quarantined(t, q, "f.bin", "quarantined content")
	if err := os.WriteFile(path, []byte("deposited since"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := q.Restore(t.Context(), id)
	if !errors.Is(err, ErrDestinationExists) {
		t.Fatalf("Restore() = %v, want ErrDestinationExists", err)
	}
	assertContent(t, path, "deposited since")
	assertNotRestored(t, q, id)
	if _, statErr := os.Stat(filepath.Join(dir, id+".lock")); statErr != nil {
		t.Errorf("the container is gone: %v", statErr)
	}
	assertNoTemp(t, filepath.Dir(path))
	// The name is freed: the same restoration now works, and the registry is marked.
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err = q.Restore(t.Context(), id); err != nil {
		t.Fatalf("Restore() after the name was freed = %v", err)
	}
	assertContent(t, path, "quarantined content")
}

func TestRestore_theRegistryIsMarkedBeforeThePublicationAndPutBackOnFailure(t *testing.T) {
	t.Run("a registry that cannot be written publishes nothing", func(t *testing.T) {
		q, dir := newE2EHandler(t, FormatTar)
		path, id := quarantined(t, q, "f.bin", "content")
		reg := &flakyRegistry{quarantineRegistry: q.registry, failAt: map[int]error{1: errors.New("database is locked")}}
		q.registry = reg
		if err := q.Restore(t.Context(), id); err == nil {
			t.Fatal("Restore() succeeded with a registry that cannot be written")
		}
		if _, err := os.Stat(path); err == nil {
			t.Error("a file was published although the registry could not be marked")
		}
		assertNotRestored(t, q, id)
		if _, err := os.Stat(filepath.Join(dir, id+".lock")); err != nil {
			t.Errorf("the container is gone: %v", err)
		}
		assertNoTemp(t, filepath.Dir(path))
	})
	t.Run("a publication that fails puts the entry back as it was", func(t *testing.T) {
		q, _ := newE2EHandler(t, FormatTar)
		path, id := quarantined(t, q, "f.bin", "content")
		if err := os.WriteFile(path, []byte("in the way"), 0o600); err != nil {
			t.Fatal(err)
		}
		reg := &flakyRegistry{quarantineRegistry: q.registry}
		q.registry = reg
		if err := q.Restore(t.Context(), id); !errors.Is(err, ErrDestinationExists) || errors.Is(err, ErrRestoreRollbackFailed) {
			t.Fatalf("Restore() = %v, want ErrDestinationExists alone: the entry was put back", err)
		}
		if len(reg.sets) != 2 || !reg.sets[0].Restored() || reg.sets[1].Restored() || reg.sets[1].QuarantineLocation == "" {
			t.Errorf("registry writes = %+v, want the mark then the entry as it was", reg.sets)
		}
		assertNotRestored(t, q, id)
	})
	t.Run("an entry that cannot be put back is said, and the container stays restorable", func(t *testing.T) {
		q, dir := newE2EHandler(t, FormatTar)
		path, id := quarantined(t, q, "f.bin", "content")
		if err := os.WriteFile(path, []byte("in the way"), 0o600); err != nil {
			t.Fatal(err)
		}
		reg := &flakyRegistry{quarantineRegistry: q.registry, failAt: map[int]error{2: errors.New("disk full")}}
		q.registry = reg
		err := q.Restore(t.Context(), id)
		if !errors.Is(err, ErrDestinationExists) || !errors.Is(err, ErrRestoreRollbackFailed) || !strings.Contains(err.Error(), "disk full") {
			t.Fatalf("Restore() = %v, want the publication failure, ErrRestoreRollbackFailed and the cause of the registry", err)
		}
		if _, statErr := os.Stat(filepath.Join(dir, id+".lock")); statErr != nil {
			t.Fatalf("the container is gone: %v", statErr)
		}
		// Marked restored, container still there: restorable again once the name is free.
		if err = os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err = q.Restore(t.Context(), id); err != nil {
			t.Fatalf("Restore() of an entry marked restored whose container is still there = %v", err)
		}
		assertContent(t, path, "content")
	})
}

func TestRestore_withoutAHardLinkTheFileIsStillNeverReplaced(t *testing.T) {
	prev := rootLink
	rootLink = func(*os.Root, string, string) error { return syscall.EPERM }
	t.Cleanup(func() { rootLink = prev })
	t.Run("a free name is published by rename", func(t *testing.T) {
		q, _ := newE2EHandler(t, FormatTar)
		path, id := quarantined(t, q, "f.bin", "content")
		if err := q.Restore(t.Context(), id); err != nil {
			t.Fatalf("Restore() = %v", err)
		}
		assertContent(t, path, "content")
		assertNoTemp(t, filepath.Dir(path))
	})
	t.Run("a taken name is refused", func(t *testing.T) {
		q, _ := newE2EHandler(t, FormatTar)
		path, id := quarantined(t, q, "f.bin", "content")
		if err := os.WriteFile(path, []byte("in the way"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := q.Restore(t.Context(), id); !errors.Is(err, ErrDestinationExists) {
			t.Fatalf("Restore() = %v, want ErrDestinationExists", err)
		}
		assertContent(t, path, "in the way")
		assertNoTemp(t, filepath.Dir(path))
	})
}

// unregisteredHandler is a handler over the quarantine directory of q with a
// registry that knows nothing: what is in the directory has no entry.
func unregisteredHandler(t *testing.T, dir string, conf Config) *QuarantineHandler {
	t.Helper()
	conf.Location, conf.LockPassword = dir, "infected"
	q, err := NewQuarantineHandler(t.Context(), conf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if e := q.Close(); e != nil {
			t.Errorf("Close() error = %v", e)
		}
	})
	return q
}

// plantContainer writes a container for content with the index saying path, as
// the id given (the id a real quarantine would give by default).
func plantContainer(t *testing.T, dir, path, content, id string) {
	t.Helper()
	locker, err := newQuarantineLocker("infected", FormatTar)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	info := &zipFakeFileInfo{size: int64(len(content)), mode: 0o644, modTime: time.Now().Truncate(time.Second)}
	if err = locker.LockFile(path, bytes.NewReader([]byte(content)), info, "malware: planted", &buf); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, id+".lock"), buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func captureQuarantineLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := logger
	logger = slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	t.Cleanup(func() { logger = prev })
	return &buf
}

func TestRestore_aContainerWithoutARegistryEntryIsRestoredAndSaidSo(t *testing.T) {
	q, dir := newE2EHandler(t, FormatTar)
	path, id := quarantined(t, q, "f.bin", "unregistered content")
	type call struct{ id, dest, sha string }
	called := make(chan call, 2)
	other := unregisteredHandler(t, dir, Config{WatchedPaths: []string{filepath.Dir(path)}})
	other.SetUnregisteredRestoreHook(func(_ context.Context, id, dest, sha string) {
		called <- call{id, dest, sha}
	})
	logs := captureQuarantineLogs(t)
	if err := other.Restore(t.Context(), id); err != nil {
		t.Fatalf("Restore() = %v", err)
	}
	assertContent(t, path, "unregistered content")
	if _, err := os.Stat(filepath.Join(dir, id+".lock")); err == nil {
		t.Error("the container must be removed after a restoration")
	}
	select {
	case got := <-called:
		if got != (call{id, path, sha256Hex([]byte("unregistered content"))}) {
			t.Errorf("hook call = %+v, want one for %s", got, path)
		}
	case <-time.After(testDeadline):
		t.Error("the hook was not called")
	}
	if !strings.Contains(logs.String(), "has no registry entry") {
		t.Errorf("no warning: %s", logs)
	}
	if restored, err := other.IsRestored(t.Context(), path, sha256Hex([]byte("unregistered content"))); err != nil || !restored {
		t.Errorf("IsRestored() = %v, %v: the file must now count as restored", restored, err)
	}
	// A restoration with an entry does not call the hook.
	q2, dir2 := newE2EHandler(t, FormatTar)
	_, id2 := quarantined(t, q2, "g.bin", "registered content")
	var registeredCalls atomic.Int32
	q2.SetUnregisteredRestoreHook(func(context.Context, string, string, string) { registeredCalls.Add(1) })
	if err := q2.Restore(t.Context(), id2); err != nil {
		t.Errorf("Restore() = %v (%s)", err, dir2)
	}
	time.Sleep(50 * time.Millisecond)
	if registeredCalls.Load() != 0 {
		t.Error("a restoration with an entry called the hook")
	}
}

func TestRestore_hostileIndexOfAContainerWithoutAnEntryIsRefusedAndNothingIsWritten(t *testing.T) {
	work, other := t.TempDir(), t.TempDir()
	quarantineDir := t.TempDir()
	q := unregisteredHandler(t, quarantineDir, Config{})
	q.SetWorkDir(work)
	existing := filepath.Join(other, "there.bin")
	if err := os.WriteFile(existing, []byte("a file that is there"), 0o600); err != nil {
		t.Fatal(err)
	}
	linkTarget := t.TempDir()
	linkDir := filepath.Join(other, "link")
	if err := os.Symlink(linkTarget, linkDir); err != nil {
		t.Skip("symbolic links not available:", err)
	}
	const content = "payload"
	tests := []struct {
		name    string
		path    string
		idOf    string // the path the id is computed on, when it is not path
		wantErr error
		watched []string
	}{
		{name: "relative path", path: "rel/f.bin", wantErr: ErrRestorePathMismatch},
		{name: "a parent element", path: other + "/a/../b/f.bin", wantErr: ErrRestorePathMismatch},
		{name: "not clean", path: other + "//sub/f.bin", wantErr: ErrRestorePathMismatch},
		{name: "a NUL", path: other + "/f\x00.bin", wantErr: ErrRestorePathMismatch},
		{name: "in the work directory", path: filepath.Join(work, "extract", "f.bin"), wantErr: ErrRestorePathMismatch},
		{name: "in the quarantine directory", path: filepath.Join(quarantineDir, "f.bin"), wantErr: ErrRestorePathMismatch},
		{name: "in the staging directory", path: filepath.Join(other, StagingDir, "f.bin"), wantErr: ErrRestorePathMismatch},
		{name: "a temporary name", path: filepath.Join(other, TempPrefix+"x"), wantErr: ErrRestorePathMismatch},
		{name: "an id that is not the one of this content", path: filepath.Join(other, "mismatch.bin"), idOf: filepath.Join(other, "else.bin"), wantErr: ErrRestorePathMismatch},
		{name: "a file that is there", path: existing, wantErr: ErrDestinationExists},
		{name: "outside every watched path", path: filepath.Join(other, "unwatched.bin"), wantErr: ErrRestoreDestinationUnsafe, watched: []string{t.TempDir()}},
		{name: "below a link", path: filepath.Join(linkDir, "f.bin"), wantErr: ErrRestoreDestinationUnsafe, watched: []string{other}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idOf := tt.path
			if tt.idOf != "" {
				idOf = tt.idOf
			}
			id := ComputeCacheID(idOf, sha256Hex([]byte(content)))
			plantContainer(t, quarantineDir, tt.path, content, id)
			q.watched = []string{other}
			if tt.watched != nil {
				q.watched = tt.watched
			}
			err := q.Restore(t.Context(), id)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Restore() = %v, want %v", err, tt.wantErr)
			}
			if _, statErr := os.Stat(filepath.Join(quarantineDir, id+".lock")); statErr != nil {
				t.Errorf("the container is gone: %v", statErr)
			}
			for _, dir := range []string{other, linkTarget, work} {
				assertNoTemp(t, dir)
			}
			if entries, readErr := os.ReadDir(linkTarget); readErr != nil || len(entries) != 0 {
				t.Errorf("something was written through the link: %v (%v)", entries, readErr)
			}
			assertContent(t, existing, "a file that is there")
		})
	}
}

func TestRestore_theDestinationInTheWorkDirectoryIsRefusedWithAnEntryToo(t *testing.T) {
	q, _ := newE2EHandler(t, FormatTar)
	path, id := quarantined(t, q, "f.bin", "content")
	q.SetWorkDir(filepath.Dir(path))
	if err := q.Restore(t.Context(), id); !errors.Is(err, ErrRestorePathMismatch) {
		t.Fatalf("Restore() = %v, want it refused: the destination is in the work directory", err)
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("something was written in the work directory")
	}
	q.SetWorkDir("")
	if err := q.Restore(t.Context(), id); err != nil {
		t.Fatalf("Restore() without a work directory = %v", err)
	}
}

func TestRestore_aContainerThatIsALinkOrNotInTheTopLevelIsRefusedAndNotListed(t *testing.T) {
	q, dir := newE2EHandler(t, FormatTar)
	path, id := quarantined(t, q, "f.bin", "content")
	lock := filepath.Join(dir, id+".lock")
	target := filepath.Join(t.TempDir(), "target.lock")
	if err := os.Rename(lock, target); err != nil {
		t.Fatal(err)
	}
	logs := captureQuarantineLogs(t)
	t.Run("a link", func(t *testing.T) {
		if err := os.Symlink(target, lock); err != nil {
			t.Skip("symbolic links not available:", err)
		}
		defer func() {
			if err := os.Remove(lock); err != nil {
				t.Fatal(err)
			}
		}()
		if err := q.Restore(t.Context(), id); err == nil {
			t.Error("Restore() accepted a container that is a link")
		}
		if _, err := os.Stat(path); err == nil {
			t.Error("something was restored from a link")
		}
		for f, err := range q.ListQuarantinedFiles(t.Context()) {
			if err != nil || f != nil {
				t.Errorf("a container that is a link is listed: %+v, %v", f, err)
			}
		}
		if !strings.Contains(logs.String(), "not a container, skipped") {
			t.Errorf("no warning for the link: %s", logs)
		}
	})
	t.Run("a link to a container of the same directory", func(t *testing.T) {
		if err := os.Symlink("elsewhere.lock", lock); err != nil {
			t.Skip("symbolic links not available:", err)
		}
		if err := os.Link(target, filepath.Join(dir, "elsewhere.lock")); err != nil {
			t.Fatal(err)
		}
		defer func() {
			for _, name := range []string{lock, filepath.Join(dir, "elsewhere.lock")} {
				if err := os.Remove(name); err != nil {
					t.Fatal(err)
				}
			}
		}()
		if err := q.Restore(t.Context(), id); err == nil {
			t.Error("Restore() followed a link to another container of the directory")
		}
		for f, err := range q.ListQuarantinedFiles(t.Context()) {
			if err != nil || f != nil {
				t.Errorf("a link is listed: %+v, %v", f, err)
			}
		}
	})
	t.Run("a directory", func(t *testing.T) {
		if err := os.Mkdir(lock, 0o750); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := os.Remove(lock); err != nil {
				t.Fatal(err)
			}
		}()
		if err := q.Restore(t.Context(), id); err == nil {
			t.Error("Restore() accepted a container that is a directory")
		}
		for f, err := range q.ListQuarantinedFiles(t.Context()) {
			if err != nil || f != nil {
				t.Errorf("a directory called like a container is listed: %+v, %v", f, err)
			}
		}
	})
	t.Run("in a sub-directory", func(t *testing.T) {
		sub := filepath.Join(dir, "sub")
		if err := os.Mkdir(sub, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(target, filepath.Join(sub, id+".lock")); err != nil {
			t.Fatal(err)
		}
		for f, err := range q.ListQuarantinedFiles(t.Context()) {
			if err != nil || f != nil {
				t.Errorf("a container of a sub-directory is listed: %+v, %v", f, err)
			}
		}
		if err := q.Restore(t.Context(), id); err == nil {
			t.Error("Restore() found a container in a sub-directory")
		}
	})
	t.Run("what is not named like a container", func(t *testing.T) {
		if err := os.Link(target, filepath.Join(dir, "notanid.lock")); err != nil {
			t.Fatal(err)
		}
		for f, err := range q.ListQuarantinedFiles(t.Context()) {
			if err != nil || f != nil {
				t.Errorf("a name that is not an id is listed: %+v, %v", f, err)
			}
		}
		if !strings.Contains(logs.String(), "not the name of a container") {
			t.Errorf("no warning for the name: %s", logs)
		}
	})
}

func TestRestore_aFailedPublicationOfAContainerWithoutEntryWritesNoEntry(t *testing.T) {
	q, dir := newE2EHandler(t, FormatTar)
	path, id := quarantined(t, q, "f.bin", "content")
	other := unregisteredHandler(t, dir, Config{WatchedPaths: []string{filepath.Dir(path)}})
	reg := &flakyRegistry{quarantineRegistry: other.registry}
	other.registry = reg
	if err := os.WriteFile(path, []byte("in the way"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := other.Restore(t.Context(), id); !errors.Is(err, ErrDestinationExists) {
		t.Fatalf("Restore() = %v, want ErrDestinationExists", err)
	}
	if len(reg.sets) != 0 {
		t.Errorf("registry writes = %+v, want none: nothing is registered before the file is published", reg.sets)
	}
	if _, err := other.registry.Get(t.Context(), id); !errors.Is(err, errEntryNotFound) {
		t.Errorf("Get() = %v, want no entry: the file must not count as restored", err)
	}
	if restored, err := other.IsRestored(t.Context(), path, sha256Hex([]byte("content"))); err != nil || restored {
		t.Errorf("IsRestored() = %v, %v, want false", restored, err)
	}
}

func TestRestore_aContainerWithoutEntryIsNotRestoredOutsideTheWatchedPaths(t *testing.T) {
	q, dir := newE2EHandler(t, FormatTar)
	path, id := quarantined(t, q, "f.bin", "content")
	other := unregisteredHandler(t, dir, Config{WatchedPaths: []string{t.TempDir()}})
	err := other.Restore(t.Context(), id)
	if !errors.Is(err, ErrRestoreDestinationUnsafe) || !strings.Contains(err.Error(), "registry entry") {
		t.Fatalf("Restore() = %v, want ErrRestoreDestinationUnsafe saying to restore it with a registry entry", err)
	}
	if _, statErr := os.Stat(path); statErr == nil {
		t.Error("a file was written")
	}
	if _, getErr := other.registry.Get(t.Context(), id); !errors.Is(getErr, errEntryNotFound) {
		t.Errorf("Get() = %v, want no entry", getErr)
	}
	if _, statErr := os.Stat(filepath.Join(dir, id+".lock")); statErr != nil {
		t.Errorf("the container is gone: %v", statErr)
	}
}

func TestRestore_publicationWithoutALinkPrefersTheAtomicRenameAndOnlyThenTheLock(t *testing.T) {
	prevLink, prevRename := rootLink, rootRenameNoReplace
	rootLink = func(*os.Root, string, string) error { return syscall.EPERM }
	t.Cleanup(func() { rootLink, rootRenameNoReplace = prevLink, prevRename })

	t.Run("a destination taken by someone else is refused by the kernel, not by a check", func(t *testing.T) {
		rootRenameNoReplace = func(root *os.Root, oldname, newname string) (bool, error) {
			if err := os.WriteFile(filepath.Join(root.Name(), newname), []byte("written by another process"), 0o600); err != nil {
				t.Fatal(err)
			}
			return prevRename(root, oldname, newname)
		}
		q, _ := newE2EHandler(t, FormatTar)
		path, id := quarantined(t, q, "f.bin", "content")
		if err := q.Restore(t.Context(), id); !errors.Is(err, ErrDestinationExists) {
			t.Fatalf("Restore() = %v, want ErrDestinationExists", err)
		}
		assertContent(t, path, "written by another process")
	})
	t.Run("without the atomic rename the check under the lock is the last resort", func(t *testing.T) {
		calls := 0
		rootRenameNoReplace = func(*os.Root, string, string) (bool, error) {
			calls++
			return false, nil
		}
		q, _ := newE2EHandler(t, FormatTar)
		path, id := quarantined(t, q, "f.bin", "content")
		if err := q.Restore(t.Context(), id); err != nil {
			t.Fatalf("Restore() = %v", err)
		}
		assertContent(t, path, "content")
		if calls != 1 {
			t.Errorf("the atomic rename was tried %d times, want once", calls)
		}
	})
	t.Run("the check under the lock refuses a taken name", func(t *testing.T) {
		rootRenameNoReplace = func(*os.Root, string, string) (bool, error) { return false, nil }
		q, _ := newE2EHandler(t, FormatTar)
		path, id := quarantined(t, q, "f.bin", "content")
		if err := os.WriteFile(path, []byte("in the way"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := q.Restore(t.Context(), id); !errors.Is(err, ErrDestinationExists) {
			t.Fatalf("Restore() = %v, want ErrDestinationExists", err)
		}
		assertContent(t, path, "in the way")
	})
	t.Run("a failure of the atomic rename is not a reason to fall back", func(t *testing.T) {
		boom := errors.New("boom")
		rootRenameNoReplace = func(*os.Root, string, string) (bool, error) { return true, boom }
		q, _ := newE2EHandler(t, FormatTar)
		path, id := quarantined(t, q, "f.bin", "content")
		if err := q.Restore(t.Context(), id); !errors.Is(err, boom) {
			t.Fatalf("Restore() = %v, want the failure", err)
		}
		if _, err := os.Stat(path); err == nil {
			t.Error("the file was published after a failed atomic rename")
		}
	})
}

func TestReconfigure_neverChangesTheBindingsOfTheRunningInstance(t *testing.T) {
	q, dir := newE2EHandler(t, FormatTar)
	path, id := quarantined(t, q, "f.bin", "content")
	q.SetWorkDir(filepath.Dir(path))
	q.SetUnregisteredRestoreHook(func(context.Context, string, string, string) {})
	conf := Config{Location: dir, LockPassword: "infected", Format: FormatTar, WatchedPaths: []string{filepath.Dir(path)}}
	if err := q.Reconfigure(t.Context(), conf); err != nil {
		t.Fatalf("Reconfigure() = %v", err)
	}
	if err := q.Restore(t.Context(), id); !errors.Is(err, ErrRestorePathMismatch) {
		t.Fatalf("Restore() = %v, want the work directory still protected after a Reconfigure", err)
	}
	if q.onUnregistered.Load() == nil {
		t.Error("Reconfigure removed the hook")
	}
}

// A container without entry is published first and registered after: when the
// registry then fails, the file is there, no entry exists, and the error says so.
func TestRestore_aContainerWithoutEntryWhoseRegistrationFailsIsRestoredButNotRegistered(t *testing.T) {
	q, dir := newE2EHandler(t, FormatTar)
	path, id := quarantined(t, q, "f.bin", "content")
	other := unregisteredHandler(t, dir, Config{WatchedPaths: []string{filepath.Dir(path)}})
	reg := &flakyRegistry{quarantineRegistry: other.registry, failAt: map[int]error{1: errors.New("database is locked")}}
	other.registry = reg
	var hookCalls atomic.Int32
	other.SetUnregisteredRestoreHook(func(context.Context, string, string, string) { hookCalls.Add(1) })
	err := other.Restore(t.Context(), id)
	if !errors.Is(err, ErrRestoredNotRegistered) || errors.Is(err, ErrRestoreRollbackFailed) || !strings.Contains(err.Error(), "database is locked") {
		t.Fatalf("Restore() = %v, want ErrRestoredNotRegistered with the cause, and not a failed rollback", err)
	}
	assertContent(t, path, "content")
	if _, getErr := other.registry.Get(t.Context(), id); !errors.Is(getErr, errEntryNotFound) {
		t.Errorf("Get() = %v, want no entry", getErr)
	}
	if _, statErr := os.Stat(filepath.Join(dir, id+".lock")); statErr == nil {
		t.Error("the container of a file that was restored must be removed")
	}
	time.Sleep(50 * time.Millisecond)
	if hookCalls.Load() != 0 {
		t.Error("the hook of the unregistered restorations was called for a restoration that could not be registered")
	}
}

// The order of a restoration with an entry is the other way round: marked first.
func TestRestore_aContainerWithAnEntryIsMarkedBeforeItIsPublished(t *testing.T) {
	q, _ := newE2EHandler(t, FormatTar)
	path, id := quarantined(t, q, "f.bin", "content")
	reg := &flakyRegistry{quarantineRegistry: q.registry}
	q.registry = reg
	prev := rootLink
	rootLink = func(root *os.Root, oldname, newname string) error {
		if len(reg.sets) != 1 || !reg.sets[0].Restored() {
			t.Errorf("at the publication the registry writes are %+v, want the mark", reg.sets)
		}
		return prev(root, oldname, newname)
	}
	t.Cleanup(func() { rootLink = prev })
	if err := q.Restore(t.Context(), id); err != nil {
		t.Fatalf("Restore() = %v", err)
	}
	assertContent(t, path, "content")
}

// The hook pushes a network event: it runs on its own, and never delays the reply.
func TestRestore_aBlockingHookDoesNotDelayTheReply(t *testing.T) {
	q, dir := newE2EHandler(t, FormatTar)
	path, id := quarantined(t, q, "f.bin", "content")
	other := unregisteredHandler(t, dir, Config{WatchedPaths: []string{filepath.Dir(path)}})
	release := make(chan struct{})
	started := make(chan struct{})
	other.SetUnregisteredRestoreHook(func(ctx context.Context, _, _, _ string) {
		close(started)
		select {
		case <-release:
		case <-ctx.Done():
		}
	})
	defer close(release)
	done := make(chan error, 1)
	go func() { done <- other.Restore(t.Context(), id) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Restore() = %v", err)
		}
	case <-time.After(testDeadline):
		t.Fatal("Restore() waited for the hook")
	}
	select {
	case <-started:
	case <-time.After(testDeadline):
		t.Error("the hook was never called")
	}
}

// What an outside process can swap for the container between the examination of
// its name and its opening is refused.
func TestRestore_aContainerSwappedBetweenTheExaminationAndTheOpeningIsRefused(t *testing.T) {
	t.Run("a link to another container", func(t *testing.T) {
		q, dir := newE2EHandler(t, FormatTar)
		_, id := quarantined(t, q, "f.bin", "content")
		_, otherID := quarantined(t, q, "g.bin", "other content")
		lock := filepath.Join(dir, id+".lock")
		prev := betweenLstatAndOpen
		betweenLstatAndOpen = func() {
			betweenLstatAndOpen = prev
			if err := os.Remove(lock); err != nil {
				t.Error(err)
			}
			if err := os.Symlink(otherID+".lock", lock); err != nil {
				t.Error(err)
			}
		}
		t.Cleanup(func() { betweenLstatAndOpen = prev })
		err := q.Restore(t.Context(), id)
		if err == nil || !errors.Is(err, errInvalidQuarantineID) {
			t.Fatalf("Restore() = %v, want the swap refused", err)
		}
	})
	t.Run("a file that is not the one named", func(t *testing.T) {
		q, dir := newE2EHandler(t, FormatTar)
		_, id := quarantined(t, q, "f.bin", "content")
		_, otherID := quarantined(t, q, "g.bin", "other content")
		lock := filepath.Join(dir, id+".lock")
		prev := betweenLstatAndOpen
		betweenLstatAndOpen = func() {
			betweenLstatAndOpen = prev
			if err := os.Remove(lock); err != nil {
				t.Error(err)
			}
			if err := os.Rename(filepath.Join(dir, otherID+".lock"), lock); err != nil {
				t.Error(err)
			}
		}
		t.Cleanup(func() { betweenLstatAndOpen = prev })
		if err := q.Restore(t.Context(), id); err == nil {
			t.Fatal("Restore() restored the content of another container under this id")
		}
	})
}

// The hook outlives the restoration: the cancellation of the context of the
// request does not reach it.
func TestRestore_theHookIsNotCancelledWithTheRequest(t *testing.T) {
	q, dir := newE2EHandler(t, FormatTar)
	path, id := quarantined(t, q, "f.bin", "content")
	other := unregisteredHandler(t, dir, Config{WatchedPaths: []string{filepath.Dir(path)}})
	cancelled := make(chan struct{})
	result := make(chan error, 1)
	other.SetUnregisteredRestoreHook(func(ctx context.Context, _, _, _ string) {
		<-cancelled
		result <- ctx.Err()
	})
	ctx, cancel := context.WithCancel(t.Context())
	if err := other.Restore(ctx, id); err != nil {
		t.Fatalf("Restore() = %v", err)
	}
	cancel()
	close(cancelled)
	select {
	case err := <-result:
		if err != nil {
			t.Errorf("the context of the hook ended with the request: %v", err)
		}
	case <-time.After(testDeadline):
		t.Error("the hook was never called")
	}
}

// within runs restore with a context the test cancels when it ends, and fails the
// test, instead of waiting for the timeout of the package, when it does not
// return in time: whatever it is stuck on is released by the cancellation.
func within(t *testing.T, restore func(ctx context.Context) error) error {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		result <- restore(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-finished:
		case <-time.After(time.Second):
		}
	})
	select {
	case err := <-result:
		return err
	case <-time.After(time.Second):
		t.Fatal("Restore() did not end: the registry holds it")
		return nil
	}
}

// A registry that hangs does not hold the locks of a restoration for ever: its
// writes are bounded, and the restoration ends with the error that says what the
// registry was left as.
func TestRestore_aRegistryThatHangsIsBounded(t *testing.T) {
	prev := registryTimeout
	registryTimeout = 100 * time.Millisecond
	t.Cleanup(func() { registryTimeout = prev })
	t.Run("the marking hangs", func(t *testing.T) {
		q, _ := newE2EHandler(t, FormatTar)
		path, id := quarantined(t, q, "f.bin", "content")
		hangingOn(t, q, 1)
		if err := within(t, func(ctx context.Context) error { return q.Restore(ctx, id) }); err == nil {
			t.Error("Restore() = nil, want the failure of the registry")
		}
		if _, err := os.Stat(path); err == nil {
			t.Error("a file was published although the registry could not be marked")
		}
	})
	t.Run("the undo hangs", func(t *testing.T) {
		q, _ := newE2EHandler(t, FormatTar)
		path, id := quarantined(t, q, "f.bin", "content")
		if err := os.WriteFile(path, []byte("in the way"), 0o600); err != nil {
			t.Fatal(err)
		}
		hangingOn(t, q, 2)
		if err := within(t, func(ctx context.Context) error { return q.Restore(ctx, id) }); !errors.Is(err, ErrRestoreRollbackFailed) {
			t.Errorf("Restore() = %v, want ErrRestoreRollbackFailed", err)
		}
	})
	t.Run("the registration of a container without entry hangs", func(t *testing.T) {
		q, dir := newE2EHandler(t, FormatTar)
		path, id := quarantined(t, q, "f.bin", "content")
		other := unregisteredHandler(t, dir, Config{WatchedPaths: []string{filepath.Dir(path)}})
		hangingOn(t, other, 1)
		if err := within(t, func(ctx context.Context) error { return other.Restore(ctx, id) }); !errors.Is(err, ErrRestoredNotRegistered) {
			t.Errorf("Restore() = %v, want ErrRestoredNotRegistered", err)
		}
	})
	t.Run("the lock of the registry is held by a call that is stuck", func(t *testing.T) {
		q, _ := newE2EHandler(t, FormatTar)
		path, id := quarantined(t, q, "f.bin", "content")
		reg, ok := q.registry.(*sqliteRegistry)
		if !ok {
			t.Fatalf("the registry is a %T", q.registry)
		}
		unlock, err := reg.lock(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer unlock()
		start := time.Now()
		if err = within(t, func(ctx context.Context) error { return q.Restore(ctx, id) }); err == nil {
			t.Error("Restore() = nil, want the failure of the registry")
		}
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Errorf("Restore() took %v with a registry that is held, want about the timeout", elapsed)
		}
		if _, statErr := os.Stat(path); statErr == nil {
			t.Error("a file was published although the registry could not be read")
		}
	})
}

// A write of the registry that was cut but made all the same is undone: the entry
// goes back as it was, and when it cannot, the restoration says so.
func TestRestore_aMarkingThatWasCutIsUndone(t *testing.T) {
	cutButWritten := func(q *QuarantineHandler, failUndo bool) {
		q.registry = &cutRegistry{quarantineRegistry: q.registry, failUndo: failUndo}
	}
	t.Run("the undo works", func(t *testing.T) {
		q, _ := newE2EHandler(t, FormatTar)
		path, id := quarantined(t, q, "f.bin", "content")
		cutButWritten(q, false)
		err := q.Restore(t.Context(), id)
		if err == nil || errors.Is(err, ErrRestoreRollbackFailed) {
			t.Fatalf("Restore() = %v, want the cut marking and no failed rollback", err)
		}
		if _, statErr := os.Stat(path); statErr == nil {
			t.Error("a file was published")
		}
		assertNotRestored(t, q, id)
	})
	t.Run("the undo fails", func(t *testing.T) {
		q, _ := newE2EHandler(t, FormatTar)
		_, id := quarantined(t, q, "f.bin", "content")
		cutButWritten(q, true)
		if err := q.Restore(t.Context(), id); !errors.Is(err, ErrRestoreRollbackFailed) {
			t.Fatalf("Restore() = %v, want ErrRestoreRollbackFailed", err)
		}
	})
}

// gateTakingRegistry reads through the registry, then takes its real gate and
// keeps it until the test ends: the writes that follow wait for a gate that is
// never freed, so nothing is written.
type gateTakingRegistry struct {
	quarantineRegistry
	reg    *sqliteRegistry
	unlock func()
	sets   atomic.Int32
}

func (r *gateTakingRegistry) Set(ctx context.Context, e *Entry) error {
	r.sets.Add(1)
	return r.quarantineRegistry.Set(ctx, e)
}

func (r *gateTakingRegistry) Get(ctx context.Context, id string) (*Entry, error) {
	entry, err := r.quarantineRegistry.Get(ctx, id)
	if err != nil || r.unlock != nil {
		return entry, err
	}
	r.unlock, err = r.reg.lock(ctx)
	return entry, err
}

// A marking that gave up waiting for the registry wrote nothing: there is nothing
// to undo, so it neither waits again nor says that a rollback failed.
func TestRestore_aMarkingThatNeverStartedIsNotUndone(t *testing.T) {
	prev := registryTimeout
	registryTimeout = 400 * time.Millisecond
	t.Cleanup(func() { registryTimeout = prev })
	q, _ := newE2EHandler(t, FormatTar)
	path, id := quarantined(t, q, "f.bin", "content")
	reg, ok := q.registry.(*sqliteRegistry)
	if !ok {
		t.Fatalf("the registry is a %T", q.registry)
	}
	gate := &gateTakingRegistry{quarantineRegistry: reg, reg: reg}
	t.Cleanup(func() {
		if gate.unlock != nil {
			gate.unlock()
		}
	})
	q.registry = gate

	err := within(t, func(ctx context.Context) error { return q.Restore(ctx, id) })
	if err == nil {
		t.Fatal("Restore() = nil, want the failure of the marking")
	}
	if errors.Is(err, ErrRestoreRollbackFailed) {
		t.Errorf("Restore() = %v, a marking that wrote nothing has nothing to roll back", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Restore() = %v, want the deadline", err)
	}
	if n := gate.sets.Load(); n != 1 {
		t.Errorf("the registry was written %d times, want the marking only: nothing was written, so nothing is undone", n)
	}
	if _, statErr := os.Stat(path); statErr == nil {
		t.Error("a file was published although the registry could not be marked")
	}
}

// cutRegistry makes its first write, then says that it was cut (the deadline ended
// while it was being made); the next write is the undo, which fails when failUndo.
type cutRegistry struct {
	quarantineRegistry
	mu       sync.Mutex
	calls    int
	failUndo bool
}

func (r *cutRegistry) Set(ctx context.Context, e *Entry) error {
	r.mu.Lock()
	r.calls++
	call := r.calls
	r.mu.Unlock()
	switch {
	case call == 1:
		if err := r.quarantineRegistry.Set(ctx, e); err != nil {
			return err
		}
		return context.DeadlineExceeded
	case call == 2 && r.failUndo:
		return errors.New("the undo fails too")
	}
	return r.quarantineRegistry.Set(ctx, e)
}

// A container that cannot be removed after a restoration is said: the file is
// restored all the same, and restoring it again would fail.
func TestRestore_aContainerThatCannotBeRemovedIsSaid(t *testing.T) {
	t.Run("registered", func(t *testing.T) {
		q, _ := newE2EHandler(t, FormatTar)
		path, id := quarantined(t, q, "f.bin", "content")
		containerNotRemovable(t)
		err := q.Restore(t.Context(), id)
		if !errors.Is(err, ErrRestoredLockKept) {
			t.Fatalf("Restore() = %v, want ErrRestoredLockKept", err)
		}
		assertContent(t, path, "content")
	})
	t.Run("without entry", func(t *testing.T) {
		q, dir := newE2EHandler(t, FormatTar)
		path, id := quarantined(t, q, "f.bin", "content")
		other := unregisteredHandler(t, dir, Config{WatchedPaths: []string{filepath.Dir(path)}})
		var hookCalls atomic.Int32
		other.SetUnregisteredRestoreHook(func(context.Context, string, string, string) { hookCalls.Add(1) })
		containerNotRemovable(t)
		err := other.Restore(t.Context(), id)
		if !errors.Is(err, ErrRestoredLockKept) || errors.Is(err, ErrRestoredNotRegistered) {
			t.Fatalf("Restore() = %v, want ErrRestoredLockKept alone: the entry was written", err)
		}
		assertContent(t, path, "content")
		if _, getErr := other.registry.Get(t.Context(), id); getErr != nil {
			t.Errorf("Get() = %v, want the entry", getErr)
		}
		deadline := time.Now().Add(testDeadline)
		for hookCalls.Load() != 1 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if hookCalls.Load() != 1 {
			t.Error("the hook was not called for a file that was restored and registered")
		}
	})
}

// containerNotRemovable makes the removal of a container fail for the rest of the
// test (a test that does so must not run in parallel with another).
func containerNotRemovable(t *testing.T) {
	t.Helper()
	prev := osRemove
	osRemove = func(name string) error {
		if strings.HasSuffix(name, ".lock") {
			return &os.PathError{Op: "remove", Path: name, Err: syscall.EACCES}
		}
		return prev(name)
	}
	t.Cleanup(func() { osRemove = prev })
}

// A hook that panics does not take the process down nor change the reply.
func TestRestore_aHookThatPanicsDoesNotChangeTheReply(t *testing.T) {
	q, dir := newE2EHandler(t, FormatTar)
	path, id := quarantined(t, q, "f.bin", "content")
	other := unregisteredHandler(t, dir, Config{WatchedPaths: []string{filepath.Dir(path)}})
	called := make(chan struct{})
	other.SetUnregisteredRestoreHook(func(context.Context, string, string, string) {
		close(called)
		panic("a hook that fails")
	})
	if err := other.Restore(t.Context(), id); err != nil {
		t.Fatalf("Restore() = %v", err)
	}
	select {
	case <-called:
	case <-time.After(testDeadline):
		t.Fatal("the hook was never called")
	}
	assertContent(t, path, "content")
}

// A retry after a restoration that left its container behind fails with a
// destination that exists, and changes nothing: the file is the one restored.
func TestRestore_aRetryAfterAContainerLeftBehindChangesNothing(t *testing.T) {
	q, dir := newE2EHandler(t, FormatTar)
	path, id := quarantined(t, q, "f.bin", "content")
	containerNotRemovable(t)
	if err := q.Restore(t.Context(), id); !errors.Is(err, ErrRestoredLockKept) {
		t.Fatalf("Restore() = %v, want ErrRestoredLockKept", err)
	}
	if err := q.Restore(t.Context(), id); !errors.Is(err, ErrDestinationExists) {
		t.Fatalf("the retry = %v, want ErrDestinationExists", err)
	}
	assertContent(t, path, "content")
	if _, err := os.Stat(filepath.Join(dir, id+".lock")); err != nil {
		t.Errorf("the container is gone: %v", err)
	}
}

// A container that vanished by itself is a container removed.
func TestRestore_aContainerThatVanishedCountsAsRemoved(t *testing.T) {
	q, _ := newE2EHandler(t, FormatTar)
	path, id := quarantined(t, q, "f.bin", "content")
	prev := osRemove
	osRemove = func(name string) error {
		if strings.HasSuffix(name, ".lock") {
			return &os.PathError{Op: "remove", Path: name, Err: fs.ErrNotExist}
		}
		return prev(name)
	}
	t.Cleanup(func() { osRemove = prev })
	if err := q.Restore(t.Context(), id); err != nil {
		t.Fatalf("Restore() = %v, want it restored", err)
	}
	assertContent(t, path, "content")
}

// A call that waits for the registry gives up with its own deadline, and what it
// wanted to write is not written.
func TestSQLiteRegistry_aCallThatWaitsGivesUpWithItsDeadline(t *testing.T) {
	reg, err := newSQLiteRegistry(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if e := reg.Close(); e != nil {
			t.Errorf("Close() = %v", e)
		}
	})
	unlock, err := reg.lock(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	released := false
	release := func() {
		if !released {
			released = true
			unlock()
		}
	}
	defer release()
	calls := map[string]func(ctx context.Context) error{
		"Get": func(ctx context.Context) error { _, e := reg.Get(ctx, "id"); return e },
		"Set": func(ctx context.Context) error {
			return reg.Set(ctx, &Entry{ID: "id", SHA256: "sha", RestoredAt: time.Now()})
		},
		"Clone": func(ctx context.Context) error { _, e := reg.Clone(ctx, "", false); return e },
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
			defer cancel()
			start := time.Now()
			result := make(chan error, 1)
			go func() { result <- call(ctx) }()
			var err error
			select {
			case err = <-result:
			case <-time.After(testDeadline):
				release() // frees the call that ignores its deadline
				t.Fatalf("%s() did not end with its deadline: it waits for the lock without its context", name)
			}
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("%s() = %v, want DeadlineExceeded", name, err)
			}
			if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
				t.Errorf("%s() took %v, want about its deadline", name, elapsed)
			}
		})
	}
	release()
	if _, err = reg.Get(t.Context(), "id"); !errors.Is(err, errEntryNotFound) {
		t.Errorf("Get() = %v, want no entry: nothing was written", err)
	}
}
