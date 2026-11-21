package quarantine

import (
	"bytes"
	"context"
	"errors"
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

// flakyRegistry is a registry whose writes can be made to fail, and that records
// them.
type flakyRegistry struct {
	quarantineRegistry
	mu     sync.Mutex
	failAt map[int]error // the n-th call of Set (from 1) fails with this error
	sets   []Entry
	// deletes are the ids of the entries removed.
	deletes []string
}

func (r *flakyRegistry) Delete(ctx context.Context, id string) error {
	r.mu.Lock()
	r.deletes = append(r.deletes, id)
	r.mu.Unlock()
	return r.quarantineRegistry.Delete(ctx, id)
}

func (r *flakyRegistry) Set(ctx context.Context, e *Entry) error {
	r.mu.Lock()
	r.sets = append(r.sets, *e)
	n := len(r.sets)
	err := r.failAt[n]
	r.mu.Unlock()
	if err != nil {
		return err
	}
	return r.quarantineRegistry.Set(ctx, e)
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
	case <-time.After(10 * time.Second):
		t.Error("the hook was not called")
	}
	if !strings.Contains(logs.String(), "has no registry entry") {
		t.Errorf("no warning: %s", logs)
	}
	if restored, err := other.IsRestored(t.Context(), path, sha256Hex([]byte("unregistered content"))); err != nil || !restored {
		t.Errorf("IsRestored() = %v, %v: the content must now count as restored", restored, err)
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

func removeContainer(dir, id string) error {
	return os.Remove(filepath.Join(dir, id+".lock"))
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
	if len(reg.sets) != 0 || len(reg.deletes) != 0 {
		t.Errorf("registry writes = %+v, deletes %v, want none: nothing is registered before the file is published", reg.sets, reg.deletes)
	}
	if _, err := other.registry.Get(t.Context(), id); !errors.Is(err, errEntryNotFound) {
		t.Errorf("Get() = %v, want no entry: content must not stay allow-listed", err)
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
	case <-time.After(10 * time.Second):
		t.Fatal("Restore() waited for the hook")
	}
	select {
	case <-started:
	case <-time.After(10 * time.Second):
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
	case <-time.After(10 * time.Second):
		t.Error("the hook was never called")
	}
}
