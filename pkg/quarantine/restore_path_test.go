package quarantine

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/glimps-re/host-connector/internal/pathutil"
)

// newRestoreFixture quarantines in/alice/sub/sample.txt and removes it, with in
// as the only watched path.
func newRestoreFixture(t *testing.T, watchIn bool) (q *QuarantineHandler, quarantineDir, in, samplePath, id string) {
	t.Helper()
	in = t.TempDir()
	conf := Config{Location: t.TempDir(), LockPassword: "pw"}
	if watchIn {
		conf.WatchedPaths = []string{in}
	}
	quarantineDir = conf.Location
	var err error
	q, err = NewQuarantineHandler(t.Context(), conf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if e := q.Close(); e != nil {
			t.Errorf("Close() error = %v", e)
		}
	})
	dir := filepath.Join(in, "alice", "sub")
	if err = os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	samplePath = filepath.Join(dir, "sample.txt")
	content := []byte("malicious content")
	if err = os.WriteFile(samplePath, content, 0o600); err != nil {
		t.Fatal(err)
	}
	_, id, err = q.Quarantine(t.Context(), samplePath, sha256Hex(content), []string{"m"})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.RemoveAll(filepath.Join(in, "alice")); err != nil {
		t.Fatal(err)
	}
	return
}

func assertNothingWritten(t *testing.T, dirs ...string) {
	t.Helper()
	for _, d := range dirs {
		entries, err := os.ReadDir(d)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 0 {
			t.Errorf("%s was written to: %v", d, entries)
		}
	}
}

func assertLockKept(t *testing.T, quarantineDir, id string) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(quarantineDir, id+".lock")); err != nil {
		t.Errorf(".lock must be kept after a refused restore: %v", err)
	}
}

func TestRestore_createsMissingTreeUnderTheWatchedRoot(t *testing.T) {
	q, _, _, sample, id := newRestoreFixture(t, true)
	if err := q.Restore(t.Context(), id); err != nil {
		t.Fatalf("Restore() error = %v", err)
	}
	got, err := os.ReadFile(filepath.Clean(sample))
	if err != nil || string(got) != "malicious content" {
		t.Errorf("restored file = %q, %v", got, err)
	}
}

func TestRestore_parentReplacedByLinkIsRefused(t *testing.T) {
	outside := t.TempDir()
	otherUser := ""
	tests := []struct {
		name   string
		target func(in string) string
	}{
		{"link to a folder outside the tree", func(string) string { return outside }},
		{"link to another user's folder under the root", func(in string) string {
			otherUser = filepath.Join(in, "bob")
			if err := os.Mkdir(otherUser, 0o750); err != nil {
				t.Fatal(err)
			}
			return otherUser
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q, quarantineDir, in, _, id := newRestoreFixture(t, true)
			if err := os.Symlink(tt.target(in), filepath.Join(in, "alice")); err != nil {
				t.Fatal(err)
			}
			err := q.Restore(t.Context(), id)
			if !errors.Is(err, ErrRestoreDestinationUnsafe) {
				t.Fatalf("Restore() error = %v, want ErrRestoreDestinationUnsafe", err)
			}
			assertNothingWritten(t, outside)
			if otherUser != "" {
				assertNothingWritten(t, otherUser)
			}
			assertLockKept(t, quarantineDir, id)
		})
	}
}

func TestRestore_deepParentReplacedByLinkIsRefused(t *testing.T) {
	q, quarantineDir, in, _, id := newRestoreFixture(t, true)
	outside := t.TempDir()
	if err := os.Mkdir(filepath.Join(in, "alice"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(in, "alice", "sub")); err != nil {
		t.Fatal(err)
	}
	if err := q.Restore(t.Context(), id); !errors.Is(err, ErrRestoreDestinationUnsafe) {
		t.Fatalf("Restore() error = %v, want ErrRestoreDestinationUnsafe", err)
	}
	assertNothingWritten(t, outside)
	assertLockKept(t, quarantineDir, id)
}

func TestRestore_parentSwappedBetweenCheckAndCreation(t *testing.T) {
	for _, target := range []string{"outside", "sibling"} {
		t.Run(target, func(t *testing.T) {
			q, quarantineDir, in, _, id := newRestoreFixture(t, true)
			dest := t.TempDir()
			if target == "sibling" {
				dest = filepath.Join(in, "bob")
				if err := os.Mkdir(dest, 0o750); err != nil {
					t.Fatal(err)
				}
			}
			prev := beforeRestoreMkdir
			t.Cleanup(func() { beforeRestoreMkdir = prev })
			beforeRestoreMkdir = func() {
				if err := os.Symlink(dest, filepath.Join(in, "alice")); err != nil {
					t.Error(err)
				}
			}
			err := q.Restore(t.Context(), id)
			if !errors.Is(err, ErrRestoreDestinationUnsafe) {
				t.Fatalf("Restore() error = %v, want ErrRestoreDestinationUnsafe", err)
			}
			assertNothingWritten(t, dest)
			assertLockKept(t, quarantineDir, id)
		})
	}
}

func TestRestore_finalDirectoryReplacedByLinkIsRefusedWithoutWatchedRoot(t *testing.T) {
	q, quarantineDir, in, _, id := newRestoreFixture(t, false)
	outside := t.TempDir()
	if err := os.MkdirAll(filepath.Join(in, "alice"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(in, "alice", "sub")); err != nil {
		t.Fatal(err)
	}
	if err := q.Restore(t.Context(), id); !errors.Is(err, ErrRestoreDestinationUnsafe) {
		t.Fatalf("Restore() error = %v, want ErrRestoreDestinationUnsafe", err)
	}
	assertNothingWritten(t, outside)
	assertLockKept(t, quarantineDir, id)
}

func TestRestore_outsideWatchedPaths(t *testing.T) {
	var logs bytes.Buffer
	prev := logger
	logger = slog.New(slog.NewJSONHandler(&logs, nil))
	t.Cleanup(func() { logger = prev })

	t.Run("existing plain directory: restored, with a warning", func(t *testing.T) {
		q, _, in, sample, id := newRestoreFixture(t, false)
		if err := os.MkdirAll(filepath.Dir(sample), 0o750); err != nil {
			t.Fatal(err)
		}
		q.mu.Lock()
		q.watched = []string{t.TempDir()}
		q.mu.Unlock()
		if err := q.Restore(t.Context(), id); err != nil {
			t.Fatalf("Restore() error = %v", err)
		}
		if _, err := os.Stat(sample); err != nil {
			t.Errorf("file not restored in %s: %v", in, err)
		}
		if !strings.Contains(logs.String(), "outside the watched paths") {
			t.Errorf("log = %q, want a warning about the unwatched destination", logs.String())
		}
	})
	t.Run("missing directory: refused, nothing created", func(t *testing.T) {
		q, quarantineDir, in, _, id := newRestoreFixture(t, false)
		err := q.Restore(t.Context(), id)
		if !errors.Is(err, ErrRestoreDestinationUnsafe) || !strings.Contains(err.Error(), "not created") {
			t.Fatalf("Restore() error = %v, want a refusal explaining nothing is created", err)
		}
		assertNothingWritten(t, in)
		assertLockKept(t, quarantineDir, id)
	})
	t.Run("link above the directory: refused", func(t *testing.T) {
		q, quarantineDir, in, _, id := newRestoreFixture(t, false)
		target := t.TempDir()
		if err := os.MkdirAll(filepath.Join(target, "alice", "sub"), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.RemoveAll(in); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, in); err != nil {
			t.Fatal(err)
		}
		if err := q.Restore(t.Context(), id); !errors.Is(err, ErrRestoreDestinationUnsafe) {
			t.Fatalf("Restore() error = %v, want ErrRestoreDestinationUnsafe: the link belongs to a user", err)
		}
		assertNothingWritten(t, filepath.Join(target, "alice", "sub"))
		assertLockKept(t, quarantineDir, id)
	})
}

func TestRestore_outsideWatchedTrustedLinks(t *testing.T) {
	prev := trustedLink
	t.Cleanup(func() { trustedLink = prev })

	t.Run("a trusted link is followed and the walk goes on", func(t *testing.T) {
		q, _, in, sample, id := newRestoreFixture(t, false)
		target := t.TempDir()
		if err := os.MkdirAll(filepath.Join(target, "alice", "sub"), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.RemoveAll(in); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, in); err != nil {
			t.Fatal(err)
		}
		trustedLink = func(link, _ fs.FileInfo) bool { return link.Name() == filepath.Base(in) }
		if err := q.Restore(t.Context(), id); err != nil {
			t.Fatalf("Restore() error = %v, want success through the trusted link", err)
		}
		if _, err := os.Stat(filepath.Join(target, "alice", "sub", filepath.Base(sample))); err != nil {
			t.Errorf("file not restored through the link: %v", err)
		}
	})
	t.Run("the target holds a user link: refused", func(t *testing.T) {
		q, quarantineDir, in, _, id := newRestoreFixture(t, false)
		target := t.TempDir()
		outside := t.TempDir()
		if err := os.Mkdir(filepath.Join(target, "alice"), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(target, "alice", "sub")); err != nil {
			t.Fatal(err)
		}
		if err := os.RemoveAll(in); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, in); err != nil {
			t.Fatal(err)
		}
		trustedLink = func(link, _ fs.FileInfo) bool { return link.Name() == filepath.Base(in) }
		if err := q.Restore(t.Context(), id); !errors.Is(err, ErrRestoreDestinationUnsafe) {
			t.Fatalf("Restore() error = %v, want a refusal: a user link follows the trusted one", err)
		}
		assertNothingWritten(t, outside)
		assertLockKept(t, quarantineDir, id)
	})
	t.Run("more than 8 links: refused", func(t *testing.T) {
		q, quarantineDir, in, _, id := newRestoreFixture(t, false)
		realDir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(realDir, "alice", "sub"), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.RemoveAll(in); err != nil {
			t.Fatal(err)
		}
		holder := t.TempDir()
		target := realDir
		for i := range pathutil.MaxLinks + 1 {
			link := filepath.Join(holder, fmt.Sprintf("l%d", i))
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			target = link
		}
		if err := os.Symlink(target, in); err != nil {
			t.Fatal(err)
		}
		trustedLink = func(fs.FileInfo, fs.FileInfo) bool { return true }
		if err := q.Restore(t.Context(), id); !errors.Is(err, ErrRestoreDestinationUnsafe) {
			t.Fatalf("Restore() error = %v, want a refusal past %d links", err, pathutil.MaxLinks)
		}
		assertLockKept(t, quarantineDir, id)
	})
}

func TestRestore_linkAboveTheWatchedRootIsAccepted(t *testing.T) {
	realBase := t.TempDir()
	linkBase := filepath.Join(t.TempDir(), "var-run")
	if err := os.Symlink(realBase, linkBase); err != nil {
		t.Fatal(err)
	}
	in := filepath.Join(linkBase, "in")
	if err := os.Mkdir(in, 0o750); err != nil {
		t.Fatal(err)
	}
	q, err := NewQuarantineHandler(t.Context(), Config{Location: t.TempDir(), LockPassword: "pw", WatchedPaths: []string{in}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if e := q.Close(); e != nil {
			t.Errorf("Close() error = %v", e)
		}
	})
	sample := filepath.Join(in, "alice", "sample.txt")
	if err = os.MkdirAll(filepath.Dir(sample), 0o750); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(sample, []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, id, err := q.Quarantine(t.Context(), sample, sha256Hex([]byte("content")), []string{"m"})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.RemoveAll(filepath.Dir(sample)); err != nil {
		t.Fatal(err)
	}
	if err = q.Restore(t.Context(), id); err != nil {
		t.Fatalf("Restore() error = %v: a link above the watched root must be accepted", err)
	}
}

func TestReconfigure_updatesWatchedPaths(t *testing.T) {
	q, _, in, _, id := newRestoreFixture(t, false)
	if err := q.Reconfigure(t.Context(), Config{Location: q.location, LockPassword: "pw", WatchedPaths: []string{in}}); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(in, "alice")); err != nil {
		t.Fatal(err)
	}
	if err := q.Restore(t.Context(), id); !errors.Is(err, ErrRestoreDestinationUnsafe) {
		t.Fatalf("Restore() error = %v, want the new watched paths to apply", err)
	}
	assertNothingWritten(t, outside)
}

func TestRestore_nestedRootsUseTheOutermost(t *testing.T) {
	in := t.TempDir()
	conf := Config{Location: t.TempDir(), LockPassword: "pw", WatchedPaths: []string{filepath.Join(in, "alice"), in}}
	q, err := NewQuarantineHandler(t.Context(), conf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if e := q.Close(); e != nil {
			t.Errorf("Close() error = %v", e)
		}
	})
	sample := filepath.Join(in, "alice", "sub", "sample.txt")
	if err = os.MkdirAll(filepath.Dir(sample), 0o750); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(sample, []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, id, err := q.Quarantine(t.Context(), sample, sha256Hex([]byte("content")), []string{"m"})
	if err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err = os.RemoveAll(filepath.Join(in, "alice")); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(outside, filepath.Join(in, "alice")); err != nil {
		t.Fatal(err)
	}
	if err = q.Restore(t.Context(), id); !errors.Is(err, ErrRestoreDestinationUnsafe) {
		t.Fatalf("Restore() error = %v, want a refusal: the inner root was swapped for a link", err)
	}
	assertNothingWritten(t, outside)
	if got := watchedRoot(conf.WatchedPaths, sample); got != in {
		t.Errorf("watchedRoot() = %q, want the outermost root %q", got, in)
	}
}
