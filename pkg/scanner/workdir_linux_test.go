//go:build linux

package scanner

import (
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
)

const (
	dirGroupRead fs.FileMode = 0o750
)

func mkOrphan(t *testing.T, base, name string, wide, withLock bool) string {
	t.Helper()
	dir := filepath.Join(base, name)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if withLock {
		if err := os.WriteFile(filepath.Join(dir, workDirLock), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if wide {
		if err := os.Chmod(dir, dirGroupRead); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Logf("cleanup: %v", err)
		}
	})
	return dir
}

func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

func TestPurgeOrphans(t *testing.T) {
	base := t.TempDir()
	orphan := mkOrphan(t, base, "gmhost-orphan", false, true)
	userDir := mkOrphan(t, base, "gmhost-equipe", false, false)
	wideMode := mkOrphan(t, base, "gmhost-wide", true, true)
	notOurs := mkOrphan(t, base, "other-orphan", false, true)
	locked := mkOrphan(t, base, "gmhost-locked", false, true)

	target := mkOrphan(t, t.TempDir(), "gmhost-target", false, true)
	link := filepath.Join(base, "gmhost-x")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	notDir := filepath.Join(base, "gmhost-file")
	if err := os.WriteFile(notDir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	lock, err := os.Open(filepath.Clean(filepath.Join(locked, workDirLock)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := lock.Close(); err != nil {
			t.Logf("close lock: %v", err)
		}
	})
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	lockLink := mkOrphan(t, base, "gmhost-locklink", false, false)
	if err := os.Symlink(filepath.Join(target, workDirLock), filepath.Join(lockLink, workDirLock)); err != nil {
		t.Fatal(err)
	}

	w, err := newWorkDir(base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := w.close(); err != nil {
			t.Errorf("close() error = %v", err)
		}
	})

	if exists(orphan) {
		t.Error("a real orphan must be removed")
	}
	for name, p := range map[string]string{
		"user folder without .lock": userDir, "mode 0755": wideMode, "not gmhost-*": notOurs,
		"locked by a live process": locked, "symlink to an orphan": link, "target of the symlink": target,
		"regular file": notDir, ".lock that is a symlink": lockLink, "own directory": w.path,
	} {
		if !exists(p) {
			t.Errorf("%s was removed: %s", name, p)
		}
	}
}

func TestInMemoryFS(t *testing.T) {
	prev := statfsType
	t.Cleanup(func() { statfsType = prev })
	for typ, want := range map[uint32]bool{tmpfsMagic: true, ramfsMagic: true, 0xEF53: false} {
		statfsType = func(string) (uint32, error) { return typ, nil }
		if got := inMemoryFS("/x"); got != want {
			t.Errorf("inMemoryFS(type %#x) = %t, want %t", typ, got, want)
		}
	}
}

func TestNewWorkDir_warnsOnMemoryFS(t *testing.T) {
	prev := statfsType
	t.Cleanup(func() { statfsType = prev })
	statfsType = func(string) (uint32, error) { return tmpfsMagic, nil }
	buf := captureLogs(t)
	w, err := newWorkDir(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := w.close(); err != nil {
			t.Errorf("close() error = %v", err)
		}
	})
	if out := buf.String(); !strings.Contains(out, "memory filesystem") || !strings.Contains(out, `"level":"WARN"`) {
		t.Errorf("log = %q, want a Warn about the memory filesystem", out)
	}
}

func captureConsole(t *testing.T) *lockedBuffer {
	t.Helper()
	buf := &lockedBuffer{}
	prev := ConsoleLogger
	ConsoleLogger = slog.New(slog.NewTextHandler(buf, nil))
	t.Cleanup(func() { ConsoleLogger = prev })
	return buf
}

func writeSpools(t *testing.T, orphan string, names ...string) string {
	t.Helper()
	dir := filepath.Join(orphan, datamodel.SessionSpoolDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestPurgeOrphans_warnsOfTheSessionSpoolsLost(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, orphan string)
		want  string
	}{
		{name: "no session folder", setup: func(*testing.T, string) {}},
		{name: "empty session folder", setup: func(t *testing.T, o string) { writeSpools(t, o) }},
		{
			name:  "three spools and other files",
			setup: func(t *testing.T, o string) { writeSpools(t, o, "a.jsonl", "b.jsonl", "c.jsonl", "d.tmp", "e.json") },
			want:  "3 session report(s) of a previous run were lost",
		},
		{
			name: "only regular files at the top level count",
			setup: func(t *testing.T, o string) {
				dir := writeSpools(t, o, "a.jsonl")
				if err := os.Mkdir(filepath.Join(dir, "dir.jsonl"), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "nested.txt"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("/etc/passwd", filepath.Join(dir, "link.jsonl")); err != nil {
					t.Fatal(err)
				}
			},
			want: "1 session report(s) of a previous run were lost",
		},
		{
			name: "session folder that is a link is not followed",
			setup: func(t *testing.T, o string) {
				elsewhere := t.TempDir()
				writeSpools(t, elsewhere, "x.jsonl")
				if err := os.Symlink(filepath.Join(elsewhere, datamodel.SessionSpoolDir), filepath.Join(o, datamodel.SessionSpoolDir)); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			console := captureConsole(t)
			base := t.TempDir()
			orphan := mkOrphan(t, base, "gmhost-crashed", false, true)
			tt.setup(t, orphan)
			purgeOrphans(base, "")
			if exists(orphan) {
				t.Error("the orphan must be removed")
			}
			got := console.String()
			switch {
			case tt.want == "" && strings.Contains(got, "were lost"):
				t.Errorf("unexpected warning: %s", got)
			case tt.want != "" && !strings.Contains(got, tt.want):
				t.Errorf("console = %q, want it to contain %q", got, tt.want)
			}
		})
	}
}

func TestCountOrphanSpools_isCapped(t *testing.T) {
	orphan := t.TempDir()
	names := make([]string, maxOrphanSpools+300)
	for i := range names {
		names[i] = fmt.Sprintf("%d.jsonl", i)
	}
	writeSpools(t, orphan, names...)
	if got := countOrphanSpools(orphan); got != maxOrphanSpools {
		t.Errorf("count = %d, want the cap %d", got, maxOrphanSpools)
	}
}

func TestPurgeOrphans_aLiveRunSpoolsAreNotCounted(t *testing.T) {
	console := captureConsole(t)
	base := t.TempDir()
	live := mkOrphan(t, base, "gmhost-live", false, true)
	writeSpools(t, live, "a.jsonl")
	lock, err := os.Open(filepath.Clean(filepath.Join(live, workDirLock)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := lock.Close(); err != nil {
			t.Logf("close lock: %v", err)
		}
	})
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	purgeOrphans(base, "")
	if !exists(live) || strings.Contains(console.String(), "were lost") {
		t.Errorf("a work directory held by a live process must be left alone, console = %q", console.String())
	}
}

func TestPurgeOrphans_saysAtLeastWhenTheCountHitsTheCap(t *testing.T) {
	console := captureConsole(t)
	base := t.TempDir()
	orphan := mkOrphan(t, base, "gmhost-crashed", false, true)
	names := make([]string, maxOrphanSpools+10)
	for i := range names {
		names[i] = fmt.Sprintf("%d%s", i, datamodel.SessionSpoolExt)
	}
	writeSpools(t, orphan, names...)
	purgeOrphans(base, "")
	if want := fmt.Sprintf("at least %d session report(s)", maxOrphanSpools); !strings.Contains(console.String(), want) {
		t.Errorf("console = %q, want it to contain %q", console.String(), want)
	}
}
