package safepath

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symbolic links unavailable: %v", err)
	}
}

func TestOpen_readsARegularFile(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "a", "b", "f.txt"), "content")
	f, err := Open(root, "a/b/f.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if e := f.Close(); e != nil {
			t.Error(e)
		}
	}()
	got, err := io.ReadAll(f.OS())
	if err != nil || string(got) != "content" {
		t.Errorf("read %q, %v, want the content", got, err)
	}
}

func TestOpen_refusesBadPaths(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "f"), "x")
	for _, rel := range []string{"", ".", "..", "../x", "a/../../x", "/etc/passwd"} {
		if _, err := Open(root, rel); !errors.Is(err, ErrBadPath) {
			t.Errorf("Open(%q) error = %v, want ErrBadPath", rel, err)
		}
	}
}

func TestOpen_refusesEverySymbolicLinkBelowTheRoot(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	write(t, filepath.Join(outside, "secret"), "secret")
	write(t, filepath.Join(root, "real", "f"), "x")
	symlink(t, outside, filepath.Join(root, "dirlink"))
	symlink(t, filepath.Join(root, "real"), filepath.Join(root, "inner"))
	symlink(t, filepath.Join(outside, "secret"), filepath.Join(root, "filelink"))
	for _, rel := range []string{"dirlink/secret", "inner/f", "filelink", "real/../dirlink/secret"} {
		f, err := Open(root, rel)
		if err == nil {
			_ = f.Close()
			t.Errorf("Open(%q) followed a link", rel)
			continue
		}
		if !errors.Is(err, ErrSymlink) && !errors.Is(err, os.ErrNotExist) {
			t.Errorf("Open(%q) error = %v, want ErrSymlink", rel, err)
		}
	}
}

func TestOpen_theRootItselfMayBeALink(t *testing.T) {
	target := t.TempDir()
	write(t, filepath.Join(target, "f"), "x")
	link := filepath.Join(t.TempDir(), "root")
	symlink(t, target, link)
	f, err := Open(link, "f")
	if err != nil {
		t.Fatalf("Open() through a monitored link error = %v: the root is trusted", err)
	}
	if err := f.Close(); err != nil {
		t.Error(err)
	}
}

func TestRemove_deletesTheOpenedFile(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "d", "f")
	write(t, path, "x")
	f, err := Open(root, "d/f")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if e := f.Close(); e != nil {
			t.Error(e)
		}
	}()
	if err := f.Remove(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the file is still there (%v)", err)
	}
}

func TestRemove_refusesAFileReplacedByAnother(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "f")
	write(t, path, "original")
	f, err := Open(root, "f")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if e := f.Close(); e != nil {
			t.Error(e)
		}
	}()
	if err := os.Rename(path, path+".moved"); err != nil {
		t.Fatal(err)
	}
	write(t, path, "someone else's file")
	if err := f.Remove(); !errors.Is(err, ErrChanged) {
		t.Errorf("Remove() error = %v, want ErrChanged", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("the other file was deleted: %v", err)
	}
}

func TestRemove_refusesANameTurnedIntoALink(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "f")
	write(t, path, "original")
	other := filepath.Join(t.TempDir(), "other")
	write(t, other, "other")
	f, err := Open(root, "f")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if e := f.Close(); e != nil {
			t.Error(e)
		}
	}()
	if err := os.Rename(path, path+".moved"); err != nil {
		t.Fatal(err)
	}
	symlink(t, other, path)
	if err := f.Remove(); !errors.Is(err, ErrChanged) {
		t.Errorf("Remove() error = %v, want ErrChanged", err)
	}
	if _, err := os.Stat(other); err != nil {
		t.Errorf("the target of the link was deleted: %v", err)
	}
}

func TestRemove_actsOnTheDirectoryItWasOpenedIn(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("only the Linux implementation keeps the directory open")
	}
	root := t.TempDir()
	write(t, filepath.Join(root, "d", "f"), "original")
	victim := t.TempDir()
	write(t, filepath.Join(victim, "f"), "victim file with the same name")
	f, err := Open(root, "d/f")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if e := f.Close(); e != nil {
			t.Error(e)
		}
	}()
	// The folder is redirected after the open: d becomes a link to the victim.
	if err := os.Rename(filepath.Join(root, "d"), filepath.Join(root, "d.moved")); err != nil {
		t.Fatal(err)
	}
	symlink(t, victim, filepath.Join(root, "d"))
	if err := f.Remove(); err != nil {
		t.Fatalf("Remove() error = %v, want the original file deleted", err)
	}
	if _, err := os.Stat(filepath.Join(victim, "f")); err != nil {
		t.Errorf("the file behind the redirected folder was deleted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "d.moved", "f")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the original file is still there (%v)", err)
	}
}

func TestOpenDir_createsAndConfines(t *testing.T) {
	root := t.TempDir()
	dir, err := OpenDir(root, "a/b/c", true, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if e := dir.Close(); e != nil {
			t.Error(e)
		}
	}()
	if err := dir.WriteFile("f", []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "a", "b", "c", "f")); err != nil {
		t.Errorf("the file is not in the folder that was opened: %v", err)
	}
	if err := dir.WriteFile("../escape", nil, 0o600); err == nil {
		t.Error("the opened folder let a write escape")
	}
}

func TestOpenDir_doesNotCreateWhenNotAsked(t *testing.T) {
	root := t.TempDir()
	if _, err := OpenDir(root, "a/b", false, 0o700); err == nil {
		t.Error("OpenDir() created or opened a missing folder")
	}
	if _, err := os.Stat(filepath.Join(root, "a")); err == nil {
		t.Error("a folder was created although create was false")
	}
}

func TestOpenDir_refusesALinkAnywhereBelowTheRoot(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	symlink(t, outside, filepath.Join(root, "link"))
	write(t, filepath.Join(root, "real", "x"), "x")
	symlink(t, filepath.Join(root, "real"), filepath.Join(root, "alias"))
	for _, rel := range []string{"link", "link/sub", "alias", "real/../link"} {
		for _, create := range []bool{false, true} {
			if d, err := OpenDir(root, rel, create, 0o700); err == nil {
				_ = d.Close()
				t.Errorf("OpenDir(%q, create=%t) followed a link", rel, create)
			}
		}
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Errorf("something was created behind a link: %v", entries)
	}
}

func TestOpenDir_refusesAFolderSwappedForALinkAtTheWorstMoment(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	write(t, filepath.Join(root, "a", "b", "x"), "x")
	prev := beforeCreate
	t.Cleanup(func() { beforeCreate = prev })
	swapped := false
	beforeCreate = func(name string) {
		if name != "b" || swapped {
			return
		}
		swapped = true
		if err := os.Rename(filepath.Join(root, "a", "b"), filepath.Join(root, "a", "b.moved")); err != nil {
			t.Error(err)
			return
		}
		symlink(t, outside, filepath.Join(root, "a", "b"))
	}
	if d, err := OpenDir(root, "a/b", true, 0o700); err == nil {
		_ = d.Close()
		t.Error("OpenDir() followed the link that replaced the folder")
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Errorf("something was created behind the link: %v", entries)
	}
}

func TestOpenDir_rootDot(t *testing.T) {
	root := t.TempDir()
	d, err := OpenDir(root, ".", false, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Error(err)
	}
	if _, err := OpenDir(root, "../x", true, 0o700); !errors.Is(err, ErrBadPath) {
		t.Errorf("OpenDir(../x) error = %v, want ErrBadPath", err)
	}
}

func TestOpen_refusesANamedPipeWithoutBlocking(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no named pipes in the file system")
	}
	root := t.TempDir()
	pipe := filepath.Join(root, "pipe")
	if err := mkfifo(pipe); err != nil {
		t.Skipf("cannot create a named pipe: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		f, err := Open(root, "pipe")
		if err == nil {
			_ = f.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrNotRegular) {
			t.Errorf("Open(pipe) error = %v, want ErrNotRegular", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Open() blocked on a named pipe")
	}
}

func TestOpen_refusesADirectory(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "d"), 0o700); err != nil {
		t.Fatal(err)
	}
	if f, err := Open(root, "d"); !errors.Is(err, ErrNotRegular) {
		if err == nil {
			_ = f.Close()
		}
		t.Errorf("Open(dir) error = %v, want ErrNotRegular", err)
	}
}

func TestRemove_worksWhileTheFileIsHeldOpenAndCloseIsHarmlessAfterwards(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "f")
	write(t, path, "x")
	f, err := Open(root, "f")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Remove(); err != nil {
		t.Fatalf("Remove() of an open file error = %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the file is still there (%v)", err)
	}
	if err := f.Close(); err != nil {
		t.Errorf("Close() after Remove error = %v", err)
	}
}

func BenchmarkOpen(b *testing.B) {
	root := b.TempDir()
	path := filepath.Join(root, "a", "b", "c", "f.bin")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		b.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		b.Fatal(err)
	}
	b.Run("os.Open", func(b *testing.B) {
		for b.Loop() {
			f, err := os.Open(filepath.Clean(path))
			if err != nil {
				b.Fatal(err)
			}
			if err := f.Close(); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("safepath.Open", func(b *testing.B) {
		for b.Loop() {
			f, err := Open(root, "a/b/c/f.bin")
			if err != nil {
				b.Fatal(err)
			}
			if err := f.Close(); err != nil {
				b.Fatal(err)
			}
		}
	})
}
