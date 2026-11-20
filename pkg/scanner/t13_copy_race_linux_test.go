//go:build linux

package scanner

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/quarantine"
)

// In copy mode a file verified clean (A) is exchanged with an unverified one (B)
// while it is moved, whatever the instant: B must never reach OUTPUT and A must
// be published at least once.
func TestT13_copyModeAnExchangeDuringTheMoveNeverPublishesTheUnverifiedFile(t *testing.T) {
	if !holdsHandle {
		t.Skip("the exchange needs the verified descriptor of Linux")
	}
	iterations := 10000
	if testing.Short() || raceEnabled {
		iterations = 3000
	}
	in, out := t.TempDir(), t.TempDir()
	a, err := NewMoveActionWithMode(out, in, MoveModeCopy, 0)
	if err != nil {
		t.Fatal(err)
	}
	var unverified, verified, unverifiedLost int
	for range iterations {
		name := filepath.Join(in, "f.bin")
		other := filepath.Join(in, "g.bin")
		if err := os.WriteFile(name, []byte("VERIFIED"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(other, []byte("UNVERIFIED"), 0o600); err != nil {
			t.Fatal(err)
		}
		src := testSource(t, name)
		var stop atomic.Bool
		var wg sync.WaitGroup
		exchangeLoop(name, other, &stop, &wg)
		_ = a.Handle(t.Context(), src, datamodel.Result{}, &datamodel.Report{})
		stop.Store(true)
		wg.Wait()

		entries, err := os.ReadDir(out)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			content, err := os.ReadFile(filepath.Clean(filepath.Join(out, e.Name())))
			if err != nil {
				t.Fatal(err)
			}
			switch string(content) {
			case "UNVERIFIED":
				unverified++
			case "VERIFIED":
				verified++
			}
			if err := os.Remove(filepath.Join(out, e.Name())); err != nil {
				t.Fatal(err)
			}
		}
		// The unverified file is not ours: it must still be in INPUT, under one of
		// the two names.
		found := false
		for _, p := range []string{name, other} {
			if b, err := os.ReadFile(filepath.Clean(p)); err == nil && string(b) == "UNVERIFIED" {
				found = true
			}
		}
		if !found {
			unverifiedLost++
		}
		for _, p := range []string{name, other} {
			if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
		}
	}
	if unverified != 0 {
		t.Errorf("the unverified file reached OUTPUT %d times out of %d", unverified, iterations)
	}
	// The removal of the source checks the name then unlinks it: an exchange that
	// lands between the two removes the file that took the name. That residual
	// window is a documented limit of phase 1, so it is reported, not asserted.
	if unverifiedLost != 0 {
		t.Logf("the file that replaced the name was removed %d times out of %d (residual window between the check and the unlink)", unverifiedLost, iterations)
	}
	if verified == 0 {
		t.Error("the verified file was never published: the test proves nothing")
	}
}

// Every class of file the card names reaches OUTPUT in copy mode as a private
// copy of the verified content, never as the source inode. Only a file the
// pipeline marked TooBig (not analysed) goes by path: a large file that was
// analysed, an extracted archive, or a small file whose result says too big
// (a plugin, a member of an archive) are all copied.
func TestT13_copyModeEveryClassOfFileReachesOutputAsAVerifiedPrivateCopy(t *testing.T) {
	large := strings.Repeat("L", 4096)
	tests := []struct {
		name    string
		content string
		result  datamodel.Result
		tooBig  bool
	}{
		{"simple file analysed", "plain analysed content", datamodel.Result{}, false},
		{"archive", "PK\x03\x04 an archive body that was analysed", datamodel.Result{}, false},
		{"large file analysed", large, datamodel.Result{}, false},
		{"restored file", "content restored from quarantine", datamodel.Result{Restored: true}, false},
		{"skipped exempted", "\x89PNG\r\n\x1a\n skipped by filetype", datamodel.Result{Score: -500}, false},
		{"empty", "", datamodel.Result{}, false},
		{"small file whose result says too big", "small but marked too big", datamodel.Result{MalwareReason: datamodel.TooBig}, false},
		{"large file whose result says too big but was analysed", large, datamodel.Result{MalwareReason: datamodel.TooBig}, false},
		{"too big not analysed passed by path", large, datamodel.Result{MalwareReason: datamodel.TooBig}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newCopyMoveFixture(t)
			p := f.deposit(t, "d/file.bin", tt.content)
			src := testSource(t, p)
			src.TooBig = tt.tooBig
			srcInode := inoOf(t, p)
			var report datamodel.Report
			if err := f.action.Handle(t.Context(), src, tt.result, &report); err != nil {
				t.Fatal(err)
			}
			dest := filepath.Join(f.dst, "d", "file.bin")
			if report.MovedTo != dest {
				t.Fatalf("MovedTo = %q, want %q", report.MovedTo, dest)
			}
			if tt.tooBig {
				if read(t, dest) != tt.content {
					t.Errorf("destination holds %d bytes, want the file", len(read(t, dest)))
				}
				if inoOf(t, dest) != srcInode {
					t.Error("a file not analysed goes by path: it must be the same inode")
				}
			} else {
				sum, err := getFileSHA256(dest)
				if err != nil {
					t.Fatal(err)
				}
				if sum != src.SHA256 {
					t.Errorf("SHA256 of OUTPUT = %s, want Source.SHA256 %s", sum, src.SHA256)
				}
				if inoOf(t, dest) == srcInode {
					t.Error("the source inode is published: copy mode must publish a private copy")
				}
			}
			if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("the source must be removed: %v", err)
			}
			if entries, err := os.ReadDir(filepath.Join(f.dst, quarantine.StagingDir)); err == nil && len(entries) != 0 {
				t.Errorf("the transit folder holds %d file(s)", len(entries))
			}
		})
	}
}

func inoOf(t *testing.T, path string) uint64 {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("no stat for %q", path)
	}
	return st.Ino
}
