//go:build linux

package main

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins/mock"
	"github.com/vimeo/go-magic/magic"
)

var pngHead = []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89")

func loadMagic(t testing.TB) {
	t.Helper()
	if err := magic.AddMagicDir(magic.GetDefaultDir()); err != nil {
		t.Fatal(err)
	}
}

func filterWith(forbidden, skipped string) *FTFilterPlugin {
	p := &FTFilterPlugin{
		ForbiddenTypes: map[string]struct{}{},
		SkippedTypes:   map[string]struct{}{},
		logger:         slog.New(slog.DiscardHandler),
		consoleLogger:  slog.New(slog.DiscardHandler),
	}
	if forbidden != "" {
		p.ForbiddenTypes[forbidden] = struct{}{}
	}
	if skipped != "" {
		p.SkippedTypes[skipped] = struct{}{}
	}
	return p
}

func withLogs(p *FTFilterPlugin) *bytes.Buffer {
	var logs bytes.Buffer
	p.logger = slog.New(slog.NewTextHandler(&logs, nil))
	return &logs
}

// fdPath is how the core gives a deposited file to plugins on Linux.
func fdPath(t testing.TB, path string) string {
	t.Helper()
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if e := f.Close(); e != nil {
			t.Errorf("Close() error = %v", e)
		}
	})
	return fmt.Sprintf("/proc/self/fd/%d", f.Fd())
}

func write(t testing.TB, name string, content []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// run calls OnScanFile and fails the test when it does not return.
func run(t *testing.T, p *FTFilterPlugin, location string) *datamodel.Result {
	t.Helper()
	done := make(chan *datamodel.Result, 1)
	go func() { done <- p.OnScanFile("f", location, "sha", false) }()
	select {
	case got := <-done:
		return got
	case <-time.After(10 * time.Second):
		t.Fatalf("OnScanFile(%s) did not return", location)
		return nil
	}
}

// typeByName types a path libmagic opens by its name; the caller keeps the descriptor.
func typeByName(path string) (string, error) { return libmagicType(path, func() {}) }

func stubTyping(t *testing.T, typing func(path string) (string, error)) {
	t.Helper()
	prev := typeFile
	typeFile = func(path string, release func()) (string, error) {
		defer release()
		return typing(path)
	}
	t.Cleanup(func() { typeFile = prev })
}

func TestOnScanFile_aFileIsTypedThroughItsNameOrItsDescriptor(t *testing.T) {
	loadMagic(t)
	png := write(t, "a.png", pngHead)
	empty := write(t, "empty", nil)
	big := write(t, "big.png", append(bytes.Clone(pngHead), make([]byte, 3<<20)...))
	tests := []struct {
		name         string
		plugin       *FTFilterPlugin
		path         string
		wantFiltered bool
		wantMalware  bool
		wantSize     int64
		wantType     string
	}{
		{"forbidden type", filterWith("image/png", ""), png, true, true, int64(len(pngHead)), "image/png"},
		{"forbidden type, a big file", filterWith("image/png", ""), big, true, true, int64(len(pngHead) + 3<<20), "image/png"},
		{"skipped type", filterWith("", "image/png"), png, true, false, int64(len(pngHead)), "image/png"},
		{"empty file, forbidden", filterWith("inode/x-empty", ""), empty, true, true, 0, "inode/x-empty"},
		{"type not listed", filterWith("application/x-executable", "text/plain"), png, false, false, 0, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, location := range []string{tt.path, fdPath(t, tt.path)} {
				got := run(t, tt.plugin, location)
				if !tt.wantFiltered {
					if got != nil {
						t.Errorf("OnScanFile(%s) = %+v, want nil", location, got)
					}
					continue
				}
				if got == nil {
					t.Fatalf("OnScanFile(%s) = nil, want the file filtered", location)
				}
				if got.Malware != tt.wantMalware || got.FileType != tt.wantType || got.FileSize != tt.wantSize || got.FilteredVolume != tt.wantSize {
					t.Errorf("OnScanFile(%s) = %+v", location, got)
				}
				if tt.wantMalware && got.MalwareReason != datamodel.FilteredFileType {
					t.Errorf("OnScanFile(%s) reason = %q", location, got.MalwareReason)
				}
			}
		})
	}
}

func TestOnScanFile_aFileThatCannotBeTypedIsRefusedWhenTypesAreForbidden(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(fifo, link); err != nil {
		t.Fatal(err)
	}
	linkToFile := filepath.Join(dir, "linkfile")
	if err := os.Symlink(write(t, "real", pngHead), linkToFile); err != nil {
		t.Fatal(err)
	}
	readable := write(t, "readable", []byte("text"))
	tests := []struct {
		name     string
		location string
		typing   func(string) (string, error)
	}{
		{"missing file", filepath.Join(dir, "absent"), nil},
		{"directory", dir, nil},
		{"FIFO", fifo, nil},
		{"link to a FIFO", link, nil},
		{"link to a file, not followed", linkToFile, nil},
		{"libmagic error", readable, func(string) (string, error) { return "", errors.New("cannot open: input/output error") }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.typing != nil {
				stubTyping(t, tt.typing)
			}
			p := filterWith("image/png", "text/plain")
			logs := withLogs(p)
			got := run(t, p, tt.location)
			if got == nil || got.Error == nil || got.Malware || got.MalwareReason != "" || got.SHA256 != "sha" {
				t.Errorf("with forbidden types: OnScanFile() = %+v, want an Error refusal and no detection", got)
			}
			if tt.typing != nil && (got == nil || got.Error == nil || !strings.Contains(got.Error.Error(), "input/output error")) {
				t.Errorf("the error of libmagic is lost: %+v", got)
			}
			if !bytes.Contains(logs.Bytes(), []byte("level=WARN")) {
				t.Errorf("logs = %q, want a warning", logs.String())
			}
			if got = run(t, filterWith("", "text/plain"), tt.location); got != nil {
				t.Errorf("without forbidden types: OnScanFile() = %+v, want nil", got)
			}
		})
	}
}

// The mode of the file is changed after the core opened it: libmagic reopens the
// descriptor by its name and is refused, which fails closed when types are
// forbidden.
func TestOnScanFile_aFileMadeUnreadableAfterTheCoreOpenedIt(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root reads whatever the mode")
	}
	loadMagic(t)
	path := write(t, "a.png", pngHead)
	location := fdPath(t, path)
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	for loc, wantText := range map[string]string{location: "no read permission", path: "permission denied"} {
		got := run(t, filterWith("image/png", ""), loc)
		if got == nil || got.Error == nil || got.Malware || !strings.Contains(got.Error.Error(), wantText) {
			t.Errorf("OnScanFile(%s) = %+v, want an Error refusal that carries %q", loc, got, wantText)
		}
		if got = run(t, filterWith("", "image/png"), loc); got != nil {
			t.Errorf("OnScanFile(%s) without forbidden types = %+v, want nil", loc, got)
		}
	}
}

// What libmagic does not recognize, and the generic type it answers, may be
// refused but never waive a file.
func TestOnScanFile_theGenericTypeRefusesButNeverWaives(t *testing.T) {
	path := write(t, "odd.bin", []byte("???"))
	for _, answer := range []string{"", octetStreamMime} {
		t.Run("libmagic says "+strconv.Quote(answer), func(t *testing.T) {
			stubTyping(t, func(string) (string, error) { return answer, nil })
			for _, location := range []string{path, fdPath(t, path)} {
				if got := run(t, filterWith("application/octet-stream", ""), location); got == nil || !got.Malware || got.MalwareReason != datamodel.FilteredFileType || got.FileType != octetStreamMime {
					t.Errorf("forbidden octet-stream: OnScanFile(%s) = %+v, want refused", location, got)
				}
				if got := run(t, filterWith("image/png", ""), location); got != nil {
					t.Errorf("octet-stream not listed: OnScanFile(%s) = %+v, want nil", location, got)
				}
				if got := run(t, filterWith("", "application/octet-stream"), location); got != nil {
					t.Errorf("skipped octet-stream: OnScanFile(%s) = %+v, want the file analyzed, not waived", location, got)
				}
			}
		})
	}
}

// Random data, typed by the real libmagic, is never waived by a skipped type.
func TestOnScanFile_aRandomBlobIsNeverWaived(t *testing.T) {
	blob := make([]byte, 64)
	for i := range blob {
		blob[i] = byte((i*131 + 7) % 256)
	}
	if got := run(t, filterWith("", "application/octet-stream"), write(t, "blob", blob)); got != nil {
		t.Errorf("OnScanFile() = %+v, want the blob analyzed, not waived", got)
	}
}

func TestValidate_refusesToWaiveTheGenericType(t *testing.T) {
	p := new(FTFilterPlugin)
	for _, tt := range []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{"empty", &Config{}, false},
		{"usual types", &Config{ForbiddenTypes: []string{"application/zip"}, SkippedTypes: []string{"text/plain"}}, false},
		{"generic type forbidden", &Config{ForbiddenTypes: []string{octetStreamMime}}, false},
		{"generic type skipped", &Config{SkippedTypes: []string{"text/plain", octetStreamMime}}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := p.Validate(tt.config, nil)
			if (err != nil) != tt.wantErr || (err != nil && !strings.Contains(err.Error(), "waive every file that is not recognized")) {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err = p.Init(tt.config, mock.NewMockHCContext()); (err != nil) != tt.wantErr {
				t.Errorf("Init() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// A libmagic that cannot be opened or does not type a known image makes the filter
// unreliable: the configuration is refused when types are forbidden, a warning is
// enough otherwise.
func TestInit_aLibmagicThatCannotBeUsed(t *testing.T) {
	prevProbe := probeType
	t.Cleanup(func() { probeType = prevProbe })
	for _, tt := range []struct {
		name  string
		probe func(string) (string, error)
		bad   bool
	}{
		{"working libmagic", prevProbe, false},
		{"database that gives the generic type", func(string) (string, error) { return octetStreamMime, nil }, true},
		{"database that gives another type", func(string) (string, error) { return "image/jpeg", nil }, true},
		{"typing that fails", func(string) (string, error) { return "", errors.New("libmagic could not be opened") }, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			probeType = tt.probe
			for _, forbidden := range []bool{false, true} {
				var logs bytes.Buffer
				ctx := mock.NewMockHCContext()
				ctx.WorkDir = t.TempDir()
				ctx.Logger = slog.New(slog.NewTextHandler(&logs, nil))
				config := &Config{}
				if forbidden {
					config.ForbiddenTypes = []string{"application/zip"}
				}
				err := new(FTFilterPlugin).Init(config, ctx)
				switch {
				case tt.bad && forbidden:
					if err == nil || !strings.Contains(err.Error(), "libmagic database") {
						t.Errorf("forbidden types: Init() error = %v, want a refusal", err)
					}
				case err != nil:
					t.Errorf("Init() error = %v", err)
				}
				if warned := bytes.Contains(logs.Bytes(), []byte("libmagic database")); warned != (tt.bad && !forbidden) {
					t.Errorf("forbidden = %v: warned = %v: %s", forbidden, warned, logs.String())
				}
			}
		})
	}
}

// The probe types a known image with the handle that types the files, from a file
// it removes.
func TestProbeType_usesTheHandleOfTheFilesAndLeavesNothing(t *testing.T) {
	dir := t.TempDir()
	got, err := probeType(dir)
	if err != nil || got != "image/png" {
		t.Errorf("probeType() = %q, %v, want image/png", got, err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("%d file(s) left by the probe", len(entries))
	}
	if _, err = probeType(filepath.Join(dir, "absent")); err == nil {
		t.Error("probeType() in a missing directory: error = nil")
	}
}

func TestCheckDatabase_aDatabaseThatCannotBeLoaded(t *testing.T) {
	p := filterWith("", "")
	logs := withLogs(p)
	if err := p.checkDatabase(errors.New("no such directory"), true, t.TempDir()); err == nil || !strings.Contains(err.Error(), "no such directory") {
		t.Errorf("forbidden types: error = %v, want a refusal", err)
	}
	if err := p.checkDatabase(errors.New("no such directory"), false, t.TempDir()); err != nil || !bytes.Contains(logs.Bytes(), []byte("level=WARN")) {
		t.Errorf("no forbidden type: error = %v, logs = %q, want a warning only", err, logs.String())
	}
}

func openFDs(t testing.TB) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

// Nothing is left open by a typing: the number of descriptors does not move.
func TestOnScanFile_leavesNoDescriptorOpen(t *testing.T) {
	loadMagic(t)
	path := write(t, "a.png", pngHead)
	p := filterWith("image/png", "")
	for _, location := range []string{path, fdPath(t, path)} {
		if got := p.OnScanFile("f", location, "sha", false); got == nil || !got.Malware {
			t.Fatalf("OnScanFile(%s) = %+v, want the image refused", location, got)
		}
		before := openFDs(t)
		for range 5000 {
			p.OnScanFile("f", location, "sha", false)
		}
		if after := openFDs(t); after != before {
			t.Errorf("%s: %d descriptors open after 5000 calls, %d before", location, after, before)
		}
	}
}

func TestIsMIMEType(t *testing.T) {
	for in, want := range map[string]bool{
		"image/png":                        true,
		"inode/x-empty":                    true,
		"application/vnd.ms-excel":         true,
		"application/x-pie-executable":     true,
		"text/x-c++":                       true,
		"":                                 false,
		"Image/png":                        true,
		"text/x-Algol68":                   true,
		"application/grib;edition=1":       true,
		"audio/AMR":                        true,
		"video/MP2T":                       true,
		"text/PGP":                         true,
		"a/b;x=1;y=2":                      true,
		"a/b; x=1":                         false,
		"a/b;":                             false,
		"a/b;x":                            false,
		"a/b;x=1,2":                        false,
		"application/SIMH-tape-data":       true,
		"application/CDFV2":                true,
		"regular file, no read permission": false,
		"writable, executable, regular file, no read permission": false,
		"application/octet-stream; x=1":                          false,
		"image/":                                                 false,
		"/png":                                                   false,
		"a/b/c":                                                  false,

		"text/a,b":                       false,
		"-a/b":                           false,
		"cannot open `x' (No such file)": false,
		"a/" + strings.Repeat("b", 125):  true,
		"a/" + strings.Repeat("b", 126):  false,
	} {
		if got := isMIMEType(in); got != want {
			t.Errorf("isMIMEType(%.40q) = %v, want %v", in, got, want)
		}
	}
}

// What libmagic says in the place of a type (under fd exhaustion, without an
// error) is an error, never a type.
func TestOnScanFile_whatIsNotATypeIsAnError(t *testing.T) {
	path := write(t, "f", []byte("text"))
	for _, junk := range []string{"writable, executable, regular file, no read permission", "regular file, no read permission", "text/plain, with comma"} {
		t.Run(junk, func(t *testing.T) {
			stubTyping(t, func(string) (string, error) { return junk, nil })
			got := run(t, filterWith("image/png", "text/plain"), path)
			if got == nil || got.Error == nil || got.Malware || !strings.Contains(got.Error.Error(), "libmagic gave no MIME type") {
				t.Errorf("with forbidden types: OnScanFile() = %+v, want an Error refusal", got)
			}
			if got = run(t, filterWith("", "text/plain"), path); got != nil {
				t.Errorf("without forbidden types: OnScanFile() = %+v, want nil (never waived on junk)", got)
			}
		})
	}
}

// A file larger than what libmagic reads (bytes_max) is typed from a part of it: it
// is never waived, and a forbidden type still refuses it.
func TestOnScanFile_aFileBeyondBytesMaxIsNeverWaived(t *testing.T) {
	loadMagic(t)
	text := bytes.Repeat([]byte("a line of plain text\n"), 1<<20)
	var archive bytes.Buffer
	zw := zip.NewWriter(&archive)
	w, err := zw.Create("hidden.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write([]byte("hidden")); err != nil {
		t.Fatal(err)
	}
	if err = zw.Close(); err != nil {
		t.Fatal(err)
	}
	within := write(t, "within.bin", append(bytes.Clone(text[:5<<20]), archive.Bytes()...))
	beyond := write(t, "beyond.bin", append(bytes.Clone(text[:20<<20]), archive.Bytes()...))
	for _, location := range []string{within, fdPath(t, within)} {
		// Within what libmagic reads, it finds the zip at the end of the text.
		if got := run(t, filterWith("", "text/plain"), location); got != nil {
			t.Errorf("a text+zip within bytes_max, text skipped: OnScanFile() = %+v, want it analyzed: libmagic types it as a zip", got)
		}
		if got := run(t, filterWith("application/zip", ""), location); got == nil || !got.Malware || got.FileType != "application/zip" {
			t.Errorf("a text+zip within bytes_max, zip forbidden: OnScanFile() = %+v, want it refused as a zip", got)
		}
	}
	for _, location := range []string{beyond, fdPath(t, beyond)} {
		if got := run(t, filterWith("", "text/plain"), location); got != nil {
			t.Errorf("a file beyond bytes_max, text skipped: OnScanFile() = %+v, want it analyzed", got)
		}
		if got := run(t, filterWith("text/plain", ""), location); got == nil || !got.Malware || got.FileType != "text/plain" {
			t.Errorf("a file beyond bytes_max, text forbidden: OnScanFile() = %+v, want it refused", got)
		}
	}
}

func TestOnScanFile_theLimitOfBytesMaxIsInclusive(t *testing.T) {
	stubTyping(t, func(string) (string, error) { return "text/plain", nil })
	prev := bytesMax
	bytesMax = 100
	t.Cleanup(func() { bytesMax = prev })
	for size, waived := range map[int]bool{99: true, 100: true, 101: false} {
		got := run(t, filterWith("", "text/plain"), write(t, "f", bytes.Repeat([]byte("a"), size)))
		if (got != nil) != waived {
			t.Errorf("size %d: OnScanFile() = %+v, waived = %v, want %v", size, got, got != nil, waived)
		}
	}
}

// waitForSlots waits until no typing is running: the calls that were stuck have
// ended, so nothing reads what a test restores.
func waitForSlots(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		cookies.mu.Lock()
		busy := len(cookies.slots) > 0
		cookies.mu.Unlock()
		if !busy {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Error("typings are still running")
}

// One call that is stuck takes a cookie and nothing else: the other typings go on.
func TestPool_oneStuckCallDoesNotStopTheOthers(t *testing.T) {
	loadMagic(t)
	prevSize, prevFile, prevTimeout := poolSize, cookieFile, typeTimeout
	poolSize, typeTimeout = 4, 200*time.Millisecond
	closeCookies()
	release := make(chan struct{})
	var first sync.Once
	cookieFile = func(k *cookie, path string) (string, error) {
		stuck := false
		first.Do(func() { stuck = true })
		if stuck {
			<-release
		}
		return prevFile(k, path)
	}
	t.Cleanup(func() {
		close(release)
		waitForSlots(t)
		poolSize, cookieFile, typeTimeout = prevSize, prevFile, prevTimeout
		closeCookies()
	})
	png := write(t, "a.png", pngHead)
	results := make(chan error, 4)
	for range 4 {
		go func() {
			mime, err := typeByName(png)
			if err == nil && mime != "image/png" {
				err = fmt.Errorf("typed %q", mime)
			}
			results <- err
		}()
	}
	var ok, timedOut int
	deadline := time.After(5 * time.Second)
	for ok+timedOut < 4 {
		select {
		case err := <-results:
			switch {
			case err == nil:
				ok++
			case strings.Contains(err.Error(), "took more than"):
				timedOut++
			default:
				t.Errorf("unexpected error: %v", err)
			}
		case <-deadline:
			t.Fatalf("%d typing(s) completed, %d timed out of 4", ok, timedOut)
		}
	}
	if ok != 3 || timedOut != 1 {
		t.Errorf("%d completed and %d timed out, want 3 and 1", ok, timedOut)
	}
}

// When every slot is held by a call that is stuck, the next call waits no longer than
// typeTimeout and fails.
func TestPool_aCallWhenEverySlotIsStuckFailsClosed(t *testing.T) {
	loadMagic(t)
	prevSize, prevFile, prevTimeout := poolSize, cookieFile, typeTimeout
	poolSize, typeTimeout = 2, 100*time.Millisecond
	closeCookies()
	release := make(chan struct{})
	cookieFile = func(k *cookie, path string) (string, error) {
		<-release
		return prevFile(k, path)
	}
	t.Cleanup(func() {
		close(release)
		waitForSlots(t)
		poolSize, cookieFile, typeTimeout = prevSize, prevFile, prevTimeout
		closeCookies()
	})
	png := write(t, "a.png", pngHead)
	// Each call is guarded: a call that waits for ever fails the test in seconds.
	typeGuarded := func() error {
		return guarded(t, func() error {
			_, err := typeByName(png)
			return err
		})
	}
	for range 2 {
		if err := typeGuarded(); err == nil || !strings.Contains(err.Error(), "took more than") {
			t.Fatalf("a stuck call: error = %v", err)
		}
	}
	start := time.Now()
	err := typeGuarded()
	if err == nil || !strings.Contains(err.Error(), "no libmagic handle was free") || time.Since(start) > 3*time.Second {
		t.Errorf("libmagicType() = %v after %v, want a refusal after about %v", err, time.Since(start), typeTimeout)
	}
}

func TestIsOwnDescriptor(t *testing.T) {
	pid := strconv.Itoa(os.Getpid())
	for location, want := range map[string]bool{
		"/proc/self/fd/7":          true,
		"/proc/" + pid + "/fd/12":  true,
		"/proc/1/fd/7":             false,
		"/proc/self/fd/07":         false,
		"/proc/self/fd/7x":         false,
		"/proc/self/fd/-1":         false,
		"/proc/self/fd/":           false,
		"/proc/self/fd/4294967296": false,
		"/proc/self/fd/7/../x":     false,
		"/tmp/proc/self/fd/7":      false,
		"/proc/self/cwd":           false,
		"/tmp/file":                false,
	} {
		if got := isOwnDescriptor(location); got != want {
			t.Errorf("isOwnDescriptor(%q) = %v, want %v", location, got, want)
		}
	}
}

func TestWithin_aTypingThatTakesTooLongIsAnError(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	start := time.Now()
	_, err := within(50*time.Millisecond, func() (string, error) {
		<-release
		return "text/plain", nil
	})
	if err == nil || !strings.Contains(err.Error(), "took more than") || time.Since(start) > 5*time.Second {
		t.Errorf("within() = %v after %v, want a timeout error", err, time.Since(start))
	}
	if mime, err := within(time.Second, func() (string, error) { return "text/plain", nil }); err != nil || mime != "text/plain" {
		t.Errorf("within() = %q, %v", mime, err)
	}
}

// A typing that takes too long refuses the file when types are forbidden, and its
// cookie is not reused while it runs.
func TestOnScanFile_aTypingThatTakesTooLongFailsClosed(t *testing.T) {
	prev := typeTimeout
	typeTimeout = 300 * time.Millisecond
	t.Cleanup(func() { typeTimeout = prev })
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	stubTyping(t, func(path string) (string, error) {
		return within(typeTimeout, func() (string, error) {
			<-release
			return "text/plain", nil
		})
	})
	path := write(t, "f", []byte("text"))
	got := run(t, filterWith("image/png", ""), path)
	if got == nil || got.Error == nil || !strings.Contains(got.Error.Error(), "took more than") {
		t.Errorf("OnScanFile() = %+v, want an Error refusal", got)
	}
}

func TestCookies_bytesMaxIsSet(t *testing.T) {
	loadMagic(t)
	prev := bytesMax
	t.Cleanup(func() { bytesMax = prev })
	for _, n := range []uint64{prev, 1 << 20, 3 << 20} {
		bytesMax = n
		k, err := newCookie(nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := k.bytesMaxSet(); got != n {
			t.Errorf("bytes_max = %d, want %d", got, n)
		}
		k.close()
	}
}

func TestCookies_areReusedAndFreed(t *testing.T) {
	loadMagic(t)
	k, generation, err := acquireCookie(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	releaseCookie(k, generation)
	again, generation2, err := acquireCookie(time.Second)
	if err != nil || again != k {
		t.Errorf("the cookie in the free list was not reused: %v", err)
	}
	closeCookies()
	releaseCookie(again, generation2)
	if n := openCookies.Load(); n != 0 {
		t.Errorf("%d libmagic handle(s) still open after the close", n)
	}
	cookies.mu.Lock()
	left := len(cookies.free)
	cookies.mu.Unlock()
	if left != 0 {
		t.Errorf("%d cookie(s) kept after the close", left)
	}
	if mime, err := typeByName(write(t, "a.png", pngHead)); err != nil || mime != "image/png" {
		t.Errorf("typing after the close = %q, %v", mime, err)
	}
}

// A typing that goes over typeTimeout is an error, and its cookie is not handed to
// another typing until it ends.
func TestLibmagicType_aTypingThatTakesTooLong(t *testing.T) {
	loadMagic(t)
	closeCookies()
	prev, prevFile := typeTimeout, cookieFile
	typeTimeout = 300 * time.Millisecond
	release := make(chan struct{})
	started := make(chan *cookie, 1)
	cookieFile = func(k *cookie, path string) (string, error) {
		started <- k
		<-release
		return prevFile(k, path)
	}
	t.Cleanup(func() { typeTimeout, cookieFile = prev, prevFile })
	typed := make(chan error, 1)
	go func() {
		_, err := typeByName(write(t, "a.png", pngHead))
		typed <- err
	}()
	select {
	case err := <-typed:
		if err == nil || !strings.Contains(err.Error(), "took more than") {
			t.Fatalf("typeByName() error = %v, want a timeout", err)
		}
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("typeByName() did not give up on a typing that takes too long")
	}
	var k *cookie
	select {
	case k = <-started:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("the typing never started")
	}
	cookies.mu.Lock()
	inFree := slices.Contains(cookies.free, k)
	cookies.mu.Unlock()
	if inFree {
		t.Error("the cookie of a typing that is still running was handed back")
	}
	close(release)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		cookies.mu.Lock()
		inFree = slices.Contains(cookies.free, k)
		cookies.mu.Unlock()
		if inFree {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Error("the cookie never came back after the typing ended")
}

func TestTypeOf_aDescriptorOfAFIFOIsNeverTyped(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Clean(fifo), os.O_RDWR|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if e := f.Close(); e != nil {
			t.Error(e)
		}
	})
	done := make(chan error, 1)
	go func() {
		_, err := typeOf(fmt.Sprintf("/proc/self/fd/%d", f.Fd()))
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, errNotRegular) {
			t.Errorf("typeOf() error = %v, want errNotRegular", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("typeOf() did not return on a FIFO")
	}
}

// Typing is safe to run from many goroutines: each uses its own cookie.
func TestOnScanFile_concurrentTypings(t *testing.T) {
	loadMagic(t)
	png := write(t, "a.png", pngHead)
	text := write(t, "a.txt", []byte("hello world, this is text\n"))
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for i := range 32 {
		wg.Go(func() {
			path, want := png, "image/png"
			if i%2 == 1 {
				path, want = text, "text/plain"
			}
			for range 100 {
				got, err := typeOf(path)
				if err != nil || got.mime != want {
					errs <- fmt.Errorf("typeOf(%s) = %q, want %q: %w", path, got.mime, want, err)
					return
				}
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func walkCorpus(t testing.TB, roots []string, limit int) (files []string) {
	t.Helper()
	for _, root := range roots {
		if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				if d != nil && d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if len(files) >= limit {
				return fs.SkipAll
			}
			if info, e := os.Stat(path); e == nil && info.Mode().IsRegular() && info.Size() > 0 {
				if target, e := filepath.EvalSymlinks(path); e == nil {
					files = append(files, target)
				}
			}
			return nil
		}); err != nil && !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("walking %s: %v", root, err)
		}
	}
	return files
}

// corpusFiles lists the files of a flat directory of files (see
// testdata/CORPUS.md), by their path. The directory is read through an os.Root: a
// corpus is made of hard links to the samples, never of links that leave it.
func corpusFiles(t testing.TB, dir string) (files []string) {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if e := root.Close(); e != nil {
			t.Error(e)
		}
	}()
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if info, statErr := root.Stat(e.Name()); statErr == nil && info.Mode().IsRegular() && info.Size() > 0 {
			files = append(files, filepath.Join(dir, e.Name()))
		}
	}
	return files
}

func referenceType(path string) string {
	if mime := magic.MimeFromFile(path); mime != "" {
		return mime
	}
	return octetStreamMime
}

// Typing the file through a descriptor gives the type libmagic gives it by its name,
// exactly, whatever its size.
func TestTypeOf_agreesWithLibmagicOnTheFilesOfTheHost(t *testing.T) {
	loadMagic(t)
	const wanted = 1000
	files := walkCorpus(t, []string{"/usr/bin", "/usr/sbin", "/usr/lib", "/usr/share", "/etc"}, wanted+200)
	if len(files) < wanted {
		t.Skipf("only %d files on this host, the corpus needs %d", len(files), wanted)
	}
	var compared int
	for _, path := range files {
		got, err := typeOf(path)
		if err != nil {
			continue
		}
		compared++
		if want := referenceType(path); got.mime != want {
			t.Errorf("typeOf(%s) = %q, MimeFromFile = %q (size %d)", path, got.mime, want, got.size)
		}
	}
	t.Logf("%d files compared", compared)
	if compared < wanted {
		t.Errorf("only %d files compared, want %d", compared, wanted)
	}
}

// The large files libmagic types by reading beyond their head (MSI and other OLE
// containers, APK, JAR, PIE executables, zip): typed through their descriptor and
// through their name, exactly as libmagic types them. HC_FILETYPE_CORPUS names a
// directory of such files (see testdata/CORPUS.md); the test is skipped without it.
func TestTypeOf_agreesWithLibmagicOnTheLargeCorpus(t *testing.T) {
	dir := os.Getenv("HC_FILETYPE_CORPUS")
	if dir == "" {
		t.Skip("HC_FILETYPE_CORPUS is not set")
	}
	loadMagic(t)
	files := corpusFiles(t, dir)
	if len(files) == 0 {
		t.Fatalf("no file in %s", dir)
	}
	kinds := map[string]int{}
	for _, path := range files {
		want := referenceType(path)
		for _, location := range []string{path, fdPath(t, path)} {
			got, err := typeOf(location)
			if err != nil {
				t.Errorf("typeOf(%s): %v", path, err)
				continue
			}
			if got.mime != want {
				t.Errorf("typeOf(%s) = %q, MimeFromFile = %q (size %d)", location, got.mime, want, got.size)
			}
		}
		kinds[want]++
	}
	t.Logf("%d files, by type: %v", len(files), kinds)
}

// worstCaseContents are the contents that cost libmagic most to type: as many bytes
// as it reads (bytes_max) that it has to examine one by one.
func worstCaseContents() map[string][]byte {
	const size = 7 << 20
	spaces := bytes.Repeat([]byte(" "), size)
	lines := bytes.Repeat([]byte("short line\n"), size/11+1)[:size]
	random := make([]byte, size)
	var state uint64 = 88172645463325252
	for i := range random {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		random[i] = byte(state & 0xff)
	}
	return map[string][]byte{"spaces_7MiB": spaces, "lines_7MiB": lines, "random_7MiB": random}
}

// BenchmarkTypeOf_pool types a worst-case file from as many goroutines as the pool
// has cookies: ns/op is the time per file with every worker busy.
func BenchmarkTypeOf_pool(b *testing.B) {
	if os.Getenv("HC_FILETYPE_BENCH") == "" {
		b.Skip("HC_FILETYPE_BENCH is not set")
	}
	loadMagic(b)
	path := write(b, "lines", worstCaseContents()["lines_7MiB"])
	b.SetParallelism(poolSize)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := typeOf(path); err != nil {
				b.Error(err)
				return
			}
		}
	})
}

func BenchmarkTypeOf_large(b *testing.B) {
	if os.Getenv("HC_FILETYPE_BENCH") == "" {
		b.Skip("HC_FILETYPE_BENCH is not set")
	}
	loadMagic(b)
	dir := b.TempDir()
	pad := func(name string, source string, size int64) string {
		out := filepath.Join(dir, name)
		dst, err := os.Create(filepath.Clean(out))
		if err != nil {
			b.Fatal(err)
		}
		if source != "" {
			src, openErr := os.Open(filepath.Clean(source))
			if openErr != nil {
				b.Fatal(openErr)
			}
			if _, err = io.Copy(dst, src); err != nil {
				b.Fatal(err)
			}
			if err = src.Close(); err != nil {
				b.Fatal(err)
			}
		}
		if err = dst.Truncate(size); err != nil {
			b.Fatal(err)
		}
		if err = dst.Close(); err != nil {
			b.Fatal(err)
		}
		return out
	}
	zipPath := filepath.Join(dir, "big.zip")
	zf, err := os.Create(filepath.Clean(zipPath))
	if err != nil {
		b.Fatal(err)
	}
	zw := zip.NewWriter(zf)
	w, err := zw.CreateHeader(&zip.FileHeader{Name: "pad.bin", Method: zip.Store})
	if err != nil {
		b.Fatal(err)
	}
	chunk := make([]byte, 1<<20)
	for range 1024 {
		if _, err = w.Write(chunk); err != nil {
			b.Fatal(err)
		}
	}
	if err = zw.Close(); err != nil {
		b.Fatal(err)
	}
	if err = zf.Close(); err != nil {
		b.Fatal(err)
	}
	cases := map[string]string{"zip_1GiB": zipPath}
	for name, content := range worstCaseContents() {
		cases[name] = write(b, name, content)
	}
	if pie := "/usr/bin/ls"; referenceType(pie) == "application/x-pie-executable" {
		cases["pie_100MiB"] = pad("pie", pie, 100<<20)
	}
	if corpus := os.Getenv("HC_FILETYPE_CORPUS"); corpus != "" {
		var biggest string
		var size int64
		for _, f := range corpusFiles(b, corpus) {
			if strings.HasSuffix(f, ".msi") {
				if info, e := os.Stat(f); e == nil && info.Size() > size {
					biggest, size = f, info.Size()
				}
			}
		}
		if biggest != "" {
			cases["msi_200MiB"] = pad("msi", biggest, 200<<20)
		}
	}
	for name, path := range cases {
		want := referenceType(path)
		b.Run(name, func(b *testing.B) {
			for range b.N {
				got, err := typeOf(fdPath(b, path))
				if err != nil || got.mime != want {
					b.Fatalf("typeOf() = %q, %v, want %q", got.mime, err, want)
				}
			}
		})
	}
}

// libmagic types some files with capitals and parameters: the lists match on the
// essence of the type, whatever its case.
func TestOnScanFile_aTypeIsMatchedOnItsEssenceWhateverItsCase(t *testing.T) {
	loadMagic(t)
	grib1 := write(t, "g1", []byte("GRIB\x00\x00\x0c\x01abcd"))
	grib2 := write(t, "g2", []byte("GRIB\x00\x00\x0c\x02abcd"))
	spaces := write(t, "spaces", bytes.Repeat([]byte(" "), 7<<20))
	for _, tt := range []struct {
		name      string
		forbidden []string
		skipped   []string
		path      string
		want      string
	}{
		{"spaces typed with capitals, forbidden in lower case", []string{"application/simh-tape-data"}, nil, spaces, "refused"},
		{"spaces, the case of the list does not matter", []string{"Application/SIMH-Tape-Data"}, nil, spaces, "refused"},
		{"a GRIB file of edition 1 is matched without the parameter", []string{"application/grib"}, nil, grib1, "refused"},
		{"a GRIB file of edition 2 too", []string{"application/grib"}, nil, grib2, "refused"},
		{"a GRIB file skipped", nil, []string{"application/grib"}, grib1, "waived"},
		{"another type is not matched", []string{"application/zip"}, nil, grib1, "analyzed"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := new(FTFilterPlugin)
			ctx := mock.NewMockHCContext()
			ctx.WorkDir = t.TempDir()
			ctx.Logger, ctx.ConsoleLogger = slog.New(slog.DiscardHandler), slog.New(slog.DiscardHandler)
			if err := p.Init(&Config{ForbiddenTypes: tt.forbidden, SkippedTypes: tt.skipped}, ctx); err != nil {
				t.Fatal(err)
			}
			got := run(t, p, tt.path)
			switch tt.want {
			case "refused":
				if got == nil || !got.Malware || got.MalwareReason != datamodel.FilteredFileType {
					t.Errorf("OnScanFile() = %+v, want it refused", got)
				}
			case "waived":
				if got == nil || got.Malware || got.Error != nil {
					t.Errorf("OnScanFile() = %+v, want it waived", got)
				}
			default:
				if got != nil {
					t.Errorf("OnScanFile() = %+v, want it analyzed", got)
				}
			}
		})
	}
}

func TestValidate_aTypeWithAParameterIsRefused(t *testing.T) {
	p := new(FTFilterPlugin)
	for _, config := range []*Config{
		{ForbiddenTypes: []string{"application/grib;edition=1"}},
		{SkippedTypes: []string{"text/plain", "application/grib;edition=1"}},
	} {
		if err := p.Validate(config, nil); err == nil || !strings.Contains(err.Error(), "list the type without parameters") {
			t.Errorf("Validate(%+v) error = %v, want a refusal", config, err)
		}
	}
	if err := p.Validate(&Config{SkippedTypes: []string{"Application/Octet-Stream"}}, nil); err == nil {
		t.Error("Validate() accepted the generic type in capitals in skipped_types")
	}
}

// libmagic answers NULL with MAGIC_ERROR when it cannot type a file (here a
// descriptor that does not exist): an error, and the file is refused.
func TestOnScanFile_aTypingThatLibmagicAnswersWithAnErrorRefusesTheFile(t *testing.T) {
	loadMagic(t)
	if mime, err := typeByName("/proc/self/fd/987654"); err == nil {
		t.Fatalf("typeByName() = %q, nil, want an error", mime)
	}
	stubTyping(t, func(string) (string, error) { return typeByName("/proc/self/fd/987654") })
	path := write(t, "f", []byte("text"))
	if got := run(t, filterWith("image/png", ""), path); got == nil || got.Error == nil || got.Malware {
		t.Errorf("OnScanFile() = %+v, want an Error refusal", got)
	}
	if got := run(t, filterWith("", "text/plain"), path); got != nil {
		t.Errorf("without forbidden types: OnScanFile() = %+v, want nil", got)
	}
}

// A typing that starts after its caller gave up still types the file it was made
// for, not whatever took the number of a descriptor that was closed since: it types
// a duplicate that it owns.
func TestTypeOf_aLateTypingStillSeesTheMember(t *testing.T) {
	loadMagic(t)
	closeCookies()
	prevFile, prevTimeout := cookieFile, typeTimeout
	typeTimeout = 300 * time.Millisecond
	release := make(chan struct{})
	answered := make(chan string, 1)
	cookieFile = func(k *cookie, path string) (string, error) {
		<-release
		mime, err := prevFile(k, path)
		answered <- mime
		return mime, err
	}
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
		waitForSlots(t)
		cookieFile, typeTimeout = prevFile, prevTimeout
		closeCookies()
	})
	member := write(t, "member.png", pngHead)
	if _, err := typeOf(member); err == nil || !strings.Contains(err.Error(), "took more than") {
		t.Fatalf("typeOf() error = %v, want a timeout", err)
	}
	// The member descriptor is closed: the number goes to the next files opened.
	others := make([]*os.File, 0, 8)
	for range 8 {
		f, err := os.Open(write(t, "other.txt", []byte("plain text, not an image\n")))
		if err != nil {
			t.Fatal(err)
		}
		others = append(others, f)
	}
	t.Cleanup(func() {
		for _, f := range others {
			if err := f.Close(); err != nil {
				t.Error(err)
			}
		}
	})
	before := openFDs(t)
	close(release)
	select {
	case mime := <-answered:
		if mime != "image/png" {
			t.Errorf("the late typing typed %q, want the member (image/png)", mime)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the late typing never ended")
	}
	waitForSlots(t)
	if after := openFDs(t); after >= before {
		t.Errorf("%d descriptors open after the late typing, %d before: its duplicate was not closed", after, before)
	}
}

// Reading the list of databases and opening a cookie take time, and the bound holds
// for them too: typing returns within it, and does not wait for them.
func TestLibmagicType_aSlowDatabaseListStaysWithinTheBound(t *testing.T) {
	loadMagic(t)
	closeCookies()
	prevLoad, prevTimeout := loadDatabases, typeTimeout
	release := make(chan struct{})
	loadDatabases = func() ([]string, error) {
		<-release
		return prevLoad()
	}
	typeTimeout = 300 * time.Millisecond
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
		waitForSlots(t)
		loadDatabases, typeTimeout = prevLoad, prevTimeout
		closeCookies()
	})
	path := write(t, "a.png", pngHead)
	start := time.Now()
	_, err := typeByName(path)
	if elapsed := time.Since(start); err == nil || !strings.Contains(err.Error(), "took more than") || elapsed > 2*time.Second {
		t.Errorf("typeByName() = %v after %v, want a timeout within the bound (%v)", err, elapsed, typeTimeout)
	}
	// The lock of the cookies is free while the list is read, so that no other call
	// waits on it.
	if !cookies.mu.TryLock() {
		t.Error("cookies.mu is held while the database list is read")
		return
	}
	cookies.mu.Unlock()
}

// The wait for a slot counts in the bound of the call, and a call with almost no
// time left starts no C call.
func TestLibmagicType_theWaitCountsInTheBound(t *testing.T) {
	loadMagic(t)
	closeCookies()
	prevSize, prevFile, prevTimeout := poolSize, cookieFile, typeTimeout
	poolSize, typeTimeout = 1, 300*time.Millisecond
	var (
		calls   atomic.Int32
		hold    atomic.Int64 // how long the first call holds the slot
		current atomic.Pointer[chan struct{}]
	)
	cookieFile = func(k *cookie, path string) (string, error) {
		if calls.Add(1) == 1 {
			time.Sleep(time.Duration(hold.Load()))
		} else {
			<-*current.Load()
		}
		return prevFile(k, path)
	}
	t.Cleanup(func() {
		poolSize, cookieFile, typeTimeout = prevSize, prevFile, prevTimeout
		closeCookies()
	})
	path := write(t, "a.png", pngHead)
	run := func(first time.Duration) (elapsed time.Duration, err error) {
		release := make(chan struct{})
		current.Store(&release)
		calls.Store(0)
		hold.Store(int64(first))
		firstDone := make(chan struct{})
		go func() {
			defer close(firstDone)
			_, _ = typeByName(path)
		}()
		for calls.Load() == 0 {
			time.Sleep(time.Millisecond)
		}
		start := time.Now()
		_, err = typeByName(path)
		elapsed = time.Since(start)
		<-firstDone
		close(release) // the call that gave up ends, and gives its slot back
		waitForSlots(t)
		return elapsed, err
	}
	// The first call keeps the slot 200 ms: the second waits for it, has about 100 ms
	// left, starts its call, and gives up at the bound, not 300 ms after the wait.
	elapsed, err := run(200 * time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "took more than") || elapsed > 450*time.Millisecond {
		t.Errorf("a call that waited: %v after %v, want a timeout at about %v", err, elapsed, typeTimeout)
	}
	if calls.Load() != 2 {
		t.Errorf("%d C calls, want 2", calls.Load())
	}
	// The first call keeps the slot 270 ms: 30 ms are left, below the floor, so the
	// second starts no call.
	elapsed, err = run(270 * time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "took more than") || elapsed > 450*time.Millisecond {
		t.Errorf("a call with no time left: %v after %v, want a timeout", err, elapsed)
	}
	if calls.Load() != 1 {
		t.Errorf("%d C calls, want 1: a call with no time left must not start", calls.Load())
	}
}

func TestValidate_aListEntryIsATypeThatCanMatch(t *testing.T) {
	p := new(FTFilterPlugin)
	for _, entry := range []string{"", " ", "text/plain ", " text/plain", "text plain", "text/", "/plain", "text", "a/b/c", "text/pl ain", "text/plain,text/html", "a/" + strings.Repeat("b", 126), "ünï/code"} {
		for _, config := range []*Config{{ForbiddenTypes: []string{entry}}, {SkippedTypes: []string{entry}}} {
			err := p.Validate(config, nil)
			if err == nil {
				t.Errorf("Validate(%q) accepted a list entry that can never match", entry)
				continue
			}
			if !strings.Contains(err.Error(), strconv.Quote(entry)) {
				t.Errorf("Validate(%q) error = %v, want the entry quoted", entry, err)
			}
		}
	}
	for _, entry := range []string{"text/plain", "Text/Plain", "application/x-pie-executable", "text/x-c++", "audio/AMR", "a/" + strings.Repeat("b", 125)} {
		if err := p.Validate(&Config{ForbiddenTypes: []string{entry}, SkippedTypes: []string{"image/png"}}, nil); err != nil {
			t.Errorf("Validate(%q) = %v, want it accepted", entry, err)
		}
	}
}

// The list of the databases is read again after a failure, not kept for ever: one
// failure at start must not break every typing until the restart.
func TestCachedDatabases_aFailureIsNotKept(t *testing.T) {
	loadMagic(t)
	closeCookies()
	prev := listDatabases
	var calls atomic.Int32
	listDatabases = func() ([]string, error) {
		if calls.Add(1) == 1 {
			return nil, errors.New("read /usr/share/misc: input/output error")
		}
		return prev()
	}
	t.Cleanup(func() {
		listDatabases = prev
		closeCookies()
	})
	path := write(t, "a.png", pngHead)
	if _, err := typeByName(path); err == nil || !strings.Contains(err.Error(), "input/output error") {
		t.Fatalf("the first typing = %v, want the failure of the list", err)
	}
	if mime, err := typeByName(path); err != nil || mime != "image/png" {
		t.Errorf("the second typing = %q, %v, want image/png: the failure was kept", mime, err)
	}
	if mime, err := typeByName(path); err != nil || mime != "image/png" || calls.Load() != 2 {
		t.Errorf("the third typing = %q, %v after %d reads of the list, want it kept once it worked", mime, err, calls.Load())
	}
	closeCookies()
	if _, err := typeByName(path); err != nil || calls.Load() != 3 {
		t.Errorf("after the close: %v, %d reads, want the list read again", err, calls.Load())
	}
}

func TestOnScanFile_aSkippedTypeIsMarkedSkippedType(t *testing.T) {
	loadMagic(t)
	location := write(t, "a.txt", []byte("a line of plain text\n"))
	got := run(t, filterWith("", "text/plain"), location)
	if got == nil || got.Malware || got.NotAnalyzedReason != datamodel.NotAnalyzedSkippedType {
		t.Errorf("OnScanFile() = %+v, want a waiver with reason %q", got, datamodel.NotAnalyzedSkippedType)
	}
}
