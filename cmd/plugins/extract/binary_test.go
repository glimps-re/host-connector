package main

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/glimps-re/host-connector/pkg/plugins"
	"github.com/glimps-re/host-connector/pkg/plugins/mock"
)

func realConfig() *Config {
	return &Config{DefaultPasswords: []string{"infected"}}
}

func TestInit_deploysTheEmbeddedBinaryInThePrivateWorkDir(t *testing.T) {
	hcc := newMockContext(t)
	var p SevenZipExtractPlugin
	if err := p.Init(realConfig(), hcc); err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	if len(hcc.Executables) != 1 || filepath.Dir(filepath.Dir(hcc.Executables[0])) != filepath.Join(hcc.WorkDir, binDirName) {
		t.Fatalf("declared %v, want the binary deployed under %s", hcc.Executables, filepath.Join(hcc.WorkDir, binDirName))
	}
	fi, err := os.Stat(hcc.Executables[0])
	if err != nil || fi.Mode().Perm() != deployedMode {
		t.Errorf("deployed binary: %v, %v, want mode %o", fi, err, deployedMode)
	}
	if err := p.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(hcc.Executables[0]); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Close left the binary behind (%v)", err)
	}
}

func TestDeployEmbedded_refusesARelativeWorkDir(t *testing.T) {
	if _, err := deployEmbedded("relative/dir"); err == nil {
		t.Error("deployEmbedded() accepted a relative work directory")
	}
}

func TestInit_neverTakesA7zzsFromPATH(t *testing.T) {
	dir := t.TempDir()
	witness := filepath.Join(dir, "witness")
	fake := filepath.Join(dir, "7zzs")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\necho ran >> "+witness+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fake, modeScript); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	hcc := newMockContext(t)
	var p SevenZipExtractPlugin
	if err := p.Init(realConfig(), hcc); err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	t.Cleanup(func() {
		if err := p.Close(t.Context()); err != nil {
			t.Error(err)
		}
	})
	if p.sze.sevenZipPath == fake {
		t.Error("a 7zzs found in PATH was taken")
	}
	if _, err := os.Stat(witness); err == nil {
		t.Error("the 7zzs of PATH was run")
	}
}

func TestInit_failureLeavesNothingBehind(t *testing.T) {
	tests := map[string]func(hcc *mock.MockHCContext){
		"declaration refused": func(hcc *mock.MockHCContext) { hcc.DeclareExecutableErr = errors.New("unsafe") },
	}
	for name, setup := range tests {
		t.Run(name, func(t *testing.T) {
			hcc := newMockContext(t)
			setup(hcc)
			var p SevenZipExtractPlugin
			if err := p.Init(realConfig(), hcc); err == nil {
				t.Fatal("Init() error = nil")
			}
			if entries, err := os.ReadDir(filepath.Join(hcc.WorkDir, binDirName)); err == nil && len(entries) != 0 {
				t.Errorf("a failed Init left %d deployed binaries", len(entries))
			}
		})
	}
	t.Run("proof refused", func(t *testing.T) {
		prev := proveBinary
		t.Cleanup(func() { proveBinary = prev })
		proveBinary = func(*sevenZipExtract, string) error { return errors.New("unsupported") }
		hcc := newMockContext(t)
		var p SevenZipExtractPlugin
		if err := p.Init(realConfig(), hcc); err == nil {
			t.Fatal("Init() error = nil")
		}
		if entries, err := os.ReadDir(filepath.Join(hcc.WorkDir, binDirName)); err == nil && len(entries) != 0 {
			t.Errorf("a failed Init left %d deployed binaries", len(entries))
		}
	})
}

func TestValidate_realBinaryLeavesTheRunningPluginAlone(t *testing.T) {
	hcc := newMockContext(t)
	var p SevenZipExtractPlugin
	if err := p.Init(realConfig(), hcc); err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	t.Cleanup(func() {
		if err := p.Close(t.Context()); err != nil {
			t.Error(err)
		}
	})
	running := p.sze.sevenZipPath

	// A Configure validates while extractions are running.
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for range 4 {
		wg.Go(func() {
			if _, err := p.ExtractFile(fixture(t, "wildcard.7z"), t.TempDir(), openLimits); err != nil {
				errs <- err
			}
		})
	}
	for range 3 {
		wg.Go(func() {
			var q SevenZipExtractPlugin
			if err := q.Validate(realConfig(), newMockContextShared(hcc.WorkDir)); err != nil {
				errs <- err
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent extraction or validation failed: %v", err)
	}
	if _, err := os.Stat(running); err != nil {
		t.Errorf("Validate removed the binary of the running plugin: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(hcc.WorkDir, binDirName))
	if err != nil || len(entries) != 1 {
		t.Errorf("%d deployed binaries (%v), want only the running one", len(entries), err)
	}
}

func newMockContextShared(workDir string) *mock.MockHCContext {
	hcc := mock.NewMockHCContext()
	hcc.WorkDir = workDir
	return hcc
}

func TestProve_realBinaryAnswersTheKnownAnswer(t *testing.T) {
	p := realPlugin(t)
	if err := prove(p.sze, t.TempDir()); err != nil {
		t.Errorf("prove() on the embedded 7-Zip error = %v", err)
	}
}

// refListing is the listing of the reference archive as a supported 7z prints it.
const refListing = `
7-Zip (z) 25.01 (x64)

Listing archive: %ARCHIVE%

--
Path = reference.7z
Type = 7z
WARNINGS:
There are data after the end of archive
Physical Size = 182
Tail Size = 28
Headers Size = 174

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2026-11-20 10:07:18 ....A            1            1  a.txt
2026-11-20 10:07:18 ....A            6            6  evil_.exe
2026-11-20 10:07:18 ....A            1            1  evil_.exe
------------------- ----- ------------ ------------  ------------------------
2026-11-20 10:07:18                  8            8  3 files

Warnings: 1
`

// refTechnical is the technical listing (-slt) of the reference archive as a
// supported 7z prints it.
const refTechnical = `
7-Zip (z) 25.01 (x64)

Listing archive: %ARCHIVE%

--
Path = reference.7z
Type = 7z
WARNINGS:
There are data after the end of archive
Physical Size = 182
Tail Size = 28
Headers Size = 174

----------
Path = a.txt
Size = 1
Encrypted = -

Path = evil_.exe
Size = 6
Encrypted = -

Path = evil_.exe
Size = 1
Encrypted = -
`

// fakeBinary is a 7z stand-in: banner for `i`, the given listing for `l`, the
// technical listing for `-slt l` (the reference one unless one is given), and the
// given command for `x`.
func fakeBinary(t *testing.T, banner, listing, extract string, technical ...string) *sevenZipExtract {
	t.Helper()
	tech := refTechnical
	if len(technical) > 0 && technical[0] != "" {
		tech = technical[0]
	}
	dir := t.TempDir()
	list, techFile := filepath.Join(dir, "listing"), filepath.Join(dir, "technical")
	if err := os.WriteFile(list, []byte(listing), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(techFile, []byte(tech), 0o600); err != nil {
		t.Fatal(err)
	}
	body := `
for a in "$@"; do case "$a" in -o*) out="${a#-o}";; esac; done
for a in "$@"; do
  if [ "$a" = i ]; then printf '%s\n' '` + banner + `'; exit 0; fi
  if [ "$a" = -slt ]; then cat ` + techFile + `; exit 0; fi
  if [ "$a" = l ]; then cat ` + list + `; exit 0; fi
  if [ "$a" = x ]; then ` + extract + `; exit 0; fi
done`
	return fakeSevenZip(t, body)
}

const goodExtract = `printf A > "$out/a.txt"; printf E > "$out/evil_.exe"`

func TestProve_fakeBinaries(t *testing.T) {
	tests := []struct {
		name        string
		banner      string
		listing     string
		extract     string
		technical   string
		wantErr     string
		wantUnavail bool
	}{
		{name: "behaves like a supported version", banner: "7-Zip (z) 25.01 (x64)", listing: refListing, extract: goodExtract},
		{name: "no banner", banner: "hello", listing: refListing, extract: goodExtract, wantErr: "banner"},
		{name: "older 7-Zip with the same listing", banner: "7-Zip (z) 24.09 (x64)", listing: refListing, extract: goodExtract, wantErr: "25.01"},
		{name: "7-Zip 25.00", banner: "7-Zip (z) 25.00 (x64)", listing: refListing, extract: goodExtract, wantErr: "25.01"},
		{name: "newer 7-Zip", banner: "7-Zip (z) 26.02 (x64)", listing: refListing, extract: goodExtract},
		{name: "no Tail Size", banner: "7-Zip (z) 25.01 (x64)", listing: strings.NewReplacer("Tail Size = 28\n", "", "WARNINGS:\nThere are data after the end of archive\n", "", "Warnings: 1\n", "").Replace(refListing), extract: goodExtract, wantErr: "Tail Size"},
		{name: "names not sanitized", banner: "7-Zip (z) 25.01 (x64)", listing: refListing, extract: goodExtract + `; printf H > "$out/evil_1.exe"`, wantErr: "sanitize"},
		{name: "shifted columns", banner: "7-Zip (z) 25.01 (x64)", listing: strings.ReplaceAll(refListing, "....A            1", "....A  x         1"), extract: goodExtract, wantErr: "not supported"},
		{name: "no separator line", banner: "7-Zip (z) 25.01 (x64)", listing: strings.Replace(refListing, "------------------- ----- ------------ ------------  ------------------------\n2026", "2026", 1), extract: goodExtract, wantErr: "not supported"},
		{name: "technical listing without Tail Size", banner: "7-Zip (z) 25.01 (x64)", listing: refListing, extract: goodExtract, technical: strings.NewReplacer("Tail Size = 28\n", "", "WARNINGS:\nThere are data after the end of archive\n", "").Replace(refTechnical), wantErr: "does not report data attached"},
		{name: "technical listing without Encrypted lines", banner: "7-Zip (z) 25.01 (x64)", listing: refListing, extract: goodExtract, technical: strings.ReplaceAll(refTechnical, "Encrypted = -\n", ""), wantErr: "Encrypted = -"},
		{name: "technical listing that says a member is encrypted", banner: "7-Zip (z) 25.01 (x64)", listing: refListing, extract: goodExtract, technical: strings.Replace(refTechnical, "Encrypted = -", "Encrypted = +", 1), wantErr: "Encrypted = -"},
		{name: "technical listing with another member count", banner: "7-Zip (z) 25.01 (x64)", listing: refListing, extract: goodExtract, technical: strings.Replace(refTechnical, "Path = evil_.exe\nSize = 1\nEncrypted = -\n", "", 1), wantErr: "technical listing"},
		{name: "technical listing without members", banner: "7-Zip (z) 25.01 (x64)", listing: refListing, extract: goodExtract, technical: "Path = reference.7z\nType = 7z\nTail Size = 28\n", wantErr: "technical listing"},
		{name: "wrong member count", banner: "7-Zip (z) 25.01 (x64)", listing: strings.Replace(refListing, "2026-11-20 10:07:18 ....A            1            1  evil_.exe\n", "", 1), extract: goodExtract, wantErr: "not supported"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sze := fakeBinary(t, tt.banner, tt.listing, tt.extract, tt.technical)
			err := prove(sze, t.TempDir())
			switch {
			case tt.wantErr == "" && err != nil:
				t.Errorf("prove() error = %v", err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Errorf("prove() error = %v, want it to mention %q", err, tt.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), "remedy") {
				t.Errorf("error %q must say the remedy", err)
			}
		})
	}
}

func TestProve_binariesThatDoNotRun(t *testing.T) {
	prev := proofTimeout
	proofTimeout = 2 * time.Second
	t.Cleanup(func() { proofTimeout = prev })
	tests := map[string]string{
		"exits with code 1": "exit 1",
		"hangs":             "sleep 60",
		"writes 100 MB":     "head -c 104857600 /dev/zero",
		"endless output":    "yes",
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			sze := fakeSevenZip(t, body)
			start := time.Now()
			err := prove(sze, t.TempDir())
			if err == nil {
				t.Fatal("prove() error = nil")
			}
			if time.Since(start) > 20*time.Second {
				t.Errorf("prove() took %v, it must be bounded", time.Since(start))
			}
		})
	}
}

func TestProve_noexecNamesTheCause(t *testing.T) {
	prev := noexec
	t.Cleanup(func() { noexec = prev })
	noexec = func(string) bool { return true }
	sze := &sevenZipExtract{sevenZipPath: filepath.Join(t.TempDir(), "absent"), logger: fakeSevenZip(t, "").logger}
	err := prove(sze, t.TempDir())
	if !errors.Is(err, plugins.ErrExtractorUnavailable) || !strings.Contains(err.Error(), "noexec") || !strings.Contains(err.Error(), "work_dir") {
		t.Errorf("prove() error = %v, want the noexec cause and the work_dir remedy", err)
	}
}

func TestExtractFile_binaryGoneIsUnavailableNotAnArchiveError(t *testing.T) {
	hcc := newMockContext(t)
	var p SevenZipExtractPlugin
	if err := p.Init(realConfig(), hcc); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := p.Close(t.Context()); err != nil {
			t.Error(err)
		}
	})
	if err := os.Remove(p.sze.sevenZipPath); err != nil {
		t.Fatal(err)
	}
	_, err := p.ExtractFile(fixture(t, "wildcard.7z"), t.TempDir(), openLimits)
	if !errors.Is(err, plugins.ErrExtractorUnavailable) {
		t.Errorf("ExtractFile() error = %v, want ErrExtractorUnavailable", err)
	}
}

func TestDeployEmbedded_twoDeploymentsInTheSameWorkDirDoNotShareAFolder(t *testing.T) {
	work := t.TempDir()
	first, err := deployEmbedded(work)
	if err != nil {
		t.Fatal(err)
	}
	second, err := deployEmbedded(work)
	if err != nil {
		t.Fatal(err)
	}
	if first.deployDir == second.deployDir || first.path == second.path {
		t.Fatalf("both deployments use %s", first.deployDir)
	}
	if err := first.remove(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(second.path); err != nil {
		t.Errorf("removing one deployment removed the other: %v", err)
	}
	if err := second.remove(); err != nil {
		t.Fatal(err)
	}
}

func TestStartRetryingBusy(t *testing.T) {
	prev := startCmd
	t.Cleanup(func() { startCmd = prev })
	path := fakeSevenZip(t, "true").sevenZipPath

	t.Run("busy then success", func(t *testing.T) {
		calls := 0
		startCmd = func(cmd *exec.Cmd) error {
			calls++
			if calls < 3 {
				return syscall.ETXTBSY
			}
			return prev(cmd)
		}
		cmd, stdout, err := startRetryingBusy(t.Context(), path, nil, io.Discard)
		if err != nil || calls != 3 {
			t.Fatalf("startRetryingBusy() = %v after %d calls, want success at the 3rd", err, calls)
		}
		if _, err := io.Copy(io.Discard, stdout); err != nil {
			t.Error(err)
		}
		if err := cmd.Wait(); err != nil {
			t.Error(err)
		}
	})
	t.Run("ten failures, no pause after the last", func(t *testing.T) {
		calls := 0
		startCmd = func(*exec.Cmd) error { calls++; return syscall.ETXTBSY }
		start := time.Now()
		_, _, err := startRetryingBusy(t.Context(), path, nil, io.Discard)
		if !errors.Is(err, syscall.ETXTBSY) || calls != busyAttempts {
			t.Fatalf("startRetryingBusy() = %v after %d calls, want ETXTBSY after %d", err, calls, busyAttempts)
		}
		if d := time.Since(start); d > time.Duration(busyAttempts)*busyPause {
			t.Errorf("took %v, want %d pauses at most (none after the last attempt)", d, busyAttempts-1)
		}
	})
	t.Run("cancelled while waiting", func(t *testing.T) {
		startCmd = func(*exec.Cmd) error { return syscall.ETXTBSY }
		ctx, cancel := context.WithCancel(t.Context())
		time.AfterFunc(20*time.Millisecond, cancel)
		start := time.Now()
		_, _, err := startRetryingBusy(ctx, path, nil, io.Discard)
		if !errors.Is(err, context.Canceled) || time.Since(start) > busyPause*3 {
			t.Errorf("startRetryingBusy() = %v after %v, want the context error promptly", err, time.Since(start))
		}
	})
	t.Run("a cancelled context is not an unavailable extractor", func(t *testing.T) {
		startCmd = func(*exec.Cmd) error { return syscall.ETXTBSY }
		ctx, cancel := context.WithCancel(t.Context())
		time.AfterFunc(20*time.Millisecond, cancel)
		sze := &sevenZipExtract{sevenZipPath: path, logger: fakeSevenZip(t, "").logger}
		_, err := sze.runStream(ctx, "", []string{"l", "x"}, nil)
		if !errors.Is(err, context.Canceled) || errors.Is(err, plugins.ErrExtractorUnavailable) {
			t.Errorf("runStream() error = %v, want the context error and not ErrExtractorUnavailable", err)
		}
	})
	t.Run("a process that cannot start for another reason is unavailable", func(t *testing.T) {
		startCmd = func(*exec.Cmd) error { return syscall.EMFILE }
		sze := &sevenZipExtract{sevenZipPath: path, logger: fakeSevenZip(t, "").logger}
		_, err := sze.runStream(t.Context(), "", []string{"l", "x"}, nil)
		if !errors.Is(err, plugins.ErrExtractorUnavailable) {
			t.Errorf("runStream() error = %v, want ErrExtractorUnavailable for EMFILE", err)
		}
	})
}

func TestCheckBanner(t *testing.T) {
	tests := map[string]bool{
		"7-Zip (z) 25.01 (x64) : Copyright": true,
		"7-Zip 25.01 (x64)":                 true,
		"7-Zip (a) 26.00":                   true,
		"7-Zip (z) 24.09 (x64)":             false,
		"7-Zip (z) 25.00":                   false,
		"7-Zip (z) 9.20":                    false,
		"p7zip 16.02":                       false,
		"":                                  false,
	}
	for banner, ok := range tests {
		if err := checkBanner(banner); (err == nil) != ok {
			t.Errorf("checkBanner(%q) error = %v, want ok = %t", banner, err, ok)
		}
	}
}
