//go:build linux

package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/glimps-re/host-connector/pkg/plugins"
)

const scriptMode os.FileMode = 0o700

// Interrupt kills the 7-Zip running: the extraction returns an error at once,
// long before the script would have ended.
func TestSevenZipExtractPlugin_InterruptCutsARunningExtraction(t *testing.T) {
	script := filepath.Join(t.TempDir(), "7z")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nsleep 60\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(script, scriptMode); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.DiscardHandler)
	p := &SevenZipExtractPlugin{
		sze:           &sevenZipExtract{sevenZipPath: script, logger: logger},
		logger:        logger,
		consoleLogger: logger,
	}
	p.baseCtx, p.cancelBase = context.WithCancel(context.Background())
	archive := filepath.Join(t.TempDir(), "a.zip")
	if err := os.WriteFile(archive, []byte("not an archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := p.ExtractFile(archive, t.TempDir(), plugins.ExtractLimits{})
		done <- err
	}()
	time.Sleep(300 * time.Millisecond)
	start := time.Now()
	p.Interrupt()
	select {
	case err := <-done:
		if err == nil {
			t.Error("ExtractFile() = nil after Interrupt, want an error")
		}
		if took := time.Since(start); took > 2*time.Second {
			t.Errorf("ExtractFile returned %s after Interrupt, want under 2s", took)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("ExtractFile did not return after Interrupt")
	}
}

func TestSevenZipExtractPlugin_CloseInterruptsToo(t *testing.T) {
	var p SevenZipExtractPlugin
	p.baseCtx, p.cancelBase = context.WithCancel(context.Background())
	if err := p.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if p.baseCtx.Err() == nil {
		t.Error("Close must cancel the base context of the extractions")
	}
}

// A 7-Zip killed by the interruption, whose output already said it refused a
// link, is not a success: the extraction is cut, not complete.
func TestSevenZipExtract_anInterruptedRunWithALinkRefusalIsNotASuccess(t *testing.T) {
	script := filepath.Join(t.TempDir(), "7z")
	body := "#!/bin/sh\necho 'ERROR: Dangerous link path was ignored : a/link : /etc' >&2\nsleep 60\n"
	if err := os.WriteFile(script, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(script, scriptMode); err != nil {
		t.Fatal(err)
	}
	sze := &sevenZipExtract{sevenZipPath: script, logger: slog.New(slog.DiscardHandler)}
	ctx, cancel := context.WithCancel(t.Context())
	type outcome struct {
		links []string
		err   error
	}
	done := make(chan outcome, 1)
	go func() {
		links, err := sze.runStream(ctx, "", []string{"x"}, func(r io.Reader) error { _, e := io.Copy(io.Discard, r); return e }, "a.zip")
		done <- outcome{links, err}
	}()
	time.Sleep(300 * time.Millisecond)
	cancel()
	select {
	case got := <-done:
		if got.err == nil || !errors.Is(got.err, context.Canceled) {
			t.Errorf("runStream() = %v, %v, want the cancellation as an error", got.links, got.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the run did not return after the cancellation")
	}
}

// 7-Zip is really running (a script that takes a minute) when the stop comes:
// the process is gone, with its children, once Interrupt returned.
func TestSevenZipExtractPlugin_noSevenZipIsLeftAfterInterrupt(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "child-pid")
	script := filepath.Join(dir, "7z")
	body := "#!/bin/sh\nsleep 60 &\necho $! > " + marker + "\nwait\n"
	if err := os.WriteFile(script, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(script, scriptMode); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.DiscardHandler)
	p := &SevenZipExtractPlugin{sze: &sevenZipExtract{sevenZipPath: script, logger: logger}, logger: logger, consoleLogger: logger}
	p.baseCtx, p.cancelBase = context.WithCancel(context.Background())
	archive := filepath.Join(dir, "a.zip")
	if err := os.WriteFile(archive, []byte("not an archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := p.ExtractFile(archive, t.TempDir(), plugins.ExtractLimits{}); err == nil {
			t.Error("ExtractFile() = nil after Interrupt, want an error")
		}
	}()
	var pid int
	for range 100 {
		if raw, err := os.ReadFile(filepath.Clean(marker)); err == nil && len(raw) > 1 {
			n, convErr := strconv.Atoi(strings.TrimSpace(string(raw)))
			if convErr != nil {
				t.Fatal(convErr)
			}
			pid = n
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if pid == 0 {
		t.Fatal("the fake 7z did not start its child")
	}
	p.Interrupt()
	<-done
	for range 50 {
		if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Errorf("the process %d of the 7-Zip is still running after Interrupt", pid)
}
