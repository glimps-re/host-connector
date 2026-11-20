//go:build linux

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestSelfTest_noChildSurvives(t *testing.T) {
	prev := renderTestTimeout
	renderTestTimeout = 2 * time.Second
	t.Cleanup(func() { renderTestTimeout = prev })

	pidFile := filepath.Join(t.TempDir(), "child.pid")
	b := runner(t, fakeBrowser(t, "sleep 300 &\necho $! > "+pidFile+"\nsleep 300"))
	if err := b.selfTest(t.Context()); err == nil {
		t.Fatal("selfTest() error = nil")
	}
	raw, err := os.ReadFile(filepath.Clean(pidFile))
	if err != nil {
		t.Fatalf("the fake browser did not start its child (is sleep in PATH?): %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Errorf("child process %d survived the browser", pid)
}
