//go:build linux

package main

import (
	"os/exec"
	"testing"

	"golang.org/x/sys/unix"
)

func TestLimitProcess_noCoreDumpAndFileSizeLimited(t *testing.T) {
	cmd := exec.CommandContext(t.Context(), "sleep", "5")
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start sleep: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	if err := limitProcess(cmd.Process.Pid, 12345); err != nil {
		t.Fatal(err)
	}
	var core, fsize unix.Rlimit
	if err := unix.Prlimit(cmd.Process.Pid, unix.RLIMIT_CORE, nil, &core); err != nil {
		t.Fatal(err)
	}
	if err := unix.Prlimit(cmd.Process.Pid, unix.RLIMIT_FSIZE, nil, &fsize); err != nil {
		t.Fatal(err)
	}
	if core.Cur != 0 || core.Max != 0 {
		t.Errorf("RLIMIT_CORE = %+v, want 0: a stopped 7z must not dump core", core)
	}
	if fsize.Cur != 12345 {
		t.Errorf("RLIMIT_FSIZE = %d, want 12345", fsize.Cur)
	}
}
