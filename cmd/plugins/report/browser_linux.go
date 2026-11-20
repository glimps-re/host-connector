//go:build linux

package main

import (
	"os/exec"
	"syscall"
)

// confineBrowser puts the browser in its own process group, killed as a whole
// when the context ends, and bounds the wait for its pipes: no child survives.
func confineBrowser(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = new(syscall.SysProcAttr)
	}
	cmd.SysProcAttr.Setpgid = true
	// Pdeathsig is tied to the thread that started the process (golang/go#27505):
	// only a best effort, the kill of the group on cancel is the real guard.
	cmd.SysProcAttr.Pdeathsig = syscall.SIGKILL
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = browserWaitDelay
}
