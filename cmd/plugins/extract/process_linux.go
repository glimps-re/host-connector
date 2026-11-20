//go:build linux

package main

import (
	"os/exec"
	"syscall"
)

// confineProcess puts 7z in its own process group, killed as a whole when the
// context ends: a configured seven_zip_path can be a script whose children
// would otherwise survive.
func confineProcess(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = new(syscall.SysProcAttr)
	}
	cmd.SysProcAttr.Setpgid = true
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
