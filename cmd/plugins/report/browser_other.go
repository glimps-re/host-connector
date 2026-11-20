//go:build !linux

package main

import "os/exec"

func confineBrowser(cmd *exec.Cmd) {
	cmd.WaitDelay = browserWaitDelay
}
