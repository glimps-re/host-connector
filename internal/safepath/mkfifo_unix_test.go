//go:build !windows

package safepath

import "syscall"

func mkfifo(path string) error { return syscall.Mkfifo(path, 0o600) }
