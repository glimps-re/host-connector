//go:build !windows

package scanner

import "syscall"

func mkfifoFile(path string) error { return syscall.Mkfifo(path, 0o600) }
