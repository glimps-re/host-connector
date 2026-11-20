//go:build linux

package main

import "syscall"

// stNoexec is ST_NOEXEC, the statfs flag of a file system mounted noexec.
const stNoexec = 8

// noexec reports whether path is on a file system mounted noexec. It only
// names a cause: running the binary is what decides.
var noexec = func(path string) bool {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return false
	}
	return st.Flags&stNoexec != 0
}
