//go:build linux

package main

import (
	"math"

	"golang.org/x/sys/unix"
)

// limitProcess caps what the process can write: no file grows past fileLimit
// (the kernel refuses, whatever the archive announces), and no core dump is
// made when it is stopped for it (SIGXFSZ dumps core by default, and an archive
// could make that happen at will). A variable so tests can make it ineffective.
var limitProcess = func(pid int, fileLimit int64) error {
	core := unix.Rlimit{}
	if err := unix.Prlimit(pid, unix.RLIMIT_CORE, &core, nil); err != nil {
		return err
	}
	if fileLimit <= 0 || fileLimit == math.MaxInt64 {
		return nil
	}
	lim := unix.Rlimit{Cur: uint64(fileLimit), Max: uint64(fileLimit)}
	return unix.Prlimit(pid, unix.RLIMIT_FSIZE, &lim, nil)
}
