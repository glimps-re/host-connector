//go:build unix

package main

import "syscall"

// openNoFollow makes an open fail on a symbolic link at the last path element.
const openNoFollow = syscall.O_NOFOLLOW
