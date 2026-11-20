//go:build !linux

package main

// limitProcess has no equivalent here: the guard on the output folder is the
// only limit. A variable to mirror the Linux build.
var limitProcess = func(int, int64) error { return nil }
