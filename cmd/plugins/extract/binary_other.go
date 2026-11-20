//go:build !linux

package main

var noexec = func(string) bool { return false }
