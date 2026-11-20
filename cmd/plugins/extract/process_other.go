//go:build !linux

package main

import "os/exec"

func confineProcess(*exec.Cmd) {}
