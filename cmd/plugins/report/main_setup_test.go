//go:build linux

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// realBrowser is the browser installed on the machine, "" when there is none.
var realBrowser string

// Mode of the fake browser scripts: named constant, they are test fixtures.
const scriptMode os.FileMode = 0o700

func TestMain(m *testing.M) {
	if p, err := exec.LookPath("chromium"); err == nil {
		realBrowser = p
	} else if p, err := exec.LookPath("google-chrome"); err == nil {
		realBrowser = p
	}
	dir, err := os.MkdirTemp("", "report-path-")
	if err != nil {
		panic(err)
	}
	fake := filepath.Join(dir, "chromium")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nexit 1\n"), 0o600); err != nil {
		panic(err)
	}
	if err := os.Chmod(fake, scriptMode); err != nil {
		panic(err)
	}
	if err := os.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH")); err != nil {
		panic(err)
	}
	unpin := pinLinkBase()
	checkBrowser = func(context.Context, *browserRunner) error { return nil }
	effectiveUID = func() int { return 1000 }
	code := m.Run()
	unpin()
	if err := os.RemoveAll(dir); err != nil {
		panic(err)
	}
	os.Exit(code)
}

func fakeBrowser(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "chrome")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, scriptMode); err != nil {
		t.Fatal(err)
	}
	return path
}

func skipWithoutBrowser(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("Chrome refuses its sandbox as root")
	}
	t.Helper()
	if realBrowser == "" {
		t.Skip("no browser installed")
	}
}
