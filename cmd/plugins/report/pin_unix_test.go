//go:build !windows

package main

import (
	"fmt"
	"os"
)

// testLinkBase is the private short folder the links of the browser are made in
// during the tests.
var testLinkBase string

// pinLinkBase points the folder of the links, and its fallback, to a private
// short folder, so that no test reaches the real temporary folder (Init purges
// it). The returned function removes the folder.
func pinLinkBase() (unpin func()) {
	dir, err := os.MkdirTemp("/tmp", "r")
	if err != nil {
		panic(err)
	}
	testLinkBase = dir
	systemTempDir = func() string { return dir }
	fallbackLinkBase = dir
	if got, lerr := linkBase(); lerr != nil || got != dir {
		panic(fmt.Sprintf("linkBase() = %q, %v, want %q", got, lerr, dir))
	}
	return func() {
		if err := os.RemoveAll(dir); err != nil {
			panic(err)
		}
	}
}
