//go:build linux
// +build linux

package cmd

import (
	"context"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	"github.com/glimps-re/host-connector/pkg/scanner"
)

func Gui(entryPath string, nbFiles int) context.Context {
	return nil
}

func (a *GuiHandleResult) Handle(path string, sha256 string, result gdetect.Result, report *scanner.Report) (err error) {
	return nil
}
