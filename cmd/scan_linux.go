//go:build linux
// +build linux

package cmd

import (
	"context"

	"github.com/glimps-re/host-connector/pkg/scanner"
)

func Gui(entryPath string, nbFiles int) context.Context {
	return nil
}

func (a *GuiHandleResult) Handle(ctx context.Context, path string, result scanner.SummarizedGMalwareResult, report *scanner.Report) (err error) {
	return nil
}
