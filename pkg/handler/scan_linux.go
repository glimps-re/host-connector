//go:build linux

package handler

import (
	"context"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/scanner"
)

func Gui(entryPath string, nbFiles int) context.Context {
	return nil
}

func (a *GuiHandleResult) Handle(ctx context.Context, src scanner.Source, result datamodel.Result, report *datamodel.Report) (err error) {
	return nil
}
