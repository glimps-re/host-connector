//go:build linux

package handler

import (
	"context"

	"github.com/glimps-re/host-connector/pkg/datamodel"
)

func Gui(entryPath string, nbFiles int) context.Context {
	return nil
}

func (a *GuiHandleResult) Handle(ctx context.Context, path string, result datamodel.Result, report *datamodel.Report) (err error) {
	return nil
}
