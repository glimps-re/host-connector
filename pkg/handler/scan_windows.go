//go:build windows

package handler

import (
	"bytes"
	"context"
	_ "embed"
	"log/slog"
	"strconv"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/scanner"
	"github.com/gonutz/wui/v2"
)

//go:embed Glimps.ico
var ico []byte

func createWindow(pg *wui.ProgressBar, xLabel *wui.Label, fileLabel *wui.Label, path string, nbFilesLabel *wui.Label) context.Context {
	window := wui.NewWindow()
	if windowFont, err := wui.NewFont(wui.FontDesc{
		Name:   "Tahoma",
		Height: -11,
	}); err != nil {
		slog.Warn("could not create the window font", slog.String("error", err.Error()))
	} else {
		window.SetFont(windowFont)
	}
	window.SetInnerSize(544, 190)
	window.SetTitle("GMHost")

	if icon, err := wui.NewIconFromReader(bytes.NewReader(ico)); err != nil {
		slog.Warn("could not load the window icon", slog.String("error", err.Error()))
	} else {
		window.SetIcon(icon)
	}
	pg.SetBounds(59, 129, 411, 30)
	pg.SetValue(0)
	window.Add(pg)

	label1 := wui.NewLabel()
	label1.SetBounds(61, 66, 150, 15)
	label1.SetText("Number of files analyzed: ")
	window.Add(label1)

	nbFilesLabel.SetBounds(219, 66, 150, 15)
	nbFilesLabel.SetText("0")
	window.Add(nbFilesLabel)

	dirScan := wui.NewLabel()

	dirScan.SetBounds(60, 30, 151, 15)
	dirScan.SetText("Scanning folder: ")
	window.Add(dirScan)

	folderName := wui.NewLabel()
	folderName.SetBounds(148, 30, 150, 15)
	folderName.SetText(path)
	window.Add(folderName)

	label2 := wui.NewLabel()
	label2.SetBounds(61, 98, 118, 15)
	label2.SetText("Last file scanned: ")
	window.Add(label2)

	fileLabel.SetBounds(179, 98, 331, 15)
	window.Add(fileLabel)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		window.SetOnClose(func() {
			cancel()
		})
		if err := window.Show(); err != nil {
			slog.Error("could not show the scan window", slog.String("error", err.Error()))
		}
	}()
	return ctx
}

func Gui(entryPath string, nbFiles int) context.Context {
	progressBar1 := wui.NewProgressBar()
	xLabel := wui.NewLabel()
	fileLabel := wui.NewLabel()
	nbFilesLabel := wui.NewLabel()
	nbFileScanned := 0
	HandleResultCB = func(path string, result datamodel.Result, report *datamodel.Report) (err error) {
		nbFileScanned++
		nbFilesLabel.SetText(strconv.Itoa(nbFileScanned))
		fileLabel.SetText(path)
		return nil
	}
	HandleScanFinished = func() {
		progressBar1.SetValue(100)
	}
	return createWindow(progressBar1, xLabel, fileLabel, entryPath, nbFilesLabel)
}

var HandleResultCB = func(path string, result datamodel.Result, report *datamodel.Report) (err error) {
	return nil
}

func (a *GuiHandleResult) Handle(ctx context.Context, src scanner.Source, result datamodel.Result, report *datamodel.Report) (err error) {
	return HandleResultCB(src.Path, result, report)
}
