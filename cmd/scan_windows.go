//go:build windows
// +build windows

package cmd

import (
	"context"
	"embed"
	"strconv"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	"github.com/glimps-re/host-connector/pkg/scanner"
	"github.com/gonutz/wui/v2"
)

//go:embed *.ico

var files embed.FS

func createWindow(pg *wui.ProgressBar, xLabel *wui.Label, fileLabel *wui.Label, path string, nbFilesLabel *wui.Label) context.Context {
	windowFont, _ := wui.NewFont(wui.FontDesc{
		Name:   "Tahoma",
		Height: -11,
	})
	window := wui.NewWindow()
	window.SetFont(windowFont)
	window.SetInnerSize(544, 190)
	window.SetTitle("GMHost")

	FSico, _ := files.Open("Glimps.ico")
	icon, _ := wui.NewIconFromReader(FSico)
	window.SetIcon(icon)
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

	dir_scan := wui.NewLabel()

	dir_scan.SetBounds(60, 30, 151, 15)
	dir_scan.SetText("Scanning folder: ")
	window.Add(dir_scan)

	folder_name := wui.NewLabel()
	folder_name.SetBounds(148, 30, 150, 15)
	folder_name.SetText(path)
	window.Add(folder_name)

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
		window.Show()
	}()
	return ctx
}

func Gui(entryPath string, nbFiles int) context.Context {
	progressBar1 := wui.NewProgressBar()
	xLabel := wui.NewLabel()
	fileLabel := wui.NewLabel()
	nbFilesLabel := wui.NewLabel()
	nbFileScanned := 0
	HandleResultCB = func(path, sha256 string, result gdetect.Result, report *scanner.Report) (err error) {
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

var HandleResultCB = func(path string, sha256 string, result gdetect.Result, report *scanner.Report) (err error) {
	return nil
}

func (a *GuiHandleResult) Handle(path string, sha256 string, result gdetect.Result, report *scanner.Report) (err error) {
	return HandleResultCB(path, sha256, result, report)
}
