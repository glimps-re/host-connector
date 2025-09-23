package scanner

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	"github.com/glimps-re/host-connector/pkg/plugins"
	"github.com/glimps-re/host-connector/pkg/report"
)

var Logger = slog.New(slog.NewJSONHandler(os.Stderr, nil))

var ErrInvalidPlugin = errors.New("invalid plugin")

var PluginInitTimeout = time.Minute * 5

func (c *Connector) SetXTractFile(f plugins.XtractFileFunc) {
	XtractFile = f
}

func (c *Connector) onStartScanFile(file string, sha256 string) *gdetect.Result {
	for _, cb := range c.onStartScanFileCbs {
		if r := cb(file, sha256); r != nil {
			return r
		}
	}
	return nil
}

func (c *Connector) onFileScanned(file string, sha256 string, result gdetect.Result, err error) {
	for _, cb := range c.onFileScannedCbs {
		cb(file, sha256, result, err)
	}
}

func (c *Connector) onReport(report *report.Report) {
	for _, cb := range c.onReportCbs {
		cb(report)
	}
}

func (c *Connector) RegisterOnStartScanFile(f plugins.OnStartScanFile) {
	c.onStartScanFileCbs = append(c.onStartScanFileCbs, f)
}

func (c *Connector) RegisterOnFileScanned(f plugins.OnFileScanned) {
	c.onFileScannedCbs = append(c.onFileScannedCbs, f)
}

func (c *Connector) RegisterOnReport(f plugins.OnReport) {
	c.onReportCbs = append(c.onReportCbs, f)
}

func (c *Connector) RegisterGenerateReport(f plugins.GenerateReport) {
	c.generateReport = f
}

func (c *Connector) GenerateReport(reportContext report.ScanContext, reports []report.Report) (io.Reader, error) {
	return c.generateReport(reportContext, reports)
}
