package scanner

import (
	"errors"
	"io"
	"time"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
)

type PluginConfig struct {
	File   string         `yaml:"file"`
	Config map[string]any `yaml:"config"`
}

var ErrInvalidPlugin = errors.New("invalid plugin")

var PluginInitTimeout = time.Minute * 5

func (c *Connector) SetExtractFile(f plugins.ExtractFile) {
	ExtractFile = f
}

func (c *Connector) onStartScanFile(filepath string, sha256 string) {
	for _, cb := range c.onStartScanFileCbs {
		cb(filepath, sha256)
	}
}

func (c *Connector) onScanFile(filename string, filepath string, sha256 string, isArchive bool) *datamodel.Result {
	for _, cb := range c.onScanFileCbs {
		if r := cb(filename, filepath, sha256, isArchive); r != nil {
			return r
		}
	}
	return nil
}

func (c *Connector) onFileScanned(filepath string, sha256 string, result datamodel.Result) (newResult *datamodel.Result) {
	for _, cb := range c.onFileScannedCbs {
		if res := cb(filepath, sha256, result); res != nil {
			return res
		}
	}
	return
}

func (c *Connector) withWaitForOptions(opts *gdetect.WaitForOptions, location string) {
	for _, f := range c.withWaitForOptionsFunc {
		f(opts, location)
	}
}

func (c *Connector) onReport(report *datamodel.Report) {
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

func (c *Connector) RegisterOnScanFile(f plugins.OnScanFile) {
	c.onScanFileCbs = append(c.onScanFileCbs, f)
}

func (c *Connector) RegisterWithWaitForOptions(f plugins.WithWaitForOptionsFunc) {
	c.withWaitForOptionsFunc = append(c.withWaitForOptionsFunc, f)
}

func (c *Connector) RegisterOnReport(f plugins.OnReport) {
	c.onReportCbs = append(c.onReportCbs, f)
}

func (c *Connector) RegisterGenerateReport(f plugins.GenerateReport) {
	c.generateReport = f
}

func (c *Connector) GenerateReport(reportContext datamodel.ScanContext, reports []datamodel.Report) (io.Reader, error) {
	return c.generateReport(reportContext, reports)
}
