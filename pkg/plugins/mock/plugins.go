package mock

import (
	"io"
	"log/slog"
	"strings"

	"github.com/glimps-re/host-connector/pkg/plugins"
	"github.com/glimps-re/host-connector/pkg/report"
)

// MockHCContext is a mock implementation of plugins.HCContext for testing
type MockHCContext struct {
	OnStartScanFile    plugins.OnStartScanFile
	OnFileScanned      plugins.OnFileScanned
	OnReport           plugins.OnReport
	GenerateReportFunc plugins.GenerateReport
	XtractFileFunc     plugins.XtractFileFunc
	Logger             *slog.Logger
}

func NewMockHCContext() *MockHCContext {
	return &MockHCContext{
		Logger: slog.Default(),
	}
}

func (m *MockHCContext) SetXTractFile(f plugins.XtractFileFunc)            { m.XtractFileFunc = f }
func (m *MockHCContext) RegisterOnStartScanFile(f plugins.OnStartScanFile) { m.OnStartScanFile = f }
func (m *MockHCContext) RegisterOnFileScanned(f plugins.OnFileScanned)     { m.OnFileScanned = f }
func (m *MockHCContext) RegisterOnReport(f plugins.OnReport)               { m.OnReport = f }
func (m *MockHCContext) RegisterGenerateReport(f plugins.GenerateReport)   { m.GenerateReportFunc = f }
func (m *MockHCContext) GetLogger() *slog.Logger                           { return m.Logger }
func (m *MockHCContext) GenerateReport(reportContext report.ScanContext, reports []report.Report) (io.Reader, error) {
	if m.GenerateReportFunc != nil {
		return m.GenerateReportFunc(reportContext, reports)
	}
	return strings.NewReader("mock report content"), nil
}
