package mock

import (
	"io"
	"log/slog"
	"strings"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
)

// MockHCContext is a mock implementation of plugins.HCContext for testing
type MockHCContext struct {
	OnStartScanFile    plugins.OnStartScanFile
	OnScanFile         plugins.OnScanFile
	WithWaitForOptions plugins.WithWaitForOptionsFunc
	OnFileScanned      plugins.OnFileScanned
	OnReport           plugins.OnReport
	GenerateReportFunc plugins.GenerateReport
	ExtractFile        plugins.ExtractFile
	ConsoleLogger      *slog.Logger
	Logger             *slog.Logger
}

func NewMockHCContext() *MockHCContext {
	return &MockHCContext{
		ConsoleLogger: slog.New(slog.DiscardHandler),
		Logger:        slog.Default(),
	}
}

func (m *MockHCContext) SetExtractFile(f plugins.ExtractFile)              { m.ExtractFile = f }
func (m *MockHCContext) RegisterOnStartScanFile(f plugins.OnStartScanFile) { m.OnStartScanFile = f }
func (m *MockHCContext) RegisterOnScanFile(f plugins.OnScanFile)           { m.OnScanFile = f }
func (m *MockHCContext) RegisterWithWaitForOptions(f plugins.WithWaitForOptionsFunc) {
	m.WithWaitForOptions = f
}
func (m *MockHCContext) RegisterOnFileScanned(f plugins.OnFileScanned)   { m.OnFileScanned = f }
func (m *MockHCContext) RegisterOnReport(f plugins.OnReport)             { m.OnReport = f }
func (m *MockHCContext) RegisterGenerateReport(f plugins.GenerateReport) { m.GenerateReportFunc = f }
func (m *MockHCContext) GetLogger() *slog.Logger                         { return m.Logger }
func (m *MockHCContext) GetConsoleLogger() *slog.Logger                  { return m.ConsoleLogger }
func (m *MockHCContext) GenerateReport(reportContext datamodel.ScanContext, reports []datamodel.Report) (io.Reader, error) {
	if m.GenerateReportFunc != nil {
		return m.GenerateReportFunc(reportContext, reports)
	}
	return strings.NewReader("mock report content"), nil
}
