package mock

import (
	"context"
	"io"
	"iter"
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
	// NotifyErrorFunc and NotifyResolutionFunc receive the console events.
	NotifyErrorFunc      func(ctx context.Context, key string, err error)
	NotifyResolutionFunc func(ctx context.Context, key, message string)
	// PendingFilesFunc answers PendingFiles; nil means 0.
	PendingFilesFunc func(dir string) int
	// NotifyReportWrittenFunc receives NotifyReportWritten.
	NotifyReportWrittenFunc func(ctx context.Context, sessionID, path, sha256 string)
	ExtractFile             plugins.ExtractFile
	ConsoleLogger           *slog.Logger
	Logger                  *slog.Logger
	WorkDir                 string
	// Executables and OutputDirs record the declarations; DeclareExecutableErr
	// is returned by DeclareExecutable.
	Executables          []string
	OutputDirs           []string
	DeclareExecutableErr error
	// DeclareExecutableFunc, when set, replaces the check of DeclareExecutable.
	DeclareExecutableFunc func(path string) error
	OwnerRoot             string
	OwnerDepth            int
	OwnersErr             error
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
func (m *MockHCContext) GetWorkDir() string                              { return m.WorkDir }
func (m *MockHCContext) DeclareExecutable(path string) error {
	m.Executables = append(m.Executables, path)
	if m.DeclareExecutableFunc != nil {
		return m.DeclareExecutableFunc(path)
	}
	return m.DeclareExecutableErr
}

func (m *MockHCContext) DeclareOutputDir(path string) error {
	m.OutputDirs = append(m.OutputDirs, path)
	return nil
}

// NotifyError calls NotifyErrorFunc when set.
func (m *MockHCContext) NotifyError(ctx context.Context, key string, err error) {
	if m.NotifyErrorFunc != nil {
		m.NotifyErrorFunc(ctx, key, err)
	}
}

// NotifyResolution calls NotifyResolutionFunc when set.
func (m *MockHCContext) NotifyResolution(ctx context.Context, key, message string) {
	if m.NotifyResolutionFunc != nil {
		m.NotifyResolutionFunc(ctx, key, message)
	}
}

// PendingFiles calls PendingFilesFunc, or returns 0.
func (m *MockHCContext) PendingFiles(dir string) int {
	if m.PendingFilesFunc != nil {
		return m.PendingFilesFunc(dir)
	}
	return 0
}

// NotifyReportWritten calls NotifyReportWrittenFunc when set.
func (m *MockHCContext) NotifyReportWritten(ctx context.Context, sessionID, path, sha256 string) {
	if m.NotifyReportWrittenFunc != nil {
		m.NotifyReportWrittenFunc(ctx, sessionID, path, sha256)
	}
}

func (m *MockHCContext) SetTrackingOwners(root string, depth int) error {
	m.OwnerRoot, m.OwnerDepth = root, depth
	return m.OwnersErr
}

// GenerateReport calls GenerateReportFunc, or returns a fixed ".pdf" content.
func (m *MockHCContext) GenerateReport(ctx context.Context, reportContext datamodel.ScanContext, reports iter.Seq2[datamodel.Report, error]) (plugins.GeneratedReport, error) {
	if m.GenerateReportFunc != nil {
		return m.GenerateReportFunc(ctx, reportContext, reports)
	}
	return plugins.GeneratedReport{Content: io.NopCloser(strings.NewReader("mock report content")), Extension: ".pdf"}, nil
}
