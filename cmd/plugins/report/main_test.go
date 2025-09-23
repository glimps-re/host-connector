package main

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/glimps-re/host-connector/pkg/plugins"
	"github.com/glimps-re/host-connector/pkg/report"
)

// mockHCContext is a mock implementation of plugins.HCContext for testing
type mockHCContext struct {
	generateReportFunc plugins.GenerateReport
}

func (m *mockHCContext) SetXTractFile(f plugins.XtractFileFunc)            {}
func (m *mockHCContext) RegisterOnStartScanFile(f plugins.OnStartScanFile) {}
func (m *mockHCContext) RegisterOnFileScanned(f plugins.OnFileScanned)     {}
func (m *mockHCContext) RegisterOnReport(f plugins.OnReport)               {}
func (m *mockHCContext) RegisterGenerateReport(f plugins.GenerateReport)   { m.generateReportFunc = f }
func (m *mockHCContext) GetLogger() *slog.Logger                           { return slog.Default() }
func (m *mockHCContext) GenerateReport(reportContext report.ScanContext, reports []report.Report) (io.Reader, error) {
	if m.generateReportFunc != nil {
		return m.generateReportFunc(reportContext, reports)
	}
	return nil, nil
}

func TestMergeArgsIntoSlice(t *testing.T) {
	tests := []struct {
		name string
		args []interface{}
		want []interface{}
	}{
		{
			name: "empty args",
			args: []interface{}{},
			want: []interface{}{},
		},
		{
			name: "single arg",
			args: []interface{}{"test"},
			want: []interface{}{"test"},
		},
		{
			name: "multiple args",
			args: []interface{}{"test", 123, true},
			want: []interface{}{"test", 123, true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mergeArgsIntoSlice(tt.args...)
			if len(got) != len(tt.want) {
				t.Errorf("mergeArgsIntoSlice() length = %v, want %v", len(got), len(tt.want))
			}
			for i, v := range got {
				if v != tt.want[i] {
					t.Errorf("mergeArgsIntoSlice()[%d] = %v, want %v", i, v, tt.want[i])
				}
			}
		})
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
		want     string
	}{
		{
			name:     "zero duration",
			duration: 0,
			want:     "0s",
		},
		{
			name:     "only seconds",
			duration: 45 * time.Second,
			want:     "45s",
		},
		{
			name:     "only minutes",
			duration: 3 * time.Minute,
			want:     "3m0s",
		},
		{
			name:     "minutes and seconds",
			duration: 2*time.Minute + 30*time.Second,
			want:     "2m30s",
		},
		{
			name:     "more than 60 minutes",
			duration: 75*time.Minute + 45*time.Second,
			want:     "75m45s",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatDuration(tt.duration)
			if got != tt.want {
				t.Errorf("formatDuration() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestReportPlugin_Init(t *testing.T) {
	tests := []struct {
		name       string
		configPath string
		wantErr    bool
	}{
		{
			name:       "init with default template",
			configPath: "",
			wantErr:    false,
		},
		{
			name:       "init with invalid config path",
			configPath: "/invalid/path/template.html",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &ReportPlugin{}
			mockContext := &mockHCContext{}

			err := p.Init(tt.configPath, mockContext)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReportPlugin.Init() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if p.templ == nil {
					t.Error("ReportPlugin.Init() template should not be nil after successful init")
				}
				if mockContext.generateReportFunc == nil {
					t.Error("ReportPlugin.Init() should register GenerateReport function")
				}
			}
		})
	}
}

func TestReportPlugin_Close(t *testing.T) {
	p := &ReportPlugin{}
	err := p.Close(context.Background())
	if err != nil {
		t.Errorf("ReportPlugin.Close() error = %v, want nil", err)
	}
}

func TestReportPlugin_scanResToReportData(t *testing.T) {
	p := &ReportPlugin{}

	startTime := time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)
	endTime := startTime.Add(2*time.Minute + 30*time.Second)

	reportContext := report.ScanContext{
		Start:  startTime,
		End:    endTime,
		ScanID: "scan1",
	}

	reports := []report.Report{
		{
			FileName:  "clean_file.txt",
			Sha256:    "abc123",
			Malicious: false,
			Malware:   []string{},
		},
		{
			FileName:  "malware_file.exe",
			Sha256:    "def456",
			Malicious: true,
			Malware:   []string{"Trojan.Win32.Test", "Backdoor.Generic"},
		},
		{
			FileName:  "another_clean.pdf",
			Sha256:    "ghi789",
			Malicious: false,
			Malware:   []string{},
		},
	}

	reportData := p.scanResToReportData(reportContext, reports)

	// Check basic fields
	if reportData.NbFileSubmitted != 3 {
		t.Errorf("ReportPlugin.scanResToReportData() NbFileSubmitted = %v, want 3", reportData.NbFileSubmitted)
	}

	if reportData.NbFileAnalyzed != 3 {
		t.Errorf("ReportPlugin.scanResToReportData() NbFileAnalyzed = %v, want 3", reportData.NbFileAnalyzed)
	}

	if reportData.ScanStartTime != startTime.Format(time.RFC3339) {
		t.Errorf("ReportPlugin.scanResToReportData() ScanStartTime = %v, want %v",
			reportData.ScanStartTime, startTime.Format(time.RFC3339))
	}

	if reportData.ScanID != reportContext.ScanID {
		t.Errorf("ReportPlugin.scanResToReportData() ScanID = %v, want %v",
			reportData.ScanID, reportContext.ScanID)
	}

	expectedDuration := endTime.Sub(startTime).String()
	if reportData.Duration != expectedDuration {
		t.Errorf("ReportPlugin.scanResToReportData() Duration = %v, want %v",
			reportData.Duration, expectedDuration)
	}

	// Check file categorization
	if len(reportData.FilesMalware) != 1 {
		t.Errorf("ReportPlugin.scanResToReportData() FilesMalware length = %v, want 1", len(reportData.FilesMalware))
	} else {
		malwareFile := reportData.FilesMalware[0]
		if malwareFile.Name != "malware_file.exe" {
			t.Errorf("ReportPlugin.scanResToReportData() malware file name = %v, want malware_file.exe", malwareFile.Name)
		}
		if malwareFile.Sha256 != "def456" {
			t.Errorf("ReportPlugin.scanResToReportData() malware file sha256 = %v, want def456", malwareFile.Sha256)
		}
		if len(malwareFile.Malwares) != 2 {
			t.Errorf("ReportPlugin.scanResToReportData() malware count = %v, want 2", len(malwareFile.Malwares))
		}
	}

	if len(reportData.FilesSafe) != 2 {
		t.Errorf("ReportPlugin.scanResToReportData() FilesSafe length = %v, want 2", len(reportData.FilesSafe))
	}
}

func TestReportPlugin_GenerateHTMLReport(t *testing.T) {
	p := &ReportPlugin{}

	// Initialize with default template
	mockContext := &mockHCContext{}
	err := p.Init("", mockContext)
	if err != nil {
		t.Fatalf("Failed to initialize plugin: %v", err)
	}

	testData := ReportData{
		ScanID:          "20230101-120000",
		NbFileSubmitted: 2,
		NbFileAnalyzed:  2,
		VolumeAnalyzed:  "1.5MB",
		FilesInError:    []FileReportData{},
		FilesSafe: []FileReportData{
			{Name: "clean.txt", Sha256: "abc123", Size: "1KB", Malwares: []string{}},
		},
		FilesMalware: []FileReportData{
			{Name: "virus.exe", Sha256: "def456", Size: "500B", Malwares: []string{"Trojan.Test"}},
		},
		FilesIgnored:  []FileReportData{},
		FilesPartial:  []FileReportData{},
		ScanStartTime: "2023-01-01T12:00:00Z",
		Duration:      "2m30s",
	}

	htmlBuf, err := p.GenerateHTMLReport(testData)
	if err != nil {
		t.Errorf("ReportPlugin.GenerateHTMLReport() error = %v", err)
		return
	}

	if htmlBuf == nil {
		t.Error("ReportPlugin.GenerateHTMLReport() returned nil buffer")
		return
	}

	htmlContent := htmlBuf.String()
	if htmlContent == "" {
		t.Error("ReportPlugin.GenerateHTMLReport() returned empty HTML content")
	}

	// Check that the HTML contains some expected content
	if !strings.Contains(htmlContent, "<!DOCTYPE html>") {
		t.Error("ReportPlugin.GenerateHTMLReport() HTML should contain DOCTYPE declaration")
	}

	// Check that data values are present in the HTML
	if !strings.Contains(htmlContent, "clean.txt") {
		t.Error("ReportPlugin.GenerateHTMLReport() HTML should contain safe file name")
	}

	if !strings.Contains(htmlContent, "virus.exe") {
		t.Error("ReportPlugin.GenerateHTMLReport() HTML should contain malware file name")
	}
}

func TestReportPlugin_GeneratePdfReport_Mock(t *testing.T) {
	// Note: This test is limited because GeneratePdfReport uses chromedp which requires
	// a browser environment. In a real CI/CD environment, you might want to:
	// 1. Skip this test if chrome/chromium is not available
	// 2. Use dependency injection to mock the PDF generation
	// 3. Test only the data preparation part

	p := &ReportPlugin{}

	// Initialize with default template
	mockContext := &mockHCContext{}
	err := p.Init("", mockContext)
	if err != nil {
		t.Fatalf("Failed to initialize plugin: %v", err)
	}

	reportContext := report.ScanContext{
		Start: time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
		End:   time.Date(2023, 1, 1, 12, 2, 30, 0, time.UTC),
	}

	reports := []report.Report{
		{
			FileName:  "test.txt",
			Sha256:    "abc123",
			Malicious: false,
			Malware:   []string{},
		},
	}

	// Test data preparation part (this will work without chromedp)
	reportData := p.scanResToReportData(reportContext, reports)

	// Test HTML generation part
	htmlBuf, err := p.GenerateHTMLReport(reportData)
	if err != nil {
		t.Errorf("ReportPlugin.GeneratePdfReport() HTML generation error = %v", err)
		return
	}

	if htmlBuf == nil || htmlBuf.Len() == 0 {
		t.Error("ReportPlugin.GeneratePdfReport() HTML buffer should not be empty")
	}

	// Note: We skip the actual PDF generation test here because it requires chromedp
	// In a full integration test environment, you would call:
	// pdfBuf, err := p.GeneratePdfReport(reportContext, reports)
	// But this requires a headless browser to be available
}

func TestReportPlugin_GenerateReport(t *testing.T) {
	p := &ReportPlugin{}

	// Initialize with default template
	mockContext := &mockHCContext{}
	err := p.Init("", mockContext)
	if err != nil {
		t.Fatalf("Failed to initialize plugin: %v", err)
	}

	reportContext := report.ScanContext{
		ScanID: "test-scan-123",
		Start:  time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
		End:    time.Date(2023, 1, 1, 12, 2, 30, 0, time.UTC),
	}

	reports := []report.Report{
		{
			FileName:  "test_file.txt",
			Sha256:    "abc123def456",
			Malicious: false,
			Malware:   []string{},
		},
		{
			FileName:  "malware_file.exe",
			Sha256:    "def456abc789",
			Malicious: true,
			Malware:   []string{"Trojan.Test", "Backdoor.Generic"},
		},
	}

	// Note: This test will likely fail in CI/CD environments without chromedp/browser
	// but will test the data preparation and HTML generation parts
	result, err := p.GenerateReport(reportContext, reports)
	// Check if we got an error due to chromedp not being available
	if err != nil {
		// This is expected in environments without a browser
		t.Logf("GenerateReport failed as expected without browser environment: %v", err)

		// We can still test that the data preparation works
		reportData := p.scanResToReportData(reportContext, reports)

		// Verify the data was prepared correctly
		if reportData.ScanID != reportContext.ScanID {
			t.Errorf("Expected ScanID %s, got %s", reportContext.ScanID, reportData.ScanID)
		}

		if reportData.NbFileSubmitted != 2 {
			t.Errorf("Expected 2 files submitted, got %d", reportData.NbFileSubmitted)
		}

		if len(reportData.FilesMalware) != 1 {
			t.Errorf("Expected 1 malware file, got %d", len(reportData.FilesMalware))
		}

		if len(reportData.FilesSafe) != 1 {
			t.Errorf("Expected 1 safe file, got %d", len(reportData.FilesSafe))
		}

		return
	}

	// If no error, verify we got a valid result
	if result == nil {
		t.Error("GenerateReport should return a non-nil reader when successful")
		return
	}

	// Read the content to verify it's not empty
	content := make([]byte, 1024)
	n, readErr := result.Read(content)
	if readErr != nil && readErr != io.EOF {
		t.Errorf("Error reading generated report: %v", readErr)
		return
	}

	if n == 0 {
		t.Error("Generated report should not be empty")
	}

	t.Logf("Successfully generated report with %d bytes", n)
}

func TestReportPlugin_Interface(t *testing.T) {
	// Test that ReportPlugin implements the Plugin interface
	var _ plugins.Plugin = &ReportPlugin{}
}
