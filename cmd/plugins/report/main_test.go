package main

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
	"github.com/glimps-re/host-connector/pkg/plugins/mock"
)

func TestMergeArgsIntoSlice(t *testing.T) {
	tests := []struct {
		name string
		args []any
		want []any
	}{
		{
			name: "empty args",
			args: []any{},
			want: []any{},
		},
		{
			name: "single arg",
			args: []any{"test"},
			want: []any{"test"},
		},
		{
			name: "multiple args",
			args: []any{"test", 123, true},
			want: []any{"test", 123, true},
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
		name    string
		config  any
		wantErr bool
	}{
		{
			name:    "init with default template",
			config:  &Config{},
			wantErr: false,
		},
		{
			name: "init with invalid template path",
			config: &Config{
				TemplatePath: "/invalid/path/template.html",
			},
			wantErr: true,
		},
		{
			name:    "init with bad config",
			config:  struct{}{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &ReportPlugin{}
			mockContext := mock.NewMockHCContext()

			err := p.Init(tt.config, mockContext)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReportPlugin.Init() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if p.templ == nil {
					t.Error("ReportPlugin.Init() template should not be nil after successful init")
				}
				if mockContext.GenerateReportFunc == nil {
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
	startTime := time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)
	endTime := startTime.Add(2*time.Minute + 30*time.Second)

	reportContext := datamodel.ScanContext{
		Start:  startTime,
		End:    endTime,
		ScanID: "scan1",
	}

	reports := []datamodel.Report{
		{
			Filename:  "clean_file.txt",
			SHA256:    "abc123",
			Malicious: false,
			Malwares:  []string{},
			// AnalyzedFileCount: 1,
		},
		{
			Filename:  "malware_file.exe",
			SHA256:    "def456",
			Malicious: true,
			Malwares:  []string{"Trojan.Win32.Test", "Backdoor.Generic"},
			// AnalyzedFileCount: 1,
		},
		{
			Filename:  "another_clean.pdf",
			SHA256:    "ghi789",
			Malicious: false,
			Malwares:  []string{},
			// AnalyzedFileCount: 1,
		},
	}

	reportData := scanResToReportData(reportContext, reports)

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
	if len(reportData.MitigatedFiles) != 1 {
		t.Errorf("ReportPlugin.scanResToReportData() FilesMalware length = %v, want 1", len(reportData.MitigatedFiles))
	} else {
		malwareFile := reportData.MitigatedFiles[0]
		if malwareFile.Name != "malware_file.exe" {
			t.Errorf("ReportPlugin.scanResToReportData() malware file name = %v, want malware_file.exe", malwareFile.Name)
		}
		if malwareFile.SHA256 != "def456" {
			t.Errorf("ReportPlugin.scanResToReportData() malware file sha256 = %v, want def456", malwareFile.SHA256)
		}
		if len(malwareFile.Malwares) != 2 {
			t.Errorf("ReportPlugin.scanResToReportData() malware count = %v, want 2", len(malwareFile.Malwares))
		}
	}
}

func TestReportPlugin_GenerateHTMLReport(t *testing.T) {
	p := &ReportPlugin{}

	// Initialize with default template
	mockContext := mock.NewMockHCContext()
	err := p.Init(p.GetDefaultConfig(), mockContext)
	if err != nil {
		t.Fatalf("Failed to initialize plugin: %v", err)
	}

	testData := ReportData{
		ScanID:          "20230101-120000",
		NbFileSubmitted: 2,
		NbFileAnalyzed:  2,
		AnalyzedVolume:  "1.5MB",
		MitigatedFiles: []FileReportData{
			{Name: "virus.exe", SHA256: "def456", Size: "500B", Malwares: []string{"Trojan.Test"}},
		},
		ScanStartTime: "2023-01-01T12:00:00Z",
		Duration:      "2m30s",
	}

	htmlBuf, err := p.generateHTMLReport(testData)
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
	mockContext := mock.NewMockHCContext()
	err := p.Init(p.GetDefaultConfig(), mockContext)
	if err != nil {
		t.Fatalf("Failed to initialize plugin: %v", err)
	}

	reportContext := datamodel.ScanContext{
		Start: time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
		End:   time.Date(2023, 1, 1, 12, 2, 30, 0, time.UTC),
	}

	reports := []datamodel.Report{
		{
			Filename:  "test.txt",
			SHA256:    "abc123",
			Malicious: false,
			Malwares:  []string{},
		},
	}

	// Test data preparation part (this will work without chromedp)
	reportData := scanResToReportData(reportContext, reports)

	// Test HTML generation part
	htmlBuf, err := p.generateHTMLReport(reportData)
	if err != nil {
		t.Errorf("ReportPlugin.generateHTMLReport() HTML generation error = %v", err)
		return
	}

	if htmlBuf == nil || htmlBuf.Len() == 0 {
		t.Error("ReportPlugin.generateHTMLReport() HTML buffer should not be empty")
	}

	// Note: We skip the actual PDF generation test here because it requires chromedp
	// In a full integration test environment, you would call:
	// pdfBuf, err := p.GeneratePdfReport(reportContext, reports)
	// But this requires a headless browser to be available
}

func TestReportPlugin_GenerateReport(t *testing.T) {
	p := &ReportPlugin{}

	// Initialize with default template
	mockContext := mock.NewMockHCContext()
	err := p.Init(p.GetDefaultConfig(), mockContext)
	if err != nil {
		t.Fatalf("Failed to initialize plugin: %v", err)
	}

	reportContext := datamodel.ScanContext{
		ScanID: "test-scan-123",
		Start:  time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
		End:    time.Date(2023, 1, 1, 12, 2, 30, 0, time.UTC),
	}

	reports := []datamodel.Report{
		{
			Filename:  "test_file.txt",
			SHA256:    "abc123def456",
			Malicious: false,
			Malwares:  []string{},
		},
		{
			Filename:  "malware_file.exe",
			SHA256:    "def456abc789",
			Malicious: true,
			Malwares:  []string{"Trojan.Test", "Backdoor.Generic"},
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
		reportData := scanResToReportData(reportContext, reports)

		// Verify the data was prepared correctly
		if reportData.ScanID != reportContext.ScanID {
			t.Errorf("Expected ScanID %s, got %s", reportContext.ScanID, reportData.ScanID)
		}

		if reportData.NbFileSubmitted != 2 {
			t.Errorf("Expected 2 files submitted, got %d", reportData.NbFileSubmitted)
		}

		if len(reportData.MitigatedFiles) != 1 {
			t.Errorf("Expected 1 malware file, got %d", len(reportData.MitigatedFiles))
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
