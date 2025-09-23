package scanner

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	"github.com/glimps-re/host-connector/pkg/plugins"
	"github.com/glimps-re/host-connector/pkg/report"
	"github.com/google/go-cmp/cmp"
)

func TestConnector_GenerateReport(t *testing.T) {
	tests := []struct {
		name string // description of this test case
		// Named input parameters for receiver constructor.
		config Config
		// Named input parameters for target function.
		reports   []report.Report
		generator plugins.GenerateReport
		want      string
		wantErr   bool
	}{
		{
			name:    "default",
			reports: []report.Report{{FileName: "test", Sha256: "123456"}},
			want:    `[{"file-name":"test","sha256":"123456","malicious":false}]`,
		},
		{
			name:    "csv",
			reports: []report.Report{{FileName: "test", Sha256: "123456"}, {FileName: "test2", Sha256: "123457", Malicious: true}},
			generator: func(reportContext report.ScanContext, reports []report.Report) (io.Reader, error) {
				buffer := &bytes.Buffer{}
				fmt.Fprintf(buffer, "file,sha256,malicious\n")
				for _, r := range reports {
					fmt.Fprintf(buffer, "%s,%s,%v\n", r.FileName, r.Sha256, r.Malicious)
				}
				return buffer, nil
			},
			want: `file,sha256,malicious
test,123456,false
test2,123457,true`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewConnector(tt.config)
			if tt.generator != nil {
				c.RegisterGenerateReport(tt.generator)
			}
			got, gotErr := c.GenerateReport(report.ScanContext{}, tt.reports)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("GenerateReport() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("GenerateReport() succeeded unexpectedly")
			}
			buffer := &bytes.Buffer{}
			if _, err := io.Copy(buffer, got); err != nil {
				t.Errorf("GenerateReport(), could not read io.Readee, error: %s", err)
				return
			}
			if strings.Trim(buffer.String(), "\n") != tt.want {
				t.Errorf("GenerateReport() = %s", cmp.Diff(buffer.String(), tt.want))
			}
		})
	}
}

func TestOnStartScanfile(t *testing.T) {
	c := Connector{}
	c.onStartScanFile("test", "testsha256")
	calls := []string{}
	c.RegisterOnStartScanFile(func(n, s string) *gdetect.Result {
		calls = append(calls, fmt.Sprintf("func1(%v, %v)", n, s))
		return nil
	})
	c.RegisterOnStartScanFile(func(n, s string) *gdetect.Result {
		calls = append(calls, fmt.Sprintf("func2(%v, %v)", n, s))
		return &gdetect.Result{}
	})
	c.RegisterOnStartScanFile(func(n, s string) *gdetect.Result {
		// func3 must not be called due to func2 return
		calls = append(calls, fmt.Sprintf("func3(%v, %v)", n, s))
		return nil
	})
	c.onStartScanFile("test_2", "testsha256_2")
	want := []string{"func1(test_2, testsha256_2)", "func2(test_2, testsha256_2)"}
	if !cmp.Equal(calls, want) {
		t.Errorf("Connector.onStartScanfile() got %v instead of %v,\n%s", calls, want, cmp.Diff(calls, want))
	}
}

func TestOnFileScanned(t *testing.T) {
	c := Connector{}
	c.onFileScanned("test", "testsha256", gdetect.Result{}, nil)
	calls := []string{}
	c.RegisterOnFileScanned(func(n, s string, _ gdetect.Result, _ error) {
		calls = append(calls, fmt.Sprintf("func1(%v, %v)", n, s))
	})
	c.RegisterOnFileScanned(func(n, s string, _ gdetect.Result, _ error) {
		calls = append(calls, fmt.Sprintf("func2(%v, %v)", n, s))
	})
	c.RegisterOnFileScanned(func(n, s string, _ gdetect.Result, _ error) {
		calls = append(calls, fmt.Sprintf("func3(%v, %v)", n, s))
	})
	c.onFileScanned("test_2", "testsha256_2", gdetect.Result{}, nil)
	want := []string{"func1(test_2, testsha256_2)", "func2(test_2, testsha256_2)", "func3(test_2, testsha256_2)"}
	if !cmp.Equal(calls, want) {
		t.Errorf("Connector.onFileScanned() got %v instead of %v,\n%s", calls, want, cmp.Diff(calls, want))
	}
}

func TestOnReport(t *testing.T) {
	c := Connector{}
	c.onReport(nil)
	calls := []string{}
	c.RegisterOnReport(func(*report.Report) {
		calls = append(calls, "func1()")
	})
	c.RegisterOnReport(func(*report.Report) {
		calls = append(calls, "func2()")
	})
	c.RegisterOnReport(func(*report.Report) {
		calls = append(calls, "func3()")
	})
	c.onReport(nil)
	want := []string{"func1()", "func2()", "func3()"}
	if !cmp.Equal(calls, want) {
		t.Errorf("Connector.onReport() got %v instead of %v,\n%s", calls, want, cmp.Diff(calls, want))
	}
}
