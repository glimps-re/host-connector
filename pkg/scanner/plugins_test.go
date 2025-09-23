package scanner

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
	quarantinermock "github.com/glimps-re/host-connector/pkg/quarantine/mock"
	"github.com/google/go-cmp/cmp"
)

func TestConnector_GenerateReport(t *testing.T) {
	tests := []struct {
		name string // description of this test case
		// Named input parameters for receiver constructor.
		config Config
		// Named input parameters for target function.
		reports   []datamodel.Report
		generator plugins.GenerateReport
		want      string
		wantErr   bool
	}{
		{
			name:    "default",
			reports: []datamodel.Report{{Filename: "test", SHA256: "123456"}},
			want:    `[{"filename":"test","sha256":"123456","malicious":false}]`,
		},
		{
			name:    "csv",
			reports: []datamodel.Report{{Filename: "test", SHA256: "123456"}, {Filename: "test2", SHA256: "123457", Malicious: true}},
			generator: func(reportContext datamodel.ScanContext, reports []datamodel.Report) (io.Reader, error) {
				buffer := &bytes.Buffer{}
				fmt.Fprintf(buffer, "file,sha256,malicious\n")
				for _, r := range reports {
					fmt.Fprintf(buffer, "%s,%s,%v\n", r.Filename, r.SHA256, r.Malicious)
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
			c := NewConnector(tt.config, &quarantinermock.QuarantineMock{}, &mockSubmitter{})
			if tt.generator != nil {
				c.RegisterGenerateReport(tt.generator)
			}
			got, gotErr := c.GenerateReport(datamodel.ScanContext{}, tt.reports)
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
	c.RegisterOnStartScanFile(func(n, s string) {
		calls = append(calls, fmt.Sprintf("func1(%v, %v)", n, s))
	})
	c.RegisterOnStartScanFile(func(n, s string) {
		calls = append(calls, fmt.Sprintf("func2(%v, %v)", n, s))
	})
	c.onStartScanFile("test_2", "testsha256_2")
	want := []string{"func1(test_2, testsha256_2)", "func2(test_2, testsha256_2)"}
	if !cmp.Equal(calls, want) {
		t.Errorf("Connector.onStartScanfile() got %v instead of %v,\n%s", calls, want, cmp.Diff(calls, want))
	}
}

func TestOnFileScanned(t *testing.T) {
	c := Connector{}
	c.onFileScanned("test", "testsha256", datamodel.Result{})
	calls := []string{}
	c.RegisterOnFileScanned(func(n, s string, _ datamodel.Result) (newRes *datamodel.Result) {
		calls = append(calls, fmt.Sprintf("func1(%v, %v)", n, s))
		return
	})
	c.RegisterOnFileScanned(func(n, s string, _ datamodel.Result) (newRes *datamodel.Result) {
		calls = append(calls, fmt.Sprintf("func2(%v, %v)", n, s))
		return
	})
	c.RegisterOnFileScanned(func(n, s string, _ datamodel.Result) (newRes *datamodel.Result) {
		calls = append(calls, fmt.Sprintf("func3(%v, %v)", n, s))
		return
	})
	c.onFileScanned("test_2", "testsha256_2", datamodel.Result{})
	want := []string{"func1(test_2, testsha256_2)", "func2(test_2, testsha256_2)", "func3(test_2, testsha256_2)"}
	if !cmp.Equal(calls, want) {
		t.Errorf("Connector.onFileScanned() got %v instead of %v,\n%s", calls, want, cmp.Diff(calls, want))
	}
}

func TestOnReport(t *testing.T) {
	c := Connector{}
	c.onReport(nil)
	calls := []string{}
	c.RegisterOnReport(func(*datamodel.Report) {
		calls = append(calls, "func1()")
	})
	c.RegisterOnReport(func(*datamodel.Report) {
		calls = append(calls, "func2()")
	})
	c.RegisterOnReport(func(*datamodel.Report) {
		calls = append(calls, "func3()")
	})
	c.onReport(nil)
	want := []string{"func1()", "func2()", "func3()"}
	if !cmp.Equal(calls, want) {
		t.Errorf("Connector.onReport() got %v instead of %v,\n%s", calls, want, cmp.Diff(calls, want))
	}
}
