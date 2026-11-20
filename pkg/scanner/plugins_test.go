package scanner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"strings"
	"testing"

	gdetectMock "github.com/glimps-re/go-gdetect/pkg/gdetect/mock"
	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
	"github.com/glimps-re/host-connector/pkg/quarantine"
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
			generator: func(_ context.Context, reportContext datamodel.ScanContext, reports iter.Seq2[datamodel.Report, error]) (plugins.GeneratedReport, error) {
				buffer := &bytes.Buffer{}
				fmt.Fprintf(buffer, "file,sha256,malicious\n")
				for r, err := range reports {
					if err != nil {
						return plugins.GeneratedReport{}, err
					}
					fmt.Fprintf(buffer, "%s,%s,%v\n", r.Filename, r.SHA256, r.Malicious)
				}
				return plugins.GeneratedReport{Content: io.NopCloser(buffer), Extension: ".csv"}, nil
			},
			want: `file,sha256,malicious
test,123456,false
test2,123457,true`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, connErr := NewConnector(tt.config, &quarantinermock.QuarantineMock{}, &gdetectMock.MockGDetectSubmitter{})
			if connErr != nil {
				t.Fatalf("could not create connector: %v", connErr)
			}
			if tt.generator != nil {
				c.RegisterGenerateReport(tt.generator)
			}
			got, gotErr := c.GenerateReport(t.Context(), datamodel.ScanContext{}, datamodel.ReportsSeq(tt.reports))
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
			if _, err := io.Copy(buffer, got.Content); err != nil {
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

func TestOnFileScanned_chain(t *testing.T) {
	setError := func(res datamodel.Result) *datamodel.Result {
		res.Error = errors.New("plugin error")
		return &res
	}
	tests := []struct {
		name                  string
		register              func(c *Connector, seen *[]datamodel.Result)
		input                 datamodel.Result
		wantNil               bool
		wantError             bool
		wantMal               bool
		wantAnErr             string
		wantSeen              int
		wantObserverSeesError bool
	}{
		{
			name: "modifier then observer: observer still called with modified result",
			register: func(c *Connector, seen *[]datamodel.Result) {
				c.RegisterOnFileScanned(func(_, _ string, r datamodel.Result) *datamodel.Result { return setError(r) })
				c.RegisterOnFileScanned(func(_, _ string, r datamodel.Result) *datamodel.Result {
					*seen = append(*seen, r)
					return nil
				})
			},
			wantError:             true,
			wantSeen:              1,
			wantObserverSeesError: true,
		},
		{
			name: "observer then modifier",
			register: func(c *Connector, seen *[]datamodel.Result) {
				c.RegisterOnFileScanned(func(_, _ string, r datamodel.Result) *datamodel.Result {
					*seen = append(*seen, r)
					return nil
				})
				c.RegisterOnFileScanned(func(_, _ string, r datamodel.Result) *datamodel.Result { return setError(r) })
			},
			wantError: true,
			wantSeen:  1,
		},
		{
			name: "no change returns nil",
			register: func(c *Connector, _ *[]datamodel.Result) {
				c.RegisterOnFileScanned(func(_, _ string, _ datamodel.Result) *datamodel.Result { return nil })
			},
			wantNil: true,
		},
		{
			name:  "plugin clearing Error is restored",
			input: datamodel.Result{Error: errors.New("core error")},
			register: func(c *Connector, _ *[]datamodel.Result) {
				c.RegisterOnFileScanned(func(_, _ string, r datamodel.Result) *datamodel.Result {
					r.Error = nil
					return &r
				})
			},
			wantError: true,
		},
		{
			name:  "plugin clearing Malware and AnalysisError is restored",
			input: datamodel.Result{Malware: true, AnalysisError: "boom"},
			register: func(c *Connector, _ *[]datamodel.Result) {
				c.RegisterOnFileScanned(func(_, _ string, r datamodel.Result) *datamodel.Result {
					r.Malware = false
					r.AnalysisError = ""
					return &r
				})
			},
			wantMal:   true,
			wantAnErr: "boom",
		},
		{
			name: "plugin hardening Malware is kept",
			register: func(c *Connector, _ *[]datamodel.Result) {
				c.RegisterOnFileScanned(func(_, _ string, r datamodel.Result) *datamodel.Result {
					r.Malware = true
					return &r
				})
			},
			wantMal: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Connector{}
			var seen []datamodel.Result
			tt.register(c, &seen)
			got := c.onFileScanned("f", "sha", tt.input)
			if tt.wantNil {
				if got != nil {
					t.Fatalf("onFileScanned() = %v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Fatal("onFileScanned() = nil, want a result")
			}
			if (got.Error != nil) != tt.wantError || got.Malware != tt.wantMal || got.AnalysisError != tt.wantAnErr {
				t.Errorf("onFileScanned() = %+v", got)
			}
			if len(seen) != tt.wantSeen {
				t.Errorf("observer called %d times, want %d", len(seen), tt.wantSeen)
			}
			if tt.wantObserverSeesError && (len(seen) == 0 || seen[0].Error == nil) {
				t.Error("observer did not receive the modified result")
			}
		})
	}
}

func TestCheckPluginNames(t *testing.T) {
	if err := checkPluginNames([]PluginConfig{{Name: "a"}, {Name: "b"}}); err != nil {
		t.Errorf("checkPluginNames() unexpected error: %v", err)
	}
	if err := checkPluginNames([]PluginConfig{{Name: "a"}, {Name: "b"}, {Name: "a"}}); !errors.Is(err, errDuplicatePlugin) {
		t.Errorf("checkPluginNames() error = %v, want %v", err, errDuplicatePlugin)
	}
}

func TestOnScanFile_waiverAndRefusal(t *testing.T) {
	waiver := func(tag string) plugins.OnScanFile {
		return func(string, string, string, bool) *datamodel.Result {
			return &datamodel.Result{Filename: tag, Score: -500}
		}
	}
	refusal := func(tag string, r datamodel.Result) plugins.OnScanFile {
		r.Filename = tag
		return func(string, string, string, bool) *datamodel.Result { return &r }
	}
	malware := datamodel.Result{Malware: true, Score: 1000}
	tests := []struct {
		name string
		cbs  []plugins.OnScanFile
		want string
	}{
		{name: "none", want: ""},
		{name: "waiver then refusal: refusal wins", cbs: []plugins.OnScanFile{waiver("w"), refusal("r", malware)}, want: "r"},
		{name: "refusal then waiver: refusal wins", cbs: []plugins.OnScanFile{refusal("r", malware), waiver("w")}, want: "r"},
		{name: "two waivers: first", cbs: []plugins.OnScanFile{waiver("w1"), waiver("w2")}, want: "w1"},
		{name: "two refusals: first", cbs: []plugins.OnScanFile{refusal("r1", malware), refusal("r2", malware)}, want: "r1"},
		{
			name: "AnalysisError without Malware is a refusal",
			cbs:  []plugins.OnScanFile{waiver("w"), refusal("ae", datamodel.Result{AnalysisError: "boom"})},
			want: "ae",
		},
		{
			name: "Error without Malware is a refusal",
			cbs:  []plugins.OnScanFile{waiver("w"), refusal("e", datamodel.Result{Error: errors.New("boom")})},
			want: "e",
		},
		{name: "nil results are skipped", cbs: []plugins.OnScanFile{
			func(string, string, string, bool) *datamodel.Result { return nil }, waiver("w"),
		}, want: "w"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Connector{onScanFileCbs: tt.cbs}
			got := c.onScanFile("f", "/loc/f", "sha", false)
			switch {
			case tt.want == "" && got != nil:
				t.Errorf("onScanFile() = %+v, want nil", got)
			case tt.want != "" && (got == nil || got.Filename != tt.want):
				t.Errorf("onScanFile() = %+v, want %s", got, tt.want)
			}
		})
	}
}

func TestOnScanFile_allCallbacksCalledAfterWaiver(t *testing.T) {
	calls := 0
	c := &Connector{onScanFileCbs: []plugins.OnScanFile{
		func(string, string, string, bool) *datamodel.Result { calls++; return &datamodel.Result{} },
		func(string, string, string, bool) *datamodel.Result { calls++; return nil },
	}}
	if got := c.onScanFile("f", "/f", "sha", false); got == nil {
		t.Error("onScanFile() = nil, want the waiver")
	}
	if calls != 2 {
		t.Errorf("callbacks called %d times, want 2", calls)
	}
}

func TestRestoreHardened_malwareDetails(t *testing.T) {
	prev := datamodel.Result{Malware: true, Malwares: []string{"Evil"}, MalwareReason: datamodel.MalwareDetected, Score: 900}
	c := &Connector{}
	c.RegisterOnFileScanned(func(_, _ string, r datamodel.Result) *datamodel.Result {
		return &datamodel.Result{Filename: r.Filename}
	})
	got := c.onFileScanned("f", "sha", prev)
	if got == nil || !got.Malware || len(got.Malwares) != 1 || got.MalwareReason != datamodel.MalwareDetected || got.Score != 900 {
		t.Errorf("onFileScanned() = %+v, malware details must be restored", got)
	}
}

func TestScanFile_skipsQuarantineTempFile(t *testing.T) {
	c := &Connector{}
	if err := c.ScanFile(t.Context(), "/nonexistent/"+quarantine.TempPrefix+"sample-0123456789abcdef"); err != nil {
		t.Errorf("ScanFile() error = %v, want nil: temporary files are ignored before any access", err)
	}
}
