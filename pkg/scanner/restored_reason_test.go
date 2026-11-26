package scanner

import (
	"context"
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
)

func TestHandleRestoredFile_theNotAnalyzedReason(t *testing.T) {
	tests := []struct {
		name       string
		plugin     func(r datamodel.Result) *datamodel.Result
		wantReason datamodel.NotAnalyzedReason
		wantRest   bool
	}{
		{"delivered as restored", nil, datamodel.NotAnalyzedRestored, true},
		{
			"a plugin that detects it", func(r datamodel.Result) *datamodel.Result {
				return &datamodel.Result{Filename: r.Filename, Location: r.Location, SHA256: r.SHA256, Malware: true, Malwares: []string{"m"}}
			},
			"", true,
		},
		{
			"a plugin result with a reason", func(r datamodel.Result) *datamodel.Result {
				return &datamodel.Result{Filename: r.Filename, Location: r.Location, SHA256: r.SHA256, NotAnalyzedReason: datamodel.NotAnalyzedPolicySkipped}
			},
			datamodel.NotAnalyzedPolicySkipped, true,
		},
		{
			"a plugin result with an analysis error", func(r datamodel.Result) *datamodel.Result {
				return &datamodel.Result{Filename: r.Filename, Location: r.Location, SHA256: r.SHA256, AnalysisError: "engine failed"}
			},
			"", true,
		},
		{
			"a plugin result in error", func(r datamodel.Result) *datamodel.Result {
				return &datamodel.Result{Filename: r.Filename, Location: r.Location, SHA256: r.SHA256, Error: context.Canceled}
			},
			"", true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _, file, _ := newPathCheckFixture(t, false)
			if tt.plugin != nil {
				c.RegisterOnFileScanned(func(_, _ string, r datamodel.Result) *datamodel.Result { return tt.plugin(r) })
			}
			var got datamodel.Result
			c.action = &MockAction{HandleMock: func(_ context.Context, _ Source, r datamodel.Result, _ *datamodel.Report) error {
				got = r
				return nil
			}}
			if err := c.handleRestoredFile(file, shaOf("some content"), 12, idOf(t, file), nil, nil); err != nil {
				t.Fatal(err)
			}
			if got.NotAnalyzedReason != tt.wantReason || got.Restored != tt.wantRest {
				t.Errorf("reason = %q, restored = %t, want %q, %t", got.NotAnalyzedReason, got.Restored, tt.wantReason, tt.wantRest)
			}
			if tt.wantReason == datamodel.NotAnalyzedRestored {
				report := &datamodel.Report{}
				if err := (&ReportAction{}).Handle(t.Context(), Source{Path: file}, got, report); err != nil {
					t.Fatal(err)
				}
				if report.NotAnalyzedReason != datamodel.NotAnalyzedRestored || !report.HasBeenRestored {
					t.Errorf("report reason = %q, restored = %t", report.NotAnalyzedReason, report.HasBeenRestored)
				}
			}
		})
	}
}
