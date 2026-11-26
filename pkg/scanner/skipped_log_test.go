package scanner

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
)

func TestMarkPolicySkipped_logsTheReasonOfTheWaiver(t *testing.T) {
	tests := []struct {
		name string
		in   datamodel.Result
		want string
	}{
		{"a plugin waiver", datamodel.Result{}, `"reason":"policy-skipped"`},
		{"a skipped path", datamodel.Result{NotAnalyzedReason: datamodel.NotAnalyzedSkippedPath}, `"reason":"skipped-path"`},
		{"a skipped type", datamodel.Result{NotAnalyzedReason: datamodel.NotAnalyzedSkippedType}, `"reason":"skipped-type"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			prev := logger
			logger = slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
			t.Cleanup(func() { logger = prev })
			r := tt.in
			markPolicySkipped(&r, "/in/f")
			if out := buf.String(); !strings.Contains(out, "file passed without analysis") || !strings.Contains(out, tt.want) {
				t.Errorf("log = %q, want a warning with %s", out, tt.want)
			}
		})
	}
}
