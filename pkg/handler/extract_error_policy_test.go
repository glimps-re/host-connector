package handler

import (
	"testing"

	"github.com/glimps-re/host-connector/pkg/config"
)

func TestReportExtractErrorPolicy(t *testing.T) {
	tests := []struct {
		name      string
		policy    string
		wantError bool
	}{
		{"as_file", "as_file", true},
		{"error", "error", false},
		{"default", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := recordEvents(t)
			logs := captureHandlerLogs(t)
			conf := &config.Config{}
			conf.UnanalyzablePolicy.ExtractError = tt.policy
			h := new(Handler)
			h.reportExtractErrorPolicy(t.Context(), conf)
			h.reportExtractErrorPolicy(t.Context(), conf)
			errs := rec.find("error", HostExtractErrorAsFile)
			resolved := rec.find("resolution", HostExtractErrorAsFile)
			if tt.wantError && (len(errs) != 2 || len(resolved) != 0) {
				t.Errorf("errors %d, resolutions %d, want the event raised at each application", len(errs), len(resolved))
			}
			if !tt.wantError && (len(errs) != 0 || len(resolved) != 2) {
				t.Errorf("errors %d, resolutions %d, want the event resolved", len(errs), len(resolved))
			}
			if got := logs.Len() > 0; got != tt.wantError {
				t.Errorf("warning logged = %t, want %t: %s", got, tt.wantError, logs)
			}
		})
	}
}

func TestConfigure_asFileRaisesTheEventAndErrorResolvesIt(t *testing.T) {
	rec := recordEvents(t)
	watched := t.TempDir()
	h := newRunningHandler(t, validConf(t, watched))

	next := validConf(t, watched)
	next.UnanalyzablePolicy.ExtractError = "as_file"
	if err := h.Configure(t.Context(), rawConf(t, next)); err != nil {
		t.Fatalf("Configure(as_file) error = %v", err)
	}
	if got := len(rec.find("error", HostExtractErrorAsFile)); got != 1 {
		t.Fatalf("events after as_file = %d, want 1", got)
	}

	back := validConf(t, watched)
	back.UnanalyzablePolicy.ExtractError = "error"
	if err := h.Configure(t.Context(), rawConf(t, back)); err != nil {
		t.Fatalf("Configure(error) error = %v", err)
	}
	if got := len(rec.find("resolution", HostExtractErrorAsFile)); got != 1 {
		t.Errorf("resolutions after error = %d, want 1", got)
	}
}
