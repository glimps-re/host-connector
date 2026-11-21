package handler

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/glimps-re/connector-integration/sdk/events"
	"github.com/glimps-re/host-connector/pkg/config"
)

func TestHandler_ConfigureRefusesUnknownExtractErrorPolicy(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantKey string
	}{
		{"extract_error", `{"unanalyzable_policy":{"extract_error":"pass"}}`, "extract_error"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := new(Handler)
			err := h.Configure(t.Context(), json.RawMessage(tt.raw))
			if err == nil || !strings.Contains(err.Error(), tt.wantKey) {
				t.Errorf("Configure() error = %v, want key %q", err, tt.wantKey)
			}
		})
	}
}

// Between the SDK keys and the code that enforces them, a setting that nothing
// enforces is refused, and the previous configuration is kept.
func TestHandler_ConfigureRefusesWhatNothingEnforcesYet(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantKey string
	}{
		{"analysis_error mitigate", `{"unanalyzable_policy":{"analysis_error":"mitigate"}}`, "unanalyzable_policy.analysis_error"},
		{"analysis_error pass", `{"unanalyzable_policy":{"analysis_error":"pass"}}`, "unanalyzable_policy.analysis_error"},
		{"forbidden paths", `{"filepath_filter":{"forbidden_paths":["a"]}}`, "filepath_filter"},
		{"skipped paths", `{"filepath_filter":{"skipped_paths":["a"]}}`, "filepath_filter"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldConf := &config.Config{}
			h := &Handler{conf: oldConf, needSetup: true, configured: true}
			t.Cleanup(h.stopRejectReminder)
			err := h.Configure(t.Context(), json.RawMessage(tt.raw))
			if !errors.Is(err, config.ErrNotImplemented) || !strings.Contains(err.Error(), tt.wantKey) {
				t.Fatalf("Configure() error = %v, want ErrNotImplemented naming %q", err, tt.wantKey)
			}
			if h.conf != oldConf {
				t.Error("h.conf changed after a refused Configure")
			}
		})
	}
}

func TestHandler_ConfigureInvalidJSON(t *testing.T) {
	h := new(Handler)
	t.Cleanup(h.Close)
	if err := h.Configure(t.Context(), json.RawMessage(`{"work_dir":`)); err == nil {
		t.Fatal("Configure() error = nil, want JSON error")
	}
}

type recordingEvents struct {
	events.NoopEventHandler
	types []events.ErrorEventType
}

func (r *recordingEvents) NotifyError(_ context.Context, errorType events.ErrorEventType, _ error) error {
	r.types = append(r.types, errorType)
	return nil
}

func TestHandler_ConfigureRefusalNotifiesAndKeepsState(t *testing.T) {
	rec := &recordingEvents{}
	prev := eventHandler
	eventHandler = rec
	t.Cleanup(func() { eventHandler = prev })

	oldConf := &config.Config{}
	oldConf.Debug = true
	h := &Handler{conf: oldConf, needSetup: true, configured: true}
	t.Cleanup(h.stopRejectReminder)
	err := h.Configure(t.Context(), json.RawMessage(`{"unanalyzable_policy":{"extract_error":"pass"}}`))
	if err == nil {
		t.Fatal("Configure() error = nil, want a refusal")
	}
	if len(rec.types) != 1 || rec.types[0] != HostConfigRejected {
		t.Errorf("NotifyError calls = %v, want exactly one %q", rec.types, HostConfigRejected)
	}
	if h.conf != oldConf {
		t.Error("h.conf changed after a refused Configure")
	}
	if !h.needSetup {
		t.Error("h.needSetup changed after a refused Configure")
	}
}
