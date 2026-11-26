package handler

import (
	"context"
	"encoding/json"
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

// A rule that the SDK validation lets by but the connector refuses when it
// compiles the rules (it matches every path) is refused too, and the previous
// configuration is kept.
func TestHandler_ConfigureRefusesPathRulesTheConnectorCannotApply(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantKey string
	}{
		{"a skipped pattern that matches the empty string", `{"filepath_filter":{"skipped_paths":["a*"]}}`, "matches the empty string"},
		{"a forbidden pattern too large to compile", `{"filepath_filter":{"forbidden_paths":["((a{1000}){1000}){1000}"]}}`, "forbidden_paths[0]"},
		{"an empty pattern", `{"filepath_filter":{"skipped_paths":[""]}}`, "skipped_paths[0]"},
		{"a pattern in both lists", `{"filepath_filter":{"forbidden_paths":["x"],"skipped_paths":["x"]}}`, "also in forbidden_paths"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldConf := &config.Config{}
			h := &Handler{conf: oldConf, needSetup: true, configured: true}
			t.Cleanup(h.stopRejectReminder)
			err := h.Configure(t.Context(), json.RawMessage(tt.raw))
			if err == nil || !strings.Contains(err.Error(), tt.wantKey) {
				t.Fatalf("Configure() error = %v, want a refusal naming %q", err, tt.wantKey)
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
