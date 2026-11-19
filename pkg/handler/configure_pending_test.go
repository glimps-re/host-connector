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

func TestHandler_ConfigureRefusesPendingKey(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantKey string
	}{
		{"work_dir", `{"work_dir":"/w"}`, "work_dir"},
		{"move mode", `{"move":{"mode":"copy"}}`, "move.mode"},
		{"min_throughput", `{"move":{"min_throughput":"10MiB"}}`, "move.min_throughput"},
		{"max_tracked_memory", `{"monitoring":{"max_tracked_memory":"256MiB"}}`, "monitoring.max_tracked_memory"},
		{"max_tracked_dir_percent", `{"monitoring":{"max_tracked_dir_percent":25}}`, "monitoring.max_tracked_dir_percent"},
		{"too_big", `{"unanalyzable_policy":{"too_big":"pass"}}`, "unanalyzable_policy.too_big"},
		{"empty", `{"unanalyzable_policy":{"empty":"mitigate"}}`, "unanalyzable_policy.empty"},
		{"encrypted", `{"unanalyzable_policy":{"encrypted":"pass"}}`, "unanalyzable_policy.encrypted"},
		{"extract_error", `{"unanalyzable_policy":{"extract_error":"as_file"}}`, "unanalyzable_policy.extract_error"},
		{"quarantine zip", `{"quarantine":{"format":"zip"}}`, "quarantine.format"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := new(Handler)
			err := h.Configure(t.Context(), json.RawMessage(tt.raw))
			if !errors.Is(err, config.ErrNotImplemented) {
				t.Fatalf("Configure() error = %v, want ErrNotImplemented", err)
			}
			if !strings.Contains(err.Error(), tt.wantKey) {
				t.Errorf("Configure() error = %v, want key %q", err, tt.wantKey)
			}
		})
	}
}

func TestHandler_ConfigureInvalidJSON(t *testing.T) {
	h := new(Handler)
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
	h := &Handler{conf: oldConf, needSetup: true}
	err := h.Configure(t.Context(), json.RawMessage(`{"work_dir":"/w"}`))
	if !errors.Is(err, config.ErrNotImplemented) {
		t.Fatalf("Configure() error = %v, want ErrNotImplemented", err)
	}
	if len(rec.types) != 1 || rec.types[0] != HostConfigError {
		t.Errorf("NotifyError calls = %v, want exactly one %q", rec.types, HostConfigError)
	}
	if h.conf != oldConf {
		t.Error("h.conf changed after a refused Configure")
	}
	if !h.needSetup {
		t.Error("h.needSetup changed after a refused Configure")
	}
}
