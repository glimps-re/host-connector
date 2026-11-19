package handler

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/glimps-re/host-connector/pkg/config"
)

func TestHandler_SetupRefusesPendingKey(t *testing.T) {
	h := new(Handler)
	conf := &config.Config{}
	conf.Move.Mode = "copy"
	err := h.setup(t.Context(), conf)
	if !errors.Is(err, config.ErrNotImplemented) {
		t.Fatalf("setup() error = %v, want ErrNotImplemented", err)
	}
	if !strings.Contains(err.Error(), "move.mode") {
		t.Errorf("setup() error = %v, want key name", err)
	}
}

func TestHandler_RefusesInvalidEnum(t *testing.T) {
	tests := []struct {
		name  string
		json  string
		field string
	}{
		{"too_big bogus", `{"unanalyzable_policy":{"too_big":"bogus"}}`, "too_big"},
		{"empty error", `{"unanalyzable_policy":{"empty":"error"}}`, "empty"},
		{"move mode link", `{"move":{"mode":"link"}}`, "mode"},
		{"quarantine format gz", `{"quarantine":{"format":"gz"}}`, "format"},
		{"percent 101", `{"monitoring":{"max_tracked_dir_percent":101}}`, "max_tracked_dir_percent"},
	}
	for _, tt := range tests {
		t.Run("Configure/"+tt.name, func(t *testing.T) {
			h := new(Handler)
			err := h.Configure(t.Context(), json.RawMessage(tt.json))
			if err == nil || !strings.Contains(err.Error(), tt.field) {
				t.Fatalf("Configure() error = %v, want field %q", err, tt.field)
			}
		})
		t.Run("setup/"+tt.name, func(t *testing.T) {
			conf := new(config.Config)
			if err := json.Unmarshal([]byte(tt.json), conf); err != nil {
				t.Fatal(err)
			}
			err := new(Handler).setup(t.Context(), conf)
			if err == nil || !strings.Contains(err.Error(), tt.field) {
				t.Fatalf("setup() error = %v, want field %q", err, tt.field)
			}
		})
	}
}
