package handler

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/glimps-re/host-connector/pkg/config"
)

func TestHandler_setupQuarantiner_zipWarnsPasswordPublic(t *testing.T) {
	tests := []struct {
		name     string
		format   string
		wantWarn bool
		wantErr  bool
	}{
		{name: "zip warns", format: "zip", wantWarn: true},
		{name: "tar does not", format: "tar"},
		{name: "default does not", format: ""},
		{name: "unknown format is refused", format: "rar", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs, console bytes.Buffer
			prevLogger, prevConsole := logger, consoleLogger
			logger = slog.New(slog.NewTextHandler(&logs, nil))
			consoleLogger = slog.New(slog.NewTextHandler(&console, nil))
			t.Cleanup(func() { logger, consoleLogger = prevLogger, prevConsole })

			conf := &config.Config{}
			conf.Actions.Quarantine = true
			conf.Quarantine.Location = t.TempDir()
			conf.Quarantine.Format = tt.format
			h := new(Handler)
			err := h.setupQuarantiner(t.Context(), conf)
			if (err != nil) != tt.wantErr {
				t.Fatalf("setupQuarantiner() error = %v, wantErr %t", err, tt.wantErr)
			}
			if h.Quarantiner != nil {
				t.Cleanup(func() {
					if e := h.Quarantiner.Close(); e != nil {
						t.Errorf("Close() error = %v", e)
					}
				})
			}
			for name, buf := range map[string]*bytes.Buffer{"log": &logs, "console": &console} {
				if got := strings.Contains(buf.String(), "must be considered public"); got != tt.wantWarn {
					t.Errorf("%s warning present = %t, want %t: %q", name, got, tt.wantWarn, buf.String())
				}
			}
		})
	}
}

func TestHandler_setupQuarantiner_warnsOnEveryApplication(t *testing.T) {
	var logs bytes.Buffer
	prev := logger
	logger = slog.New(slog.NewTextHandler(&logs, nil))
	t.Cleanup(func() { logger = prev })

	conf := &config.Config{}
	conf.Actions.Quarantine = true
	conf.Quarantine.Location = t.TempDir()
	conf.Quarantine.Format = "zip"
	h := new(Handler)
	for range 2 {
		if err := h.setupQuarantiner(t.Context(), conf); err != nil {
			t.Fatalf("setupQuarantiner() error = %v", err)
		}
	}
	t.Cleanup(func() {
		if err := h.Quarantiner.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
	if got := strings.Count(logs.String(), "must be considered public"); got != 2 {
		t.Errorf("warnings = %d, want 2 (start and Configure)", got)
	}

	conf.Quarantine.Format = "tar"
	logs.Reset()
	if err := h.setupQuarantiner(t.Context(), conf); err != nil {
		t.Fatalf("setupQuarantiner(tar) error = %v", err)
	}
	if strings.Contains(logs.String(), "must be considered public") {
		t.Error("no warning expected after switching back to tar")
	}
}
