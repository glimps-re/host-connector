package config

import (
	"testing"
	"time"

	"github.com/glimps-re/connector-integration/sdk"
)

func TestShutdownDurations(t *testing.T) {
	tests := []struct {
		name        string
		timeout     time.Duration
		total       time.Duration
		drain       time.Duration
		wantRefused bool
	}{
		{"unset gives the default", 0, 8 * time.Second, 4 * time.Second, false},
		{"8s is split 4/4", 8 * time.Second, 8 * time.Second, 4 * time.Second, false},
		{"90s keeps 30s for closing", 90 * time.Second, 90 * time.Second, 60 * time.Second, false},
		{"the minimum is accepted", 2 * time.Second, 2 * time.Second, time.Second, false},
		{"under the minimum is refused", time.Second, 0, 0, true},
		{"negative is refused", -time.Second, 0, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Config{ShutdownTimeout: sdk.Duration(tt.timeout)}
			total, drain, err := c.ShutdownDurations()
			if (err != nil) != tt.wantRefused {
				t.Fatalf("error = %v, want refused = %v", err, tt.wantRefused)
			}
			if total != tt.total || drain != tt.drain {
				t.Errorf("ShutdownDurations() = %s, %s, want %s, %s", total, drain, tt.total, tt.drain)
			}
		})
	}
}
