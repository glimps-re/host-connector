package handler

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/glimps-re/connector-integration/sdk"
	"github.com/glimps-re/host-connector/pkg/config"
	"github.com/glimps-re/host-connector/pkg/scanner"
)

// A modification_delay under one second is accepted, with a warning when the
// monitor is made that says what it risks; one second and over starts without it.
// A monitor that cannot be made says nothing about its delay.
func TestNewMonitor_aModificationDelayUnderASecondWarns(t *testing.T) {
	tests := []struct {
		name        string
		delay       time.Duration
		noPeriod    bool
		wantWarns   int
		wantErr     error
		wantDelayNs string
	}{
		{name: "zero", delay: 0, wantWarns: 1, wantDelayNs: `"modification_delay":0`},
		{name: "a millisecond", delay: time.Millisecond, wantWarns: 1, wantDelayNs: `"modification_delay":1000000`},
		{name: "just under a second", delay: 999 * time.Millisecond, wantWarns: 1, wantDelayNs: `"modification_delay":999000000`},
		{name: "exactly a second", delay: time.Second},
		{name: "just over a second", delay: time.Second + time.Millisecond},
		{name: "the default", delay: 30 * time.Second},
		{name: "a short delay on a monitor that cannot be made", delay: 0, noPeriod: true, wantErr: config.ErrWatcherNeedsPeriod},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := captureHandlerLogs(t)
			period := sdk.Duration(time.Hour)
			if tt.noPeriod {
				period = 0
			}
			m, err := NewMonitor(func(string, scanner.FileIdentity) (bool, error) { return true, nil },
				Config{DisableWatcher: true, Period: period, ModDelay: sdk.Duration(tt.delay)})
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("NewMonitor() error = %v, want %v: a short delay is accepted", err, tt.wantErr)
			}
			if m != nil {
				t.Cleanup(func() {
					if e := m.Close(); e != nil {
						t.Errorf("Close() error = %v", e)
					}
				})
			}
			if got := strings.Count(buf.String(), "modification_delay is short"); got != tt.wantWarns {
				t.Fatalf("%d warnings for %v, want %d: %s", got, tt.delay, tt.wantWarns, buf)
			}
			assertWarnAttributes(t, buf, tt.wantDelayNs)
		})
	}
}

// The warning carries the delay it is about and the minimum that is recommended
// (durations are nanoseconds in the JSON of the log).
func assertWarnAttributes(t *testing.T, buf *bytes.Buffer, wantDelay string) {
	t.Helper()
	if wantDelay == "" {
		return
	}
	if !strings.Contains(buf.String(), wantDelay) {
		t.Errorf("the warning lacks %s: %s", wantDelay, buf)
	}
	if want := `"recommended_minimum":1000000000`; !strings.Contains(buf.String(), want) {
		t.Errorf("the warning lacks %s: %s", want, buf)
	}
}
