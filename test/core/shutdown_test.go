//go:build linux && (e2e || e2e_core)

package core

import (
	"errors"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/glimps-re/host-connector/test/internal/fakes/gmalware"
	"github.com/glimps-re/host-connector/test/internal/harness"
)

// A second signal while the stop waits ends the process at once.
func TestShutdown_aSecondSignalStopsImmediately(t *testing.T) {
	tests := []struct {
		name    string
		timeout string
	}{
		{name: "a second SIGTERM under a 30 s shutdown timeout", timeout: "30s"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := gmalware.New(t)
			g.Hang()
			in := harness.Start(t, g, harness.Options{Timeout: tt.timeout})
			in.Drop(t, "a.txt", []byte("some content to analyze"))
			in.WaitFor(t, "the analysis to start", func() bool { return g.Submitted.Load() > 0 })
			in.Signal(t, syscall.SIGTERM)
			in.WaitFor(t, "the stop to be under way", func() bool { return in.LogHas("stop requested") })
			in.Signal(t, syscall.SIGTERM)
			took, err := in.Wait(t, 3*time.Second)
			t.Logf("second signal handled in %s", took)
			var exit *exec.ExitError
			if !errors.As(err, &exit) {
				t.Fatalf("wait = %v, want the process killed by a signal", err)
			}
			if status, ok := exit.Sys().(syscall.WaitStatus); !ok || !status.Signaled() || status.Signal() != syscall.SIGTERM {
				t.Errorf("exit status = %v, want ended by SIGTERM (the default action, not the handler)", exit)
			}
		})
	}
}

func TestShutdown_aTooShortTimeoutRefusesToStart(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		scenario harness.Scenario
	}{
		{name: "a 1 s shutdown timeout", scenario: harness.Scenario{Timeout: "1s", WantRefused: "shutdown_timeout"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			harness.Run(t, tt.scenario)
		})
	}
}

// SIGINT (Ctrl+C) stops the connector the same way as SIGTERM.
func TestShutdown_sigintStopsLikeSigterm(t *testing.T) {
	tests := []struct {
		name   string
		signal syscall.Signal
	}{
		{name: "SIGINT", signal: syscall.SIGINT},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := gmalware.New(t)
			g.Hang()
			in := harness.Start(t, g, harness.Options{Timeout: "4s"})
			in.Drop(t, "a.txt", []byte("some content to analyze"))
			in.WaitFor(t, "the analysis to start", func() bool { return g.Submitted.Load() > 0 })
			in.Signal(t, tt.signal)
			if _, err := in.Wait(t, 6*time.Second); err != nil {
				t.Errorf("exit = %v, want code 0; log:\n%s", err, in.Stderr.String())
			}
			if m := harness.GlobOne(t, filepath.Join(in.Work, "gmhost-*")); len(m) != 0 {
				t.Errorf("work directory left: %v", m)
			}
		})
	}
}

// The agent, driven by a connector manager, stops on a signal the same way.
func TestShutdown_sigtermStopsTheAgent(t *testing.T) {
	tests := []struct {
		name   string
		signal syscall.Signal
	}{
		{name: "SIGTERM", signal: syscall.SIGTERM},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := gmalware.New(t)
			g.Hang()
			in := harness.Start(t, g, harness.Options{Timeout: "4s", Agent: true})
			in.Drop(t, "a.txt", []byte("some content to analyze"))
			in.WaitFor(t, "the analysis to start", func() bool { return g.Submitted.Load() > 0 })
			in.Signal(t, tt.signal)
			if _, err := in.Wait(t, 6*time.Second); err != nil {
				t.Errorf("exit = %v, want code 0; log:\n%s", err, in.Stderr.String())
			}
			if m := harness.GlobOne(t, filepath.Join(in.Work, "gmhost-*")); len(m) != 0 {
				t.Errorf("work directory left: %v", m)
			}
		})
	}
}
