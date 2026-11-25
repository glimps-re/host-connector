package handler

import (
	"strings"
	"testing"

	"github.com/glimps-re/connector-integration/sdk"
	"github.com/glimps-re/host-connector/pkg/config"
	"github.com/glimps-re/host-connector/pkg/scanner"
)

// moveConf is a valid configuration whose move action is on or off, in the mode
// given, with the empty policy given.
func moveConf(t *testing.T, on bool, mode, empty string) *config.Config {
	t.Helper()
	conf := validConf(t, t.TempDir())
	conf.Actions.Move = on
	if on {
		conf.Move.Destination = t.TempDir()
	}
	conf.Move.Mode = mode
	conf.UnanalyzablePolicy.Empty = empty
	return conf
}

// empty: pass with the move action on in rename mode is refused when the
// configuration is applied, before anything is stopped: the running connector is
// the same one.
func TestConfigure_emptyPassWithRenameIsRefusedAndTheRunningOneKept(t *testing.T) {
	recordEvents(t)
	h := newRunningHandler(t, validConf(t, t.TempDir()))
	conn := h.Conn
	err := h.Configure(t.Context(), rawConf(t, moveConf(t, true, "rename", "pass")))
	if err == nil || !strings.Contains(err.Error(), "unanalyzable_policy.empty") || !strings.Contains(err.Error(), "move.mode") {
		t.Fatalf("Configure() = %v, want a refusal naming both keys", err)
	}
	if h.Conn != conn || h.Status() != sdk.Started {
		t.Error("the refused configuration must leave the running connector in place")
	}
}

// The mode counts only while the move action is on.
func TestPrepare_theEmptyPolicyAndTheMoveMode(t *testing.T) {
	tests := []struct {
		name    string
		on      bool
		mode    string
		empty   string
		wantErr bool
	}{
		{"move on, copy, pass", true, "copy", "pass", false},
		{"move on, no mode, absent", true, "", "", false},
		{"move on, rename, absent (skips, warns)", true, "rename", "", false},
		{"move on, rename, skip", true, "rename", "skip", false},
		{"move on, rename, mitigate", true, "rename", "mitigate", false},
		{"move on, rename, pass", true, "rename", "pass", true},
		{"move off, rename, pass", false, "rename", "pass", false},
		{"move off, rename, absent", false, "rename", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := new(Handler).prepare(moveConf(t, tt.on, tt.mode, tt.empty))
			if (err != nil) != tt.wantErr {
				t.Errorf("prepare() = %v, want error %v", err, tt.wantErr)
			}
		})
	}
}

func TestEffectiveMoveMode(t *testing.T) {
	for _, tt := range []struct {
		on   bool
		mode string
		want scanner.MoveMode
	}{
		{true, "rename", scanner.MoveModeRename},
		{true, "copy", scanner.MoveModeCopy},
		{true, "", scanner.MoveMode("")},
		{false, "rename", scanner.MoveModeCopy},
	} {
		conf := &config.Config{}
		conf.Actions.Move, conf.Move.Mode = tt.on, tt.mode
		if got := effectiveMoveMode(conf); got != tt.want {
			t.Errorf("move %v, mode %q: effectiveMoveMode() = %q, want %q", tt.on, tt.mode, got, tt.want)
		}
	}
}
