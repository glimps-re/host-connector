package handler

import (
	"testing"

	"github.com/glimps-re/host-connector/pkg/config"
	"github.com/glimps-re/host-connector/pkg/scanner"
)

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
