//go:build linux

package main

import (
	"path/filepath"
	"testing"
	"time"
)

func TestSessionPlugin_Validate(t *testing.T) {
	base := t.TempDir()
	t.Run("exports are declared", func(t *testing.T) {
		hcc := newMockHCC(t)
		hcc.WorkDir = filepath.Join(base, "gmhost-validate-abc")
		var p SessionPlugin
		reports := filepath.Join(t.TempDir(), "reports")
		if err := p.Validate(&Config{ReportTimeout: time.Minute, MaxDuration: 24 * time.Hour, MaxSpoolSize: "1GiB", InflightTimeout: 24 * time.Hour, RootFolder: t.TempDir(), Exports: []string{reports}}, hcc); err != nil {
			t.Fatalf("Validate() error = %v", err)
		}
		if len(hcc.OutputDirs) != 1 || hcc.OutputDirs[0] != reports {
			t.Errorf("declared output directories = %v, want %q", hcc.OutputDirs, reports)
		}
		if p.started || p.sessions != nil || p.stop != nil {
			t.Error("Validate must not change the plugin state or start anything")
		}
	})
	t.Run("root_folder is the base of the work directory", func(t *testing.T) {
		hcc := newMockHCC(t)
		hcc.WorkDir = filepath.Join(base, "gmhost-validate-abc")
		var p SessionPlugin
		if err := p.Validate(&Config{ReportTimeout: time.Minute, MaxDuration: 24 * time.Hour, MaxSpoolSize: "1GiB", InflightTimeout: 24 * time.Hour, RootFolder: base}, hcc); err == nil {
			t.Error("Validate() error = nil, want a refusal")
		}
	})
	t.Run("wrong config type", func(t *testing.T) {
		var p SessionPlugin
		if err := p.Validate("x", newMockHCC(t)); err == nil {
			t.Error("Validate() error = nil")
		}
	})
}

func TestSessionPlugin_CloseTwice(t *testing.T) {
	var p SessionPlugin
	for range 2 {
		if err := p.Close(t.Context()); err != nil {
			t.Fatalf("Close() on a plugin never started error = %v", err)
		}
	}
	hcc := newMockHCC(t)
	hcc.WorkDir = filepath.Join(t.TempDir(), "gmhost-x")
	if err := p.Init(&Config{ReportTimeout: time.Minute, MaxDuration: 24 * time.Hour, MaxSpoolSize: "1GiB", InflightTimeout: 24 * time.Hour, Depth: 1, RootFolder: t.TempDir(), Delay: 1}, hcc); err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	for range 2 {
		if err := p.Close(t.Context()); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}
}

func TestSessionPlugin_InitFailureLeavesNothingStarted(t *testing.T) {
	hcc := newMockHCC(t)
	var p SessionPlugin
	if err := p.Init("not a config", hcc); err == nil {
		t.Fatal("Init() error = nil")
	}
	if p.started {
		t.Error("a failed Init must not leave the plugin started")
	}
}
