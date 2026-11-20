//go:build linux

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGetConfigFile_prefersTheUserFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".config", "gmhost")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(want, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := GetConfigFile()
	if err != nil || got != want {
		t.Errorf("GetConfigFile() = (%q, %v), want (%q, nil)", got, err, want)
	}
}
