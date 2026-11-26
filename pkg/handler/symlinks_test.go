package handler

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/glimps-re/host-connector/pkg/config"
)

func TestWarnFollowSymlinks(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(c *config.Config)
		wantWarn bool
	}{
		{"default", func(*config.Config) {}, false},
		{"follow with delete", func(c *config.Config) { c.FollowSymlinks = true; c.Paths = []string{"/in"}; c.Actions.Delete = true }, true},
		{"follow with quarantine", func(c *config.Config) {
			c.FollowSymlinks = true
			c.Paths = []string{"/in"}
			c.Actions.Quarantine = true
		}, true},
		{"follow with move", func(c *config.Config) { c.FollowSymlinks = true; c.Paths = []string{"/in"}; c.Actions.Move = true }, true},
		{"follow with log only", func(c *config.Config) { c.FollowSymlinks = true; c.Paths = []string{"/in"}; c.Actions.Log = true }, false},
		{"follow without paths (scan command)", func(c *config.Config) { c.FollowSymlinks = true; c.Actions.Delete = true }, false},
		{"delete without follow", func(c *config.Config) { c.Paths = []string{"/in"}; c.Actions.Delete = true }, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := captureHandlerLogs(t)
			conf := &config.Config{}
			tt.mutate(conf)
			warnFollowSymlinks(conf)
			if got := buf.Len() > 0; got != tt.wantWarn {
				t.Errorf("warning = %t (%q), want %t", got, buf.String(), tt.wantWarn)
			}
		})
	}
}

func TestStatFor(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.bin")
	if err := os.WriteFile(target, []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.bin")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	lfi, err := statFor(false)(link)
	if err != nil || lfi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("statFor(false) must describe the link itself: %v, %v", lfi, err)
	}
	sfi, err := statFor(true)(link)
	if err != nil || sfi.Mode()&os.ModeSymlink != 0 || sfi.Size() != int64(len("content")) {
		t.Errorf("statFor(true) must follow the link: %v, %v", sfi, err)
	}
}
