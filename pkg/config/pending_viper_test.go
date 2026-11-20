package config

import (
	"errors"
	"strings"
	"testing"

	"github.com/glimps-re/connector-integration/sdk"
	"github.com/spf13/viper"
)

func loadViperYAML(t *testing.T, content string) *Config {
	t.Helper()
	v := viper.New()
	v.SetConfigType("yaml")
	if err := v.ReadConfig(strings.NewReader(content)); err != nil {
		t.Fatal(err)
	}
	c := new(Config)
	if err := v.Unmarshal(c, viper.DecodeHook(sdk.DurationMapstructureHook())); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCheckImplemented_ViperYAML(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantKey string
	}{
		{"empty", "debug: true\n", ""},
		{"tar", "quarantine:\n  format: tar\n", ""},
		{"accepted explicit values", "move:\n  mode: rename\nunanalyzable_policy:\n  too_big: error\n  empty: skip\nmonitoring:\n  disable_fs_watcher: false\nwork_dir: \"\"\nquarantine:\n  format: tar\n", ""},
		{"too_big pass", "unanalyzable_policy:\n  too_big: pass\n", ""},
		{"too_big mitigate", "unanalyzable_policy:\n  too_big: mitigate\n", ""},
		{"empty mitigate", "unanalyzable_policy:\n  empty: mitigate\n", ""},
		{"empty pass", "unanalyzable_policy:\n  empty: pass\n", ""},
		{"encrypted pass", "unanalyzable_policy:\n  encrypted: pass\n", ""},
		{"encrypted mitigate", "unanalyzable_policy:\n  encrypted: mitigate\n", ""},
		{"extract_error", "unanalyzable_policy:\n  extract_error: as_file\n", "unanalyzable_policy.extract_error"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertPending(t, CheckImplemented(loadViperYAML(t, tt.yaml)), tt.wantKey)
		})
	}
}

func assertPending(t *testing.T, err error, wantKey string) {
	t.Helper()
	if wantKey == "" {
		if err != nil {
			t.Fatalf("error = %v, want nil", err)
		}
		return
	}
	if !errors.Is(err, ErrNotImplemented) || !strings.Contains(err.Error(), wantKey) {
		t.Fatalf("error = %v, want ErrNotImplemented naming %q", err, wantKey)
	}
}
