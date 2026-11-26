package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/glimps-re/host-connector/pkg/config"
	"github.com/spf13/cobra"
)

func TestInitConfig_invalidFileRefusesToStart(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantKey string
	}{
		{name: "invalid yaml", content: "workers: [\n"},
		{name: "mistyped value", content: "workers: beaucoup\n", wantKey: "workers"},
		{name: "unknown key", content: "unanalyzable_policy:\n  too_bg: pass\n", wantKey: "too_bg"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yml")
			if err := os.WriteFile(path, []byte(tt.content), 0o600); err != nil {
				t.Fatal(err)
			}
			prev := hostConfig
			hostConfig = &config.Config{Config: path}
			t.Cleanup(func() { hostConfig = prev; errConfigFile = nil })

			initConfig()
			for name, start := range map[string]func() error{
				"monitoring": func() error { return initHandlerNoConsole(&cobra.Command{}, nil) },
				"scan":       func() error { return initHandler(&cobra.Command{}, nil, nil, nil) },
				"agent":      func() error { return agentCmd.RunE(&cobra.Command{}, nil) },
			} {
				err := start()
				if err == nil {
					t.Fatalf("%s: error = nil, want a refusal to start", name)
				}
				for _, want := range []string{path, tt.wantKey} {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("%s: error %q must name %q", name, err, want)
					}
				}
			}
		})
	}
}

func TestInitConfig_absentFileStartsWithDefaults(t *testing.T) {
	prev := hostConfig
	hostConfig = &config.Config{Config: filepath.Join(t.TempDir(), "absent.yml")}
	t.Cleanup(func() { hostConfig = prev; errConfigFile = nil })
	initConfig()
	if errConfigFile != nil {
		t.Errorf("an absent file must not refuse to start: %v", errConfigFile)
	}
}
