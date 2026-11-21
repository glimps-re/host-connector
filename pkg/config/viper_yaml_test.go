package config

import (
	"fmt"
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

func TestValidate_ViperYAML(t *testing.T) {
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
		{"extract_error as_file", "unanalyzable_policy:\n  extract_error: as_file\n", ""},
		{"extract_error error", "unanalyzable_policy:\n  extract_error: error\n", ""},
		{"extract_error pass", "unanalyzable_policy:\n  extract_error: pass\n", "extract_error"},
		{"analysis_error error", "unanalyzable_policy:\n  analysis_error: error\n", ""},
		{"analysis_error mitigate", "unanalyzable_policy:\n  analysis_error: mitigate\n", ""},
		{"analysis_error pass", "unanalyzable_policy:\n  analysis_error: pass\n", ""},
		{"analysis_error skip", "unanalyzable_policy:\n  analysis_error: skip\n", "analysis_error"},
		{"filepath_filter both lists", "filepath_filter:\n  forbidden_paths:\n    - '\\.exe$'\n  skipped_paths:\n    - '^/srv/in/trusted/'\n", ""},
		{"filepath_filter 256 patterns", "filepath_filter:\n  forbidden_paths: [" + strings.TrimSuffix(strings.Repeat("a, ", 256), ", ") + "]\n", ""},
		{"filepath_filter 257 patterns", "filepath_filter:\n  skipped_paths: [" + strings.TrimSuffix(strings.Repeat("a, ", 257), ", ") + "]\n", "skipped_paths"},
		{"filepath_filter empty pattern", "filepath_filter:\n  skipped_paths: ['']\n", "skipped_paths[0]"},
		{"filepath_filter invalid pattern", "filepath_filter:\n  forbidden_paths: ['(']\n", "forbidden_paths[0]"},
		{"filepath_filter 1025 bytes", "filepath_filter:\n  forbidden_paths:\n    - " + strings.Repeat("a", 1025) + "\n", "forbidden_paths[0]"},
		{"filepath_filter 512 two-byte runes", "filepath_filter:\n  skipped_paths:\n    - " + strings.Repeat("é", 512) + "\n", ""},
		{"filepath_filter 513 two-byte runes", "filepath_filter:\n  skipped_paths:\n    - " + strings.Repeat("é", 513) + "\n", "skipped_paths[0]"},
		{"filepath_filter 32 KiB in all", "filepath_filter:\n  forbidden_paths: " + yamlPatterns(16, 1024, "a") + "\n  skipped_paths: " + yamlPatterns(16, 1024, "b") + "\n", ""},
		{"filepath_filter 32 KiB and one byte", "filepath_filter:\n  forbidden_paths: " + yamlPatterns(16, 1024, "a") + "\n  skipped_paths: " + yamlPatterns(15, 1024, "b")[:len(yamlPatterns(15, 1024, "b"))-1] + ", " + strings.Repeat("c", 1024) + "x]\n", "32768 in all"},
		{"filepath_filter 20000 entries", "filepath_filter:\n  forbidden_paths: " + yamlPatterns(20_000, 6, "a") + "\n", "20000 patterns, at most 256"},
		{"filepath_filter pattern in both lists", "filepath_filter:\n  forbidden_paths: [same]\n  skipped_paths: [same]\n", "also in forbidden_paths"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRefusal(t, Validate(loadViperYAML(t, tt.yaml)), tt.wantKey)
		})
	}
}

func assertRefusal(t *testing.T, err error, wantKey string) {
	t.Helper()
	if wantKey == "" {
		if err != nil {
			t.Fatalf("error = %v, want nil", err)
		}
		return
	}
	if err == nil || !strings.Contains(err.Error(), wantKey) {
		t.Fatalf("error = %v, want a refusal naming %q", err, wantKey)
	}
}

// yamlPatterns is a YAML list (flow style) of n different patterns of size bytes,
// each made of letter and its number.
func yamlPatterns(n, size int, letter string) string {
	items := make([]string, n)
	for i := range items {
		tail := fmt.Sprintf("%06d", i)
		items[i] = strings.Repeat(letter, size-len(tail)) + tail
	}
	return "[" + strings.Join(items, ", ") + "]"
}
