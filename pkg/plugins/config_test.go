package plugins

import (
	"errors"
	"strings"
	"testing"
	"time"
)

type testPluginConfig struct {
	Passwords []string      `mapstructure:"default_passwords"`
	Paths     []string      `mapstructure:"forbidden_paths"`
	Delay     time.Duration `mapstructure:"delay"`
	Depth     int           `mapstructure:"depth"`
}

func setRemovedKeys(t *testing.T, removed map[string]map[string]string) {
	t.Helper()
	previous := removedConfigKeys
	removedConfigKeys = removed
	t.Cleanup(func() { removedConfigKeys = previous })
}

func TestDecodeConfig(t *testing.T) {
	tests := []struct {
		name       string
		raw        map[string]any
		want       testPluginConfig
		wantErr    string
		wantAbsent []string
	}{
		{name: "nil config", raw: nil},
		{
			name: "valid",
			raw:  map[string]any{"default_passwords": []any{"infected"}, "delay": "30s", "depth": 2},
			want: testPluginConfig{Passwords: []string{"infected"}, Delay: 30 * time.Second, Depth: 2},
		},
		{name: "typo in key", raw: map[string]any{"forbidden_pathes": []any{"/x"}}, wantErr: "forbidden_pathes"},
		{name: "unknown nested level", raw: map[string]any{"confg": map[string]any{"a": 1}}, wantErr: "confg"},
		{name: "wrong type hides value", raw: map[string]any{"depth": "S3CRET-value"}, wantErr: "depth", wantAbsent: []string{"S3CRET-value"}},
		{name: "bad duration hides value", raw: map[string]any{"delay": "S3CRET-1x"}, wantErr: "delay", wantAbsent: []string{"S3CRET-1x"}},
		{name: "secret list wrong type", raw: map[string]any{"default_passwords": map[string]any{"k": "S3CRET-pw"}}, wantErr: "default_passwords", wantAbsent: []string{"S3CRET-pw"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got testPluginConfig
			err := DecodeConfig("p", tt.raw, &got)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("DecodeConfig() error = %v", err)
				}
				if got.Delay != tt.want.Delay || got.Depth != tt.want.Depth || len(got.Passwords) != len(tt.want.Passwords) {
					t.Errorf("DecodeConfig() = %+v, want %+v", got, tt.want)
				}
				return
			}
			if !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("DecodeConfig() error = %v, want key %q", err, tt.wantErr)
			}
			for _, absent := range tt.wantAbsent {
				if strings.Contains(err.Error(), absent) {
					t.Errorf("error leaks a value: %v", err)
				}
			}
		})
	}
}

func TestDecodeConfig_removedKeyBeforeStrictDecoding(t *testing.T) {
	setRemovedKeys(t, map[string]map[string]string{"p": {"old_key": "replaced by the global old_limit"}})
	var cfg testPluginConfig
	err := DecodeConfig("p", map[string]any{"old_key": 1}, &cfg)
	if !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), "replaced by the global old_limit") || strings.Contains(err.Error(), "unknown") {
		t.Errorf("DecodeConfig() = %v, want the removal message, not the generic refusal", err)
	}
}

func TestCheckRemovedKeys(t *testing.T) {
	setRemovedKeys(t, map[string]map[string]string{"extract": {"max_file_size": "use the global max_file_size"}})
	err := checkRemovedKeys("extract", map[string]any{"max_file_size": "1GB", "default_passwords": []string{"s3cret"}})
	if !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), "use the global max_file_size") {
		t.Errorf("checkRemovedKeys() = %v, want the removal message", err)
	}
	if strings.Contains(err.Error(), "s3cret") || strings.Contains(err.Error(), "1GB") {
		t.Errorf("error leaks a value: %v", err)
	}
	if err := checkRemovedKeys("extract", map[string]any{"default_passwords": nil}); err != nil {
		t.Errorf("checkRemovedKeys() = %v, want nil", err)
	}
	if err := checkRemovedKeys("other", map[string]any{"max_file_size": 1}); err != nil {
		t.Errorf("checkRemovedKeys(other) = %v, want nil", err)
	}
}

func TestDecodeConfig_removedExtractLimitKeysAreRefusedWithTheReplacement(t *testing.T) {
	replacement := map[string]string{
		"max_file_size":            "max_file_size",
		"max_extracted_files":      "recursive_extract_max_files",
		"max_total_extracted_size": "recursive_extract_max_size",
	}
	type extractConfig struct {
		DefaultPasswords []string `mapstructure:"default_passwords"`
	}
	for key, want := range replacement {
		var dst extractConfig
		err := DecodeConfig("extract", map[string]any{key: "1", "default_passwords": []any{"infected"}}, &dst)
		if !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), key) || !strings.Contains(err.Error(), want) {
			t.Errorf("key %s: error = %v, want a refusal naming the key and %s", key, err, want)
		}
		if err != nil && strings.Contains(err.Error(), "unknown config key") {
			t.Errorf("key %s: the explicit message was replaced by the generic one: %v", key, err)
		}
	}
}
