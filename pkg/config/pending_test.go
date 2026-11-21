package config

import (
	"errors"
	"strings"
	"testing"
)

func TestCheckImplemented_ViperYAML(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantKey string
	}{
		{"nothing set", "debug: true\n", ""},
		{"analysis_error left out", "unanalyzable_policy:\n  too_big: error\n", ""},
		{"analysis_error error", "unanalyzable_policy:\n  analysis_error: error\n", ""},
		{"analysis_error mitigate", "unanalyzable_policy:\n  analysis_error: mitigate\n", ""},
		{"analysis_error pass", "unanalyzable_policy:\n  analysis_error: pass\n", ""},
		{"filepath_filter empty lists", "filepath_filter:\n  forbidden_paths: []\n  skipped_paths: []\n", ""},
		{"filepath_filter forbidden", "filepath_filter:\n  forbidden_paths:\n    - '\\.exe$'\n", "filepath_filter"},
		{"filepath_filter skipped", "filepath_filter:\n  skipped_paths:\n    - '^/srv/in/trusted/'\n", "filepath_filter"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckImplemented(loadViperYAML(t, tt.yaml))
			if tt.wantKey == "" {
				if err != nil {
					t.Fatalf("error = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, ErrNotImplemented) || !strings.Contains(err.Error(), tt.wantKey) {
				t.Fatalf("error = %v, want ErrNotImplemented naming %q", err, tt.wantKey)
			}
		})
	}
}

func TestCheckImplemented_namesTheKeysThatAreStillPending(t *testing.T) {
	err := CheckImplemented(loadViperYAML(t, "unanalyzable_policy:\n  analysis_error: pass\nfilepath_filter:\n  skipped_paths: [a]\n"))
	if err == nil || strings.Contains(err.Error(), "unanalyzable_policy.analysis_error") || !strings.Contains(err.Error(), "filepath_filter") {
		t.Errorf("error = %v, want only filepath_filter named", err)
	}
}
