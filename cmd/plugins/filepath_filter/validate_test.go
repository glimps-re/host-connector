package main

import (
	"testing"

	"github.com/glimps-re/host-connector/pkg/plugins/mock"
)

func TestFilePathFilterPlugin_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  any
		wantErr bool
	}{
		{name: "valid", config: &Config{ForbiddenPaths: []string{`^/tmp/.*`}, SkippedPaths: []string{`.*\.png$`}}},
		{name: "invalid regexp", config: &Config{ForbiddenPaths: []string{`(`}}, wantErr: true},
		{name: "pattern in both lists", config: &Config{ForbiddenPaths: []string{`a`}, SkippedPaths: []string{`a`}}, wantErr: true},
		{name: "wrong config type", config: "x", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var p FilePathFilterPlugin
			if err := p.Validate(tt.config, mock.NewMockHCContext()); (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %t", err, tt.wantErr)
			}
			if p.ForbiddenPaths != nil || p.SkippedPaths != nil {
				t.Error("Validate must not change the plugin state")
			}
		})
	}
}

func TestFilePathFilterPlugin_CloseTwice(t *testing.T) {
	var p FilePathFilterPlugin
	for range 2 {
		if err := p.Close(t.Context()); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}
}
