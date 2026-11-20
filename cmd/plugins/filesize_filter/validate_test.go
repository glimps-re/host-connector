package main

import (
	"testing"

	"github.com/glimps-re/host-connector/pkg/plugins/mock"
)

func TestFileSizePlugin_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  any
		wantErr bool
	}{
		{name: "valid", config: &Config{MaxSize: "100MB"}},
		{name: "unparsable size", config: &Config{MaxSize: "lots"}, wantErr: true},
		{name: "wrong config type", config: "x", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var p FileSizePlugin
			if err := p.Validate(tt.config, mock.NewMockHCContext()); (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %t", err, tt.wantErr)
			}
			if p.MaxSize != 0 {
				t.Error("Validate must not change the plugin state")
			}
		})
	}
}

func TestFileSizePlugin_CloseTwice(t *testing.T) {
	var p FileSizePlugin
	for range 2 {
		if err := p.Close(t.Context()); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}
}
