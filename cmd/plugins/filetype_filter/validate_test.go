package main

import (
	"testing"

	"github.com/glimps-re/host-connector/pkg/plugins/mock"
)

func TestFTFilterPlugin_Validate(t *testing.T) {
	var p FTFilterPlugin
	if err := p.Validate(&Config{ForbiddenTypes: []string{"application/x-dosexec"}}, mock.NewMockHCContext()); err != nil {
		t.Errorf("Validate() error = %v", err)
	}
	if err := p.Validate("x", mock.NewMockHCContext()); err == nil {
		t.Error("Validate() with a wrong config type: error = nil")
	}
	if p.ForbiddenTypes != nil || p.SkippedTypes != nil {
		t.Error("Validate must not change the plugin state")
	}
}

func TestFTFilterPlugin_CloseTwice(t *testing.T) {
	var p FTFilterPlugin
	for range 2 {
		if err := p.Close(t.Context()); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}
}
