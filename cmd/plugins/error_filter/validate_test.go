package main

import (
	"testing"

	"github.com/glimps-re/host-connector/pkg/plugins/mock"
)

func TestErrorFilterPlugin_ValidateAndCloseTwice(t *testing.T) {
	var p ErrorFilterPlugin
	if err := p.Validate(&Config{}, mock.NewMockHCContext()); err != nil {
		t.Errorf("Validate() error = %v", err)
	}
	for range 2 {
		if err := p.Close(t.Context()); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}
}
