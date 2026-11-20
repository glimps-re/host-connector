package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/glimps-re/host-connector/pkg/plugins/mock"
)

func TestReportPlugin_Validate(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.tmpl")
	if err := os.WriteFile(good, []byte("{{.ScanID}}"), 0o600); err != nil {
		t.Fatal(err)
	}
	broken := filepath.Join(dir, "broken.tmpl")
	if err := os.WriteFile(broken, []byte("{{.ScanID"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		config  any
		wantErr bool
	}{
		{name: "embedded template", config: &Config{}},
		{name: "custom template", config: &Config{TemplatePath: good}},
		{name: "missing template", config: &Config{TemplatePath: filepath.Join(dir, "missing.tmpl")}, wantErr: true},
		{name: "template syntax error", config: &Config{TemplatePath: broken}, wantErr: true},
		{name: "wrong config type", config: "x", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var p ReportPlugin
			if err := p.Validate(tt.config, mock.NewMockHCContext()); (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %t", err, tt.wantErr)
			}
			if p.templ != nil {
				t.Error("Validate must not change the plugin state")
			}
		})
	}
}

func TestReportPlugin_CloseTwice(t *testing.T) {
	var p ReportPlugin
	for range 2 {
		if err := p.Close(t.Context()); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}
}
