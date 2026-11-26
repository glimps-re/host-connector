package config

import (
	"reflect"
	"strings"
	"testing"

	"github.com/glimps-re/connector-integration/sdk"
)

func TestLoadFile_periodStrictness(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"unit", "5s", false},
		{"disabled with a bare zero", "0", false},
		{"disabled with a quoted zero", `"0"`, false},
		{"bare integer is nanoseconds", "5", true},
		{"quoted bare integer", `"10"`, true},
		{"bare float", "1.5", true},
		{"negative with unit", "-5s", true},
		{"negative quoted", `"-1m"`, true},
		{"garbage", "soon", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := LoadFile(writeConfig(t, "monitoring:\n  period: "+tt.value+"\n"), &Config{}, true)
			if (err != nil) != tt.wantErr {
				t.Fatalf("LoadFile() error = %v, wantErr %t", err, tt.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), "monitoring.period") {
				t.Errorf("error %q must name monitoring.period", err)
			}
		})
	}
}

func TestLoadFile_syntaxErrorNamesTheLineNotTheContent(t *testing.T) {
	path := writeConfig(t, "workers: 2\ngmalware_api_token: SECRET-TOKEN-VALUE\n  bad indent: [\n")
	err := LoadFile(path, &Config{}, true)
	if err == nil {
		t.Fatal("LoadFile() error = nil, want a syntax error")
	}
	if !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), "line") {
		t.Errorf("error %q must name the file and the line", err)
	}
	if strings.Contains(err.Error(), "SECRET-TOKEN-VALUE") {
		t.Errorf("error %q quotes a secret value", err)
	}
}

func TestLoadFile_unreadablePathIsRefused(t *testing.T) {
	if err := LoadFile(t.TempDir(), &Config{}, false); err == nil {
		t.Error("LoadFile() on a directory: error = nil, want a refusal even when the file may be absent")
	}
}

func TestStrictDuration_decodedNumberKinds(t *testing.T) {
	to := reflect.TypeFor[sdk.Duration]()
	tests := []struct {
		name    string
		data    any
		wantErr bool
	}{
		{"int zero", 0, false},
		{"int", 3, true},
		{"int64 zero", int64(0), false},
		{"int64", int64(3), true},
		{"uint64 zero", uint64(0), false},
		{"uint64", uint64(3), true},
		{"float64 zero", float64(0), false},
		{"float64", 2.5, true},
		{"duration string", "1h", false},
		{"unrelated type", true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := strictDuration(reflect.TypeOf(tt.data), to, tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("strictDuration(%v) error = %v, wantErr %t", tt.data, err, tt.wantErr)
			}
		})
	}
	if got, err := strictDuration(reflect.TypeFor[int](), reflect.TypeFor[int](), 7); err != nil || got != 7 {
		t.Errorf("a non-duration target must pass through, got (%v, %v)", got, err)
	}
}
