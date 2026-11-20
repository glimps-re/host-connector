package config

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/glimps-re/connector-integration/sdk"
)

func TestValidate(t *testing.T) {
	tests := []struct {
		name      string
		yaml      string
		wantField string
	}{
		{"no paths nor api url (quarantine sub-commands)", "quarantine:\n  location: /q\n  password: x\n", ""},
		{"valid values", "move:\n  mode: copy\nunanalyzable_policy:\n  too_big: pass\n  empty: mitigate\n  encrypted: error\n  extract_error: as_file\nmonitoring:\n  max_tracked_dir_percent: 100\nquarantine:\n  format: zip\n", ""},
		{"too_big bogus", "unanalyzable_policy:\n  too_big: bogus\n", "too_big"},
		{"too_big wrong case", "unanalyzable_policy:\n  too_big: Pass\n", "too_big"},
		{"empty error", "unanalyzable_policy:\n  empty: error\n", "empty"},
		{"encrypted skip", "unanalyzable_policy:\n  encrypted: skip\n", "encrypted"},
		{"extract_error pass", "unanalyzable_policy:\n  extract_error: pass\n", "extract_error"},
		{"move.mode link", "move:\n  mode: link\n", "mode"},
		{"move.mode COPY", "move:\n  mode: COPY\n", "mode"},
		{"quarantine.format gz", "quarantine:\n  format: gz\n", "format"},
		{"percent 101", "monitoring:\n  max_tracked_dir_percent: 101\n", "max_tracked_dir_percent"},
		{"percent negative", "monitoring:\n  max_tracked_dir_percent: -1\n", "max_tracked_dir_percent"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(loadViperYAML(t, tt.yaml))
			if tt.wantField == "" {
				if err != nil {
					t.Fatalf("Validate() error = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantField) {
				t.Fatalf("Validate() error = %v, want field %q", err, tt.wantField)
			}
		})
	}
}

func TestSDKDefaultConfigAccepted(t *testing.T) {
	raw, err := sdk.InitDefault(sdk.HostKey)
	if err != nil {
		t.Fatal(err)
	}
	hc, ok := raw.(*sdk.HostConfig)
	if !ok {
		t.Fatalf("InitDefault returned %T", raw)
	}
	conf := &Config{HostConfig: *hc}
	if err := Validate(conf); err != nil {
		t.Errorf("Validate(SDK default) = %v", err)
	}
	if err := CheckImplemented(conf); err != nil {
		t.Errorf("CheckImplemented(SDK default) = %v", err)
	}
}

func TestExplicitAcceptedValues(t *testing.T) {
	conf := &Config{}
	conf.Monitoring.DisableFSWatcher = false
	conf.Monitoring.MaxTrackedDirPercent = 0
	conf.Move.Mode = "rename"
	conf.Move.MinThroughput = "10MiB"
	conf.WorkDir = ""
	conf.UnanalyzablePolicy.TooBig = "error"
	conf.UnanalyzablePolicy.Empty = "skip"
	conf.Quarantine.Format = "tar"
	if err := CheckImplemented(conf); err != nil {
		t.Errorf("CheckImplemented(explicit accepted values) = %v", err)
	}
	for _, mutate := range []func(){
		func() { conf.UnanalyzablePolicy.ExtractError = "as_file" },
	} {
		mutate()
		if err := CheckImplemented(conf); err == nil {
			t.Errorf("CheckImplemented() = nil after mutation, want refusal")
		}
		conf = &Config{}
	}
}

func TestDisableFSWatcherSameInYAMLAndJSON(t *testing.T) {
	fromYAML := loadViperYAML(t, "monitoring:\n  disable_fs_watcher: true\n  period: 1h\n")
	fromJSON := new(Config)
	if err := json.Unmarshal([]byte(`{"monitoring":{"disable_fs_watcher":true,"period":"1h"}}`), fromJSON); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]*Config{"yaml": fromYAML, "json": fromJSON} {
		if !c.Monitoring.DisableFSWatcher || c.Monitoring.Period != sdk.Duration(time.Hour) {
			t.Errorf("%s: monitoring = %+v", name, c.Monitoring)
		}
		if err := errors.Join(Validate(c), CheckImplemented(c)); err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
	}
	if diff := cmp.Diff(fromYAML.Monitoring, fromJSON.Monitoring); diff != "" {
		t.Errorf("effective monitoring differs (-yaml +json):\n%s", diff)
	}
	absent := new(Config)
	if err := json.Unmarshal([]byte(`{"monitoring":{"period":"1h"}}`), absent); err != nil || absent.Monitoring.DisableFSWatcher {
		t.Errorf("absent key must mean the default (false): %v %+v", err, absent.Monitoring)
	}
}

func TestValidate_disableFSWatcherNeedsPeriod(t *testing.T) {
	err := Validate(loadViperYAML(t, "monitoring:\n  disable_fs_watcher: true\n"))
	if !errors.Is(err, ErrWatcherNeedsPeriod) {
		t.Errorf("Validate() = %v, want ErrWatcherNeedsPeriod", err)
	}
}
