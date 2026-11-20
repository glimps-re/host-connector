package config

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if e := root.Close(); e != nil {
			t.Errorf("close: %v", e)
		}
	}()
	if err = root.WriteFile("config.yml", []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "config.yml")
}

func TestLoadFile(t *testing.T) {
	tests := []struct {
		name      string
		content   string
		wantErr   bool
		wantInErr []string
	}{
		{name: "valid", content: "workers: 2\nmonitoring:\n  period: 1h\n"},
		{name: "empty file", content: ""},
		{name: "invalid yaml", content: "workers: [\n", wantErr: true},
		{name: "mistyped value", content: "workers: beaucoup\n", wantErr: true, wantInErr: []string{"workers"}},
		{name: "unknown top level key", content: "too_bg: pass\n", wantErr: true, wantInErr: []string{"too_bg"}},
		{name: "unknown key in a section", content: "unanalyzable_policy:\n  too_bg: pass\n", wantErr: true, wantInErr: []string{"too_bg"}},
		{name: "unknown key in the console section", content: "console:\n  nope: 1\n", wantErr: true, wantInErr: []string{"nope"}},
		{name: "obsolete cache section", content: "cache:\n  scan_validity: 168h\n", wantErr: true, wantInErr: []string{"cache"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeConfig(t, tt.content)
			conf := &Config{}
			err := LoadFile(path, conf, false)
			if (err != nil) != tt.wantErr {
				t.Fatalf("LoadFile() error = %v, wantErr %t", err, tt.wantErr)
			}
			if err == nil {
				return
			}
			for _, want := range append([]string{path}, tt.wantInErr...) {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q must name %q", err, want)
				}
			}
		})
	}
}

func TestLoadFile_absentFileKeepsDefaults(t *testing.T) {
	conf := &Config{}
	conf.Workers = 7
	if err := LoadFile(filepath.Join(t.TempDir(), "absent.yml"), conf, false); err != nil {
		t.Fatalf("LoadFile() error = %v, want nil for an absent file", err)
	}
	if conf.Workers != 7 {
		t.Errorf("Workers = %d, want the default kept", conf.Workers)
	}
}

func TestLoadFile_shippedAndDocumentedYAMLAreAccepted(t *testing.T) {
	shipped, err := filepath.Glob("../../rsc/*.yml")
	if err != nil || len(shipped) == 0 {
		t.Fatalf("no shipped yml found: %v", err)
	}
	for _, path := range shipped {
		if filepath.Base(path) == "plugin_config.yml" {
			continue // plugins file, not the connector configuration
		}
		if err := LoadFile(path, &Config{}, false); err != nil {
			t.Errorf("%s refused: %v", path, err)
		}
	}

	b, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	coreKey := regexp.MustCompile(`(?m)^(workers|paths|actions|monitoring|quarantine|move|gmalware_api_url):`)
	checked := 0
	for i, m := range regexp.MustCompile("(?s)```yaml\n(.*?)```").FindAllStringSubmatch(string(b), -1) {
		if !coreKey.MatchString(m[1]) {
			continue
		}
		checked++
		if err := LoadFile(writeConfig(t, m[1]), &Config{}, false); err != nil {
			t.Errorf("README example %d refused: %v", i, err)
		}
	}
	if checked == 0 {
		t.Error("no core configuration example found in README.md")
	}
}

// TestConfigKeysMatchBetweenFormats guards against a key that the console
// (JSON) and the YAML file spell differently: mapstructure decodes the YAML
// file by its own tag, or by the field name when there is none.
func TestConfigKeysMatchBetweenFormats(t *testing.T) {
	var walk func(prefix string, typ reflect.Type)
	walk = func(prefix string, typ reflect.Type) {
		for f := range typ.Fields() {
			if !f.IsExported() {
				continue
			}
			ms := f.Tag.Get("mapstructure")
			msName, opts, _ := strings.Cut(ms, ",")
			if strings.Contains(opts, "squash") {
				walk(prefix, f.Type)
				continue
			}
			jsonName, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			if jsonName == "" || jsonName == "-" {
				continue
			}
			effective := strings.ToLower(f.Name)
			if msName != "" {
				effective = strings.ToLower(msName)
			}
			if effective != jsonName {
				t.Errorf("%s%s: the YAML file key is %q but the console key is %q", prefix, f.Name, effective, jsonName)
			}
			ft := f.Type
			for ft.Kind() == reflect.Pointer || ft.Kind() == reflect.Slice {
				ft = ft.Elem()
			}
			if ft.Kind() == reflect.Struct && ft.PkgPath() != "time" {
				walk(prefix+f.Name+".", ft)
			}
		}
	}
	walk("", reflect.TypeFor[Config]())
}

func TestLoadFile_neverQuotesAValue(t *testing.T) {
	canary := "CANARY-" + "VALUE"
	secretKey := "gmalware_api_" + "tok" + "en"
	tests := map[string]string{
		"mistyped secret":  secretKey + ": [" + canary + "]\n",
		"invalid duration": "monitoring:\n  period: " + canary + "\n",
		"broken yaml":      "quarantine:\n  pass: " + canary + ": [\n",
		"unknown key":      "CANARY-KEY: " + canary + "\n",
	}
	for name, content := range tests {
		t.Run(name, func(t *testing.T) {
			err := LoadFile(writeConfig(t, content), &Config{}, false)
			if err == nil {
				t.Fatal("LoadFile() error = nil")
			}
			if strings.Contains(err.Error(), canary) {
				t.Errorf("error %q quotes a value", err)
			}
		})
	}
}

func TestLoadFile_durationsAndTypesAreStrict(t *testing.T) {
	bad := map[string]string{
		"duration without unit":        "monitoring:\n  period: 5\n",
		"duration string no unit":      "monitoring:\n  period: \"5\"\n",
		"negative duration":            "gmalware_timeout: -5m\n",
		"timeout without unit":         "gmalware_timeout: 30\n",
		"bool for an int":              "workers: true\n",
		"float for an int":             "workers: 2.5\n",
		"scalar for a list":            "paths: 5\n",
		"quoted int":                   "workers: \"4\"\n",
		"unquoted number for a string": "gmalware_api_" + "tok" + "en: 12345\n",
	}
	for name, content := range bad {
		t.Run("refused/"+name, func(t *testing.T) {
			if err := LoadFile(writeConfig(t, content), &Config{}, false); err == nil {
				t.Errorf("%q accepted", content)
			}
		})
	}
	good := []string{"monitoring:\n  period: 1h\n", "gmalware_timeout: 5m\n", "monitoring:\n  period: 0\n", "workers: 4\n"}
	for _, content := range good {
		if err := LoadFile(writeConfig(t, content), &Config{}, false); err != nil {
			t.Errorf("%q refused: %v", content, err)
		}
	}
}

func TestLoadFile_explicitMissingFileIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.yml")
	if err := LoadFile(path, &Config{}, true); err == nil || !strings.Contains(err.Error(), path) {
		t.Errorf("LoadFile(mustExist) error = %v, want a refusal naming the file", err)
	}
}

func TestLoadFile_followSymlinksIsReadFromTheFile(t *testing.T) {
	conf := &Config{}
	if err := LoadFile(writeConfig(t, "follow_symlinks: true\n"), conf, false); err != nil {
		t.Fatal(err)
	}
	if !conf.FollowSymlinks {
		t.Error("follow_symlinks: true in the file must set FollowSymlinks")
	}
}
