package handler

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/glimps-re/host-connector/pkg/scanner"
	"github.com/google/go-cmp/cmp"
)

func TestDecodePluginsConfig(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    []scanner.PluginConfig
		wantErr bool
	}{
		{name: "empty file", in: "", wantErr: true},
		{name: "comments only", in: "# nothing\n", wantErr: true},
		{name: "empty mapping", in: "{}\n", wantErr: true},
		{name: "second document", in: "a:\n  file: a.so\n---\nb:\n  file: b.so\n", wantErr: true},
		{name: "duplicate key", in: "a:\n  file: a.so\na:\n  file: b.so\n", wantErr: true},
		{name: "alias", in: "a: &x\n  file: a.so\nb: *x\n", wantErr: true},
		{name: "merge key", in: "base: &x\n  file: a.so\n<<: *x\n", wantErr: true},
		{name: "non scalar key", in: "? [a, b]\n: {file: a.so}\n", wantErr: true},
		{
			name: "order and content kept",
			in:   "zeta:\n  file: z.so\nalpha:\n  file: a.so\n  config:\n    k: v\nmid:\n  file: m.so\n",
			want: []scanner.PluginConfig{
				{Name: "zeta", File: "z.so"},
				{Name: "alpha", File: "a.so", Config: map[string]any{"k": "v"}},
				{Name: "mid", File: "m.so"},
			},
		},
		{name: "not a mapping", in: "- a\n- b\n", wantErr: true},
		{name: "plugin entry not a mapping", in: "a: 3\n", wantErr: true},
		{name: "invalid yaml", in: "a: [\n", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodePluginsConfig(strings.NewReader(tt.in))
			if (err != nil) != tt.wantErr {
				t.Fatalf("decodePluginsConfig() error = %v, wantErr %t", err, tt.wantErr)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("decodePluginsConfig() mismatch:\n%s", diff)
			}
		})
	}
}

func TestDecodePluginsConfig_stableOrder(t *testing.T) {
	var sb strings.Builder
	want := make([]string, 0, 30)
	for i := range 30 {
		name := fmt.Sprintf("p%02d", (i*7)%30)
		want = append(want, name)
		fmt.Fprintf(&sb, "%s:\n  file: %s.so\n", name, name)
	}
	for range 20 {
		got, err := decodePluginsConfig(strings.NewReader(sb.String()))
		if err != nil {
			t.Fatal(err)
		}
		names := make([]string, 0, len(got))
		for _, pc := range got {
			names = append(names, pc.Name)
		}
		if diff := cmp.Diff(want, names); diff != "" {
			t.Fatalf("order changed:\n%s", diff)
		}
	}
}

func TestDecodePluginsConfig_errFormat(t *testing.T) {
	for name, in := range map[string]string{
		"not a mapping":   "- a\n",
		"empty":           "",
		"duplicate":       "a:\n  file: a.so\na:\n  file: b.so\n",
		"second document": "a:\n  file: a.so\n---\nb:\n  file: b.so\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := decodePluginsConfig(strings.NewReader(in))
			if !errors.Is(err, errPluginsConfigFormat) {
				t.Errorf("error = %v, want %v", err, errPluginsConfigFormat)
			}
		})
	}
}

func TestDecodePluginsConfig_sizeLimit(t *testing.T) {
	big := "a:\n  file: a.so\n  config:\n    k: " + strings.Repeat("x", maxPluginsConfigSize) + "\n"
	if _, err := decodePluginsConfig(strings.NewReader(big)); !errors.Is(err, errPluginsConfigFormat) {
		t.Errorf("error = %v, want %v", err, errPluginsConfigFormat)
	}
}

func TestDecodePluginsConfig_shippedFile(t *testing.T) {
	f, err := os.Open(filepath.Join("..", "..", "rsc", "plugin_config.yml"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if e := f.Close(); e != nil {
			t.Errorf("close: %v", e)
		}
	}()
	got, err := decodePluginsConfig(f)
	if err != nil {
		t.Fatalf("decodePluginsConfig() error = %v", err)
	}
	names := make([]string, 0, len(got))
	for _, pc := range got {
		names = append(names, pc.Name)
	}
	want := []string{"extract", "filetype_filter", "session", "report"}
	if diff := cmp.Diff(want, names); diff != "" {
		t.Errorf("shipped plugin order mismatch:\n%s", diff)
	}
}

func TestDecodePluginsConfig_hardening(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantErr string
	}{
		{"alias in config", "a:\n  file: a.so\n  config:\n    x: &p [1]\n    y: *p\n", "aliases"},
		{"alias as file", "a:\n  file: &f a.so\nb:\n  file: *f\n", "aliases"},
		{"anchor alone", "a: &x\n  file: a.so\n", "aliases"},
		{"nested merge", "a:\n  file: a.so\n  config:\n    <<: {k: v}\n", "merge"},
		{"unknown entry key", "a:\n  file: a.so\n  confg:\n    k: v\n", `unknown key "confg"`},
		{"entry key misspelled file", "a:\n  fle: a.so\n", `unknown key "fle"`},
		{"settings not a mapping", "a: [file]\n", "mapping"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := decodePluginsConfig(strings.NewReader(tt.in))
			if err == nil || !errors.Is(err, errPluginsConfigFormat) || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("decodePluginsConfig() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestDecodePluginsConfig_errorsHideValues(t *testing.T) {
	const secret = "S3CRET-pass"
	inputs := map[string]string{
		"file not a string": "a:\n  file: [" + secret + "]\n",
		"config not a map":  "a:\n  file: a.so\n  config: " + secret + "\n",
		"syntax":            "a:\n  file: a.so\n  config:\n    pw: [" + secret + "\n",
		"tab indent":        "a:\n\tfile: " + secret + "\n",
	}
	for name, in := range inputs {
		t.Run(name, func(t *testing.T) {
			_, err := decodePluginsConfig(strings.NewReader(in))
			if err == nil {
				t.Fatal("decodePluginsConfig() error = nil")
			}
			if strings.Contains(err.Error(), secret) {
				t.Errorf("error leaks a value: %v", err)
			}
		})
	}
}

func TestDecodePluginsConfig_shippedExamplesAccepted(t *testing.T) {
	b, err := os.ReadFile("../../rsc/plugin_config.yml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodePluginsConfig(strings.NewReader(string(b))); err != nil {
		t.Errorf("rsc/plugin_config.yml refused: %v", err)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("disk exploded") }

func TestDecodePluginsConfig_readErrorIsNotSyntaxError(t *testing.T) {
	_, err := decodePluginsConfig(failingReader{})
	if err == nil || !strings.Contains(err.Error(), "read plugins file") || strings.Contains(err.Error(), "syntax") {
		t.Errorf("decodePluginsConfig() error = %v, want a read error", err)
	}
}
