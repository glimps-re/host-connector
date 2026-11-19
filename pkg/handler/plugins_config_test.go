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
	var want []string
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
		var names []string
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
	var names []string
	for _, pc := range got {
		names = append(names, pc.Name)
	}
	want := []string{"extract", "filetype_filter", "filepath_filter", "filesize_filter", "error_filter", "session", "report"}
	if diff := cmp.Diff(want, names); diff != "" {
		t.Errorf("shipped plugin order mismatch:\n%s", diff)
	}
}
