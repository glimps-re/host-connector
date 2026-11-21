package handler

import (
	"errors"
	"strings"
	"testing"

	"github.com/glimps-re/host-connector/pkg/scanner"
	"github.com/google/go-cmp/cmp"
)

func TestDropRemovedPlugins(t *testing.T) {
	keep := scanner.PluginConfig{Name: "extract", File: "extract.so"}
	other := scanner.PluginConfig{Name: "report", File: "report.so"}
	byName := scanner.PluginConfig{Name: "filesize_filter", File: "/opt/anything.so"}
	byFile := scanner.PluginConfig{Name: "size", File: "/opt/plugins/filesize_filter.so"}
	byShort := scanner.PluginConfig{Name: "acme", File: "/opt/acme/filesize.so"}
	lookalike := scanner.PluginConfig{Name: "filesize_filter_v2", File: "my_filesize_filter.so"}
	tests := []struct {
		name        string
		in          []scanner.PluginConfig
		want        []scanner.PluginConfig
		wantDropped []scanner.PluginConfig
	}{
		{"nothing to drop", []scanner.PluginConfig{keep, other}, []scanner.PluginConfig{keep, other}, nil},
		{"by name, whatever the file", []scanner.PluginConfig{keep, byName, other}, []scanner.PluginConfig{keep, other}, []scanner.PluginConfig{byName}},
		{"by the file of the plugin, under another name", []scanner.PluginConfig{keep, byFile}, []scanner.PluginConfig{keep}, []scanner.PluginConfig{byFile}},
		{"by the short file name, in a directory of its own", []scanner.PluginConfig{byShort, other}, []scanner.PluginConfig{other}, []scanner.PluginConfig{byShort}},
		{"a plugin that only looks like it", []scanner.PluginConfig{lookalike}, []scanner.PluginConfig{lookalike}, nil},
		{"no plugin at all", nil, []scanner.PluginConfig{}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, dropped := dropRemovedPlugins(tt.in)
			if diff := cmp.Diff(tt.wantDropped, dropped); diff != "" {
				t.Errorf("dropped plugins mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("kept plugins mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestRemovedFilesizeWarning(t *testing.T) {
	dropped := []scanner.PluginConfig{{Name: "acme", File: "/opt/acme/filesize.so"}, {Name: "filesize_filter", File: "filesize_filter.so"}}
	tests := []struct {
		name    string
		tooBig  string
		want    []string
		notWant []string
	}{
		{"too_big unset", "", []string{`"acme" (file "/opt/acme/filesize.so")`, `"filesize_filter" (file "filesize_filter.so")`, "max_size", "not carried over", "error (the default)", "set it to mitigate"}, nil},
		{"too_big error", "error", []string{"too_big is error:", "set it to mitigate"}, []string{"the default"}},
		{"too_big mitigate", "mitigate", []string{"too_big is mitigate, which keeps oversized files quarantined"}, []string{"set it to", "the default"}},
		{"too_big pass", "pass", []string{"too_big is pass:"}, []string{"the default"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := removedFilesizeWarning(dropped, tt.tooBig)
			for _, w := range tt.want {
				if !strings.Contains(got, w) {
					t.Errorf("message %q lacks %q", got, w)
				}
			}
			for _, w := range tt.notWant {
				if strings.Contains(got, w) {
					t.Errorf("message %q must not contain %q", got, w)
				}
			}
		})
	}
}

// An entry of the removed plugin does not fail the validation, however the file it
// names is (it is not shipped any more); the other entries are validated.
func TestPrepare_anEntryOfTheRemovedPluginIsIgnored(t *testing.T) {
	t.Run("alone: refused, nothing is validated", func(t *testing.T) {
		conf := validConf(t, t.TempDir())
		conf.PluginsConfig = writePluginsFile(t, "filesize_filter:\n  file: /nonexistent/filesize_filter.so\n  config:\n    max_size: 100MB\n")
		called := false
		h := &Handler{validatePlugins: func([]scanner.PluginConfig, *scanner.ValidationContext) error {
			called = true
			return nil
		}}
		p, err := h.prepare(conf)
		if !errors.Is(err, errOnlyRemovedPlugins) || p != nil || called {
			t.Errorf("prepare() = (%v, %v), validated %v; want errOnlyRemovedPlugins, nothing prepared nor validated", p, err, called)
		}
	})
	t.Run("among others: the others are validated", func(t *testing.T) {
		conf := validConf(t, t.TempDir())
		conf.PluginsConfig = writePluginsFile(t, "filesize_filter:\n  file: filesize.so\nextra:\n  file: /nonexistent/extra.so\n")
		var validated []string
		h := &Handler{validatePlugins: func(pcs []scanner.PluginConfig, _ *scanner.ValidationContext) error {
			for _, pc := range pcs {
				validated = append(validated, pc.Name)
			}
			return nil
		}}
		p, err := h.prepare(conf)
		if err != nil {
			t.Fatal(err)
		}
		if len(p.removedPlugins) != 1 {
			t.Errorf("removed = %v, want the entry", p.removedPlugins)
		}
		if diff := cmp.Diff([]string{"extra"}, validated); diff != "" {
			t.Errorf("validated plugins mismatch (-want +got):\n%s", diff)
		}
	})
}

// The entries of the removed plugin raise the event at each report, and the
// configuration without them resolves it exactly once.
func TestReportRemovedPlugins_raisesAtEachReportAndResolvesOnce(t *testing.T) {
	rec := recordEvents(t)
	captureHandlerLogs(t)
	h := new(Handler)
	dropped := []scanner.PluginConfig{{Name: "filesize_filter", File: "filesize_filter.so"}}
	h.reportRemovedPlugins(t.Context(), dropped, "")
	h.reportRemovedPlugins(t.Context(), dropped, "mitigate")
	if n := len(rec.find("error", HostPluginRemovedFilesize)); n != 2 {
		t.Errorf("%d events for two reports with the entry, want one at each", n)
	}
	if n := len(rec.find("resolution", HostPluginRemovedFilesize)); n != 0 {
		t.Errorf("%d resolutions while the entry is there, want none", n)
	}
	h.reportRemovedPlugins(t.Context(), nil, "")
	if n := len(rec.find("resolution", HostPluginRemovedFilesize)); n != 1 {
		t.Errorf("%d resolutions by the report without the entry, want exactly 1", n)
	}
}

// A configuration whose installation fails raises nothing about the entry: it
// was not applied.
func TestConfigure_aFailedInstallRaisesNoRemovedPluginEvent(t *testing.T) {
	rec := recordEvents(t)
	h := newRunningHandler(t, validConf(t, t.TempDir()))
	h.validatePlugins = func([]scanner.PluginConfig, *scanner.ValidationContext) error { return nil }
	next := validConf(t, t.TempDir())
	next.PluginsConfig = writePluginsFile(t, "filesize_filter:\n  file: filesize_filter.so\nextra:\n  file: extra.so\n")
	if err := h.Configure(t.Context(), rawConf(t, next)); err == nil {
		t.Fatal("Configure() error = nil, want the load of extra.so to fail")
	}
	if n := len(rec.find("error", HostPluginRemovedFilesize)); n != 0 {
		t.Errorf("%d removed-plugin events for a configuration that was not applied, want none", n)
	}
}

func TestConfigure_aPluginsFileOfOnlyTheRemovedPluginIsRefusedAndNothingIsApplied(t *testing.T) {
	rec := recordEvents(t)
	h := newRunningHandler(t, validConf(t, t.TempDir()))
	good := h.conf
	next := validConf(t, t.TempDir())
	next.PluginsConfig = writePluginsFile(t, "filesize_filter:\n  file: filesize_filter.so\n")
	if err := h.Configure(t.Context(), rawConf(t, next)); !errors.Is(err, errOnlyRemovedPlugins) {
		t.Fatalf("Configure() error = %v, want errOnlyRemovedPlugins", err)
	}
	if h.conf != good {
		t.Error("the configuration in service changed after a refusal")
	}
	if n := len(rec.find("error", HostPluginRemovedFilesize)); n != 0 {
		t.Errorf("%d removed-plugin events for a refused configuration, want none", n)
	}
}
