package handler

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"unicode/utf8"

	"github.com/glimps-re/connector-integration/sdk"
	"github.com/glimps-re/host-connector/pkg/config"
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

// sealOnly stands for the load of the plugins: a plugin is a shared object, the
// test only needs the connector sealed as after a load.
func sealOnly(conn *scanner.Connector, _ []scanner.PluginConfig) error { return conn.LoadPlugins(nil) }

// newPluginHandler is a running handler whose plugins validation and load are
// replaced, so that a plugins file can be applied without a shared object.
func newPluginHandler(t *testing.T, conf *config.Config, load func(*scanner.Connector, []scanner.PluginConfig) error) *Handler {
	t.Helper()
	return newRunningHandler(t, conf, func(h *Handler) {
		h.validatePlugins = func([]scanner.PluginConfig, *scanner.ValidationContext) error { return nil }
		h.loadPlugins = load
	})
}

func withRemovedEntry(t *testing.T, tooBig string) *config.Config {
	t.Helper()
	conf := validConf(t, t.TempDir())
	conf.UnanalyzablePolicy.TooBig = tooBig
	conf.PluginsConfig = writePluginsFile(t, "filesize_filter:\n  file: /opt/plugins/filesize_filter.so\nextra:\n  file: extra.so\n")
	return conf
}

// captureScannerConsole replaces a global: a test that uses it must not run in
// parallel with another.
func captureScannerConsole(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := scanner.ConsoleLogger
	scanner.ConsoleLogger = slog.New(slog.NewTextHandler(&buf, nil))
	t.Cleanup(func() { scanner.ConsoleLogger = prev })
	return &buf
}

// An application that installs with an entry of the removed plugin raises the
// event, writes the console line, and tells the policy in force.
func TestConfigure_anEntryOfTheRemovedPluginIsReportedAfterASuccessfulInstall(t *testing.T) {
	for _, tooBig := range []string{"", "mitigate"} {
		t.Run("too_big "+tooBig, func(t *testing.T) {
			rec := recordEvents(t)
			logs := captureHandlerLogs(t)
			console := captureScannerConsole(t)
			h := newPluginHandler(t, validConf(t, t.TempDir()), sealOnly)
			if err := h.Configure(t.Context(), rawConf(t, withRemovedEntry(t, tooBig))); err != nil {
				t.Fatalf("Configure() error = %v", err)
			}
			events := rec.find("error", HostPluginRemovedFilesize)
			if len(events) != 1 {
				t.Fatalf("%d events, want one", len(events))
			}
			want := "too_big is error (the default)"
			if tooBig == "mitigate" {
				want = "too_big is mitigate, which keeps"
			}
			for name, text := range map[string]string{"event": events[0].msg, "console": console.String(), "log": logs.String()} {
				if !strings.Contains(text, want) || !strings.Contains(text, "/opt/plugins/filesize_filter.so") {
					t.Errorf("%s = %q, want the policy %q and the entry named", name, text, want)
				}
			}
		})
	}
}

// A refusal leaves the previous configuration running: nothing is stopped, rebuilt
// or replaced, and the rejection is raised.
func TestConfigure_aPluginsFileOfOnlyTheRemovedPluginIsRefusedAndTheRunningConfigurationKeepsRunning(t *testing.T) {
	rec := recordEvents(t)
	captureHandlerLogs(t)
	h := newPluginHandler(t, validConf(t, t.TempDir()), sealOnly)
	good, conn, monitor := h.conf, h.Conn, h.monitor
	next := validConf(t, t.TempDir())
	next.PluginsConfig = writePluginsFile(t, "filesize_filter:\n  file: filesize_filter.so\n")
	if err := h.Configure(t.Context(), rawConf(t, next)); !errors.Is(err, errOnlyRemovedPlugins) {
		t.Fatalf("Configure() error = %v, want errOnlyRemovedPlugins", err)
	}
	if h.conf != good || h.Conn != conn || h.monitor != monitor {
		t.Error("the configuration, the connector or the monitor in service changed after a refusal")
	}
	if got := h.Status(); got != sdk.Started {
		t.Errorf("Status() = %v, want Started", got)
	}
	if n := len(rec.find("error", HostPluginRemovedFilesize)); n != 0 {
		t.Errorf("%d removed-plugin events for a refused configuration, want none", n)
	}
	if n := len(rec.find("error", HostConfigRejected)); n != 1 {
		t.Errorf("%d rejection events, want one", n)
	}
}

// A configuration whose installation fails raises nothing about the entry: it was
// not applied. The previous configuration is replayed, and as it has the entry
// too, it is reported again, once.
func TestConfigure_aRollbackReportsTheEntryOfTheConfigurationItReplays(t *testing.T) {
	rec := recordEvents(t)
	captureHandlerLogs(t)
	var loads atomic.Int32
	failSecond := func(conn *scanner.Connector, cfgs []scanner.PluginConfig) error {
		if loads.Add(1) == 2 {
			return errors.New("the load of the second configuration fails")
		}
		return sealOnly(conn, cfgs)
	}
	h := newPluginHandler(t, withRemovedEntry(t, ""), failSecond)
	if n := len(rec.find("error", HostPluginRemovedFilesize)); n != 1 {
		t.Fatalf("%d events after the start, want one", n)
	}
	next := withRemovedEntry(t, "mitigate")
	if err := h.Configure(t.Context(), rawConf(t, next)); err == nil {
		t.Fatal("Configure() error = nil, want the load to fail")
	}
	events := rec.find("error", HostPluginRemovedFilesize)
	if len(events) != 2 {
		t.Fatalf("%d events in all, want the start and the replay", len(events))
	}
	if !strings.Contains(events[1].msg, "too_big is error (the default)") {
		t.Errorf("the replay reports %q, want the policy of the configuration replayed, not of the refused one", events[1].msg)
	}
	if h.conf.UnanalyzablePolicy.TooBig != "" {
		t.Error("the configuration in service is not the previous one")
	}
}

// What the plugins file says is hostile: the message escapes it and is bounded.
func TestRemovedFilesizeWarning_isBoundedAndEscapesWhatTheFileSays(t *testing.T) {
	hostile := scanner.PluginConfig{Name: "filesize_filter\n\x1b[31mred\u202e", File: strings.Repeat("a", 5000) + ".so"}
	dropped := make([]scanner.PluginConfig, 2000)
	for i := range dropped {
		dropped[i] = hostile
	}
	got := removedFilesizeWarning(dropped, "")
	if len(got) > maxReportedKeys*(maxReportedKeyLen+8)+1024 {
		t.Errorf("the message is %d bytes long, want it bounded", len(got))
	}
	if !strings.Contains(got, fmt.Sprintf("%d more", len(dropped)-maxReportedKeys)) {
		t.Errorf("the message does not say how many entries are not listed: %.200q", got)
	}
	for _, bad := range []string{"\n", "\x1b", "\u202e"} {
		if strings.Contains(got, bad) {
			t.Errorf("the message holds the raw character %q", bad)
		}
	}
}

// Whatever bytes an entry is made of, the message keeps valid UTF-8 and both parts
// (name and file) of each entry it lists, within the bound once quoted.
func TestRemovedFilesizeWarning_isBoundedAfterQuotingAndKeepsBothPartsOfAnEntry(t *testing.T) {
	texts := map[string]string{
		"control bytes":   strings.Repeat("\x01", 300),
		"invalid bytes":   strings.Repeat("\xff", 300),
		"bidi marks":      strings.Repeat("\u202e", 300),
		"two byte runes":  strings.Repeat("é", 300),
		"four byte runes": strings.Repeat("😀", 300),
		"printable":       strings.Repeat("a", 300),
	}
	for name, text := range texts {
		t.Run(name, func(t *testing.T) {
			entry := scanner.PluginConfig{Name: text, File: text + ".so"}
			dropped := make([]scanner.PluginConfig, 60)
			for i := range dropped {
				dropped[i] = entry
			}
			got := removedFilesizeWarning(dropped, "")
			if !utf8.ValidString(got) {
				t.Error("the message is not valid UTF-8")
			}
			if n := strings.Count(got, "(file "); n != maxReportedKeys {
				t.Errorf("%d entries keep their file part, want the %d listed", n, maxReportedKeys)
			}
			if !strings.Contains(got, "10 more") {
				t.Errorf("the message does not say how many entries are not listed: %.200q", got)
			}
			for _, raw := range []string{"\x01", "\xff", "\u202e"} {
				if strings.Contains(got, raw) {
					t.Errorf("the message holds the raw %q", raw)
				}
			}
			if len(got) > maxReportedKeys*(maxReportedNameLen+maxReportedFileLen+16)+1024 {
				t.Errorf("the message is %d bytes long", len(got))
			}
		})
	}
}

func TestQuoteBounded(t *testing.T) {
	tests := []struct {
		name   string
		in     string
		budget int
		whole  bool
	}{
		{"short", "abc", 20, true},
		{"fits exactly", "abcd", 6, true},
		{"an invalid byte", "a\xffb", 20, true},
		{"a bidi mark", "a\u202eb", 20, true},
		{"control bytes", strings.Repeat("\x01", 100), 40, false},
		{"invalid bytes", strings.Repeat("\xfe", 100), 40, false},
		{"two byte runes", strings.Repeat("é", 100), 40, false},
		{"four byte runes", strings.Repeat("😀", 100), 40, false},
		{"bidi", strings.Repeat("\u202e", 100), 40, false},
		{"a budget below the mark", "abcdef", 3, false},
		{"a budget of zero", "abcdef", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := quoteBounded(tt.in, tt.budget)
			if !utf8.ValidString(got) {
				t.Errorf("not valid UTF-8: %q", got)
			}
			if !strings.HasPrefix(got, `"`) || !strings.HasSuffix(got, `"`) {
				t.Errorf("not quoted: %q", got)
			}
			if tt.whole {
				if want := strconv.Quote(tt.in); got != want {
					t.Errorf("quoteBounded() = %q, want %q", got, want)
				}
				return
			}
			if !strings.HasSuffix(got, truncationMark+`"`) {
				t.Errorf("a cut text lacks the mark: %q", got)
			}
			if len(got) > max(tt.budget, len(truncationMark)+2) {
				t.Errorf("quoteBounded() is %d bytes, budget %d: %q", len(got), tt.budget, got)
			}
		})
	}
}

// The unknown keys of a configuration come from the network: they are quoted and
// bounded too.
func TestReportUnknownKeys_quotesWhatTheNetworkSends(t *testing.T) {
	rec := recordEvents(t)
	logs := captureHandlerLogs(t)
	h := new(Handler)
	h.reportUnknownKeys(t.Context(), []string{"ok\nERROR forged line\x1b[31m\u202e", strings.Repeat("\x01", 1000)})
	events := rec.find("error", HostConfigUnknownKeys)
	if len(events) != 1 {
		t.Fatalf("%d events, want one", len(events))
	}
	for name, text := range map[string]string{"event": events[0].msg, "log": logs.String()} {
		for _, raw := range []string{"\n", "\x1b", "\u202e", "\x01"} {
			if name == "log" && raw == "\n" {
				continue // the log line ends with one
			}
			if strings.Contains(text, raw) {
				t.Errorf("%s holds the raw %q: %.200q", name, raw, text)
			}
		}
	}
}
