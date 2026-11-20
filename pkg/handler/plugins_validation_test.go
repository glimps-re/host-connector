package handler

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/glimps-re/connector-integration/sdk"
	"github.com/glimps-re/host-connector/pkg/config"
	"github.com/glimps-re/host-connector/pkg/scanner"
)

func pluginsFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "plugins.yml")
	if err := os.WriteFile(path, []byte("fake:\n  file: /nonexistent/fake.so\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func validationDirs(t *testing.T, base string) []string {
	t.Helper()
	dirs, err := filepath.Glob(filepath.Join(base, "gmhost-validate-*"))
	if err != nil {
		t.Fatal(err)
	}
	return dirs
}

func TestApply_pluginValidationFailureKeepsRunningConfigAndLeavesNothing(t *testing.T) {
	rec := recordEvents(t)
	good := validConf(t, t.TempDir())
	h := newRunningHandler(t, good)
	conn := h.Conn

	work := t.TempDir()
	bad := validConf(t, t.TempDir())
	bad.WorkDir = work
	bad.PluginsConfig = pluginsFile(t)
	var scratch string
	h.validatePlugins = func(_ []scanner.PluginConfig, vc *scanner.ValidationContext) error {
		scratch = vc.GetWorkDir()
		if err := os.WriteFile(filepath.Join(scratch, "extracted-7z"), []byte("binary"), 0o600); err != nil {
			t.Fatal(err)
		}
		return errors.New("7z cannot run: noexec mount")
	}
	err := h.Configure(t.Context(), rawConf(t, bad))
	if err == nil || !strings.Contains(err.Error(), "noexec") {
		t.Fatalf("Configure() error = %v, want the plugin failure", err)
	}
	if h.Conn != conn || h.Status() != sdk.Started || h.conf != good {
		t.Error("a configuration refused by a plugin must leave the running connector in place")
	}
	if got := len(rec.find("error", HostConfigRejected)); got != 1 {
		t.Errorf("host-config-rejected events = %d, want 1", got)
	}
	if scratch == "" {
		t.Fatal("Validate was not called")
	}
	if dirs := validationDirs(t, work); len(dirs) != 0 {
		t.Errorf("validation directories left behind: %v", dirs)
	}
}

func TestApply_firstStartWithFailingPluginValidation(t *testing.T) {
	rec := recordEvents(t)
	h := new(Handler)
	h.stopped = true
	h.validatePlugins = func([]scanner.PluginConfig, *scanner.ValidationContext) error {
		return errors.New("plugin cannot work")
	}
	conf := validConf(t, t.TempDir())
	conf.PluginsConfig = pluginsFile(t)
	if err := h.setup(t.Context(), conf); err == nil {
		t.Fatal("setup() error = nil, want a refusal to start")
	}
	if h.Status() != sdk.Stopped || h.Conn != nil || h.monitor != nil {
		t.Error("nothing must run after a refused first start")
	}
	if err := h.Start(t.Context()); err == nil {
		t.Error("Start() error = nil, want the same failure without panic")
	}
	if got := len(rec.find("error", HostConfigError)); got != 2 {
		t.Errorf("host-bad-config events = %d, want 2", got)
	}
}

func TestCheckDeclarations(t *testing.T) {
	base := t.TempDir()
	watched := filepath.Join(base, "in")
	moveDest := filepath.Join(base, "out")
	quarantineDir := filepath.Join(base, "quarantine")
	conf := &config.Config{}
	conf.Paths = []string{watched}
	conf.Move.Destination = moveDest
	conf.Actions.Quarantine = true
	conf.Quarantine.Location = quarantineDir
	otherOut := filepath.Join(base, "results")

	tests := []struct {
		name    string
		decl    scanner.Declarations
		wantErr string
	}{
		{name: "nothing declared"},
		{name: "output directory elsewhere", decl: scanner.Declarations{OutputDirs: []string{otherOut}}},
		{name: "output directory equal to a monitored path", decl: scanner.Declarations{OutputDirs: []string{watched}}, wantErr: "monitored path"},
		{name: "output directory under a monitored path", decl: scanner.Declarations{OutputDirs: []string{filepath.Join(watched, "reports")}}, wantErr: "monitored path"},
		{name: "output directory overlapping the quarantine", decl: scanner.Declarations{OutputDirs: []string{filepath.Join(quarantineDir, "x")}}, wantErr: "quarantine"},
		{name: "executable under a monitored path", decl: scanner.Declarations{Executables: []string{filepath.Join(watched, "bin", "7z")}}, wantErr: "monitored path"},
		{name: "executable under move.destination", decl: scanner.Declarations{Executables: []string{filepath.Join(moveDest, "7z")}}, wantErr: "move.destination"},
		{name: "executable under an output directory", decl: scanner.Declarations{Executables: []string{filepath.Join(otherOut, "7z")}, OutputDirs: []string{otherOut}}, wantErr: "output directory"},
		{name: "output directory under move.destination", decl: scanner.Declarations{OutputDirs: []string{filepath.Join(moveDest, "results")}}, wantErr: "move.destination"},
		{name: "executable elsewhere", decl: scanner.Declarations{Executables: []string{filepath.Join(base, "bin", "7z")}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkDeclarations(conf, tt.decl)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("checkDeclarations() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("checkDeclarations() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestCheckDeclarations_linkUnderAWatchedPathPointingOutside(t *testing.T) {
	base := t.TempDir()
	watched := filepath.Join(base, "in")
	outside := filepath.Join(base, "bin")
	for _, d := range []string{watched, outside} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	target := filepath.Join(outside, "7zzs")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(watched, "7zzs")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	conf := &config.Config{}
	conf.Paths = []string{watched}
	// The configured form is under the watched path although the target is not.
	err := checkDeclarations(conf, scanner.Declarations{Executables: []string{target, link}})
	if err == nil || !strings.Contains(err.Error(), "monitored path") {
		t.Errorf("checkDeclarations() error = %v, want the configured form refused", err)
	}
}

func TestReadPluginsConfig_unsafeFileRefused(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the ownership rules differ for root")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, modeOwnerOnly); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "plugins.yml")
	if err := os.WriteFile(path, []byte("fake:\n  file: /x/fake.so\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, modeWritableByOthersPlugins); err != nil {
		t.Fatal(err)
	}
	if _, err := readPluginsConfig(path); err == nil {
		t.Error("readPluginsConfig() accepted a plugins file writable by others")
	}
}

// modeWritableByOthersPlugins is the unsafe mode under test.
const modeWritableByOthersPlugins fs.FileMode = 0o606
