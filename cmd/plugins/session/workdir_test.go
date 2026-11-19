package main

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/glimps-re/host-connector/pkg/plugins/mock"
)

func TestSessionPlugin_ignoresWorkDir(t *testing.T) {
	const root = "/srv/in"
	plugin := &SessionPlugin{}
	hcc := mock.NewMockHCContext()
	hcc.WorkDir = root + "/tmp/gmhost-abc"
	if err := plugin.Init(&Config{RootFolder: root, Depth: 1, Delay: time.Second}, hcc); err != nil {
		t.Fatalf("Init() error = %v, a work directory deeper than the root is only a warning case", err)
	}
	t.Cleanup(func() {
		if err := plugin.Close(t.Context()); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})

	tests := []struct {
		name string
		path string
		want string
	}{
		{"user deposit", root + "/team/a.txt", "team"},
		{"work dir file", root + "/tmp/gmhost-abc/extract/x-1/a.txt", ""},
		{"work dir itself", root + "/tmp/gmhost-abc", ""},
		{"sibling with the same prefix", root + "/tmp/gmhost-abcd/a.txt", "tmp"},
		{"folder named ..x stays in its session", root + "/..x/a.txt", "..x"},
		{"outside root", "/srv/other/a.txt", ""},
		{"parent of root", "/srv/a.txt", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := plugin.getSession(tt.path, true)
			switch {
			case tt.want == "" && got != nil:
				t.Errorf("getSession(%q) = session %q, want none", tt.path, got.ID)
			case tt.want != "" && (got == nil || got.ID != tt.want):
				t.Errorf("getSession(%q) = %+v, want session %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestSessionPlugin_InitRefusesWorkDirBaseAsRoot(t *testing.T) {
	for _, root := range []string{"/srv/in", "/srv/in/"} {
		plugin := &SessionPlugin{}
		hcc := mock.NewMockHCContext()
		hcc.WorkDir = "/srv/in/gmhost-abc"
		err := plugin.Init(&Config{RootFolder: root, Depth: 1, Delay: time.Second}, hcc)
		if err == nil || !strings.Contains(err.Error(), "work_dir") {
			t.Errorf("Init(root %q) error = %v, want a refusal naming work_dir", root, err)
		}
	}
}

func TestSessionPlugin_InitRefusesRootFolderLinkedToWorkDirBase(t *testing.T) {
	base := t.TempDir()
	link := filepath.Join(t.TempDir(), "root-link")
	if err := os.Symlink(base, link); err != nil {
		t.Fatal(err)
	}
	plugin := &SessionPlugin{}
	hcc := mock.NewMockHCContext()
	hcc.WorkDir = filepath.Join(base, "gmhost-abc")
	err := plugin.Init(&Config{RootFolder: link, Depth: 1, Delay: time.Second}, hcc)
	if err == nil || !strings.Contains(err.Error(), "work_dir") {
		t.Errorf("Init() error = %v, want a refusal: root_folder is a link to the work_dir base", err)
	}
}

func TestSessionPlugin_InitWarnsWorkDirUnderRoot(t *testing.T) {
	var logs, console bytes.Buffer
	hcc := mock.NewMockHCContext()
	hcc.Logger = slog.New(slog.NewJSONHandler(&logs, nil))
	hcc.ConsoleLogger = slog.New(slog.NewJSONHandler(&console, nil))
	hcc.WorkDir = "/srv/in/tmp/gmhost-abc"
	plugin := &SessionPlugin{}
	if err := plugin.Init(&Config{RootFolder: "/srv/in", Depth: 1, Delay: time.Second}, hcc); err != nil {
		t.Fatalf("Init() error = %v: a work directory under root_folder is only a warning", err)
	}
	t.Cleanup(func() {
		if err := plugin.Close(t.Context()); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
	for name, buf := range map[string]*bytes.Buffer{"log": &logs, "console": &console} {
		if !strings.Contains(buf.String(), "work directory") || !strings.Contains(buf.String(), `"level":"WARN"`) {
			t.Errorf("%s = %q, want a Warn about the work directory under root_folder", name, buf.String())
		}
	}
}
