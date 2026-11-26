//go:build linux

package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/glimps-re/host-connector/pkg/plugins"
)

// modeWritableByOthers is the unsafe mode under test.
const (
	modeWritableByOthers fs.FileMode = 0o707
	modeExecutableOwner  fs.FileMode = 0o500
)

func TestSevenZipExtractPlugin_Validate(t *testing.T) {
	good := func() *Config {
		return &Config{}
	}
	tests := []struct {
		name         string
		mutate       func(c *Config)
		declareErr   error
		wantErr      bool
		wantDeclared string
		wantDeployed bool
	}{
		{name: "valid, embedded binary", wantDeployed: true},
		{name: "valid, configured binary", mutate: func(c *Config) { c.SevenZipPath = "/opt/7z/7zzs" }, wantDeclared: "/opt/7z/7zzs"},
		{name: "unsafe configured binary", mutate: func(c *Config) { c.SevenZipPath = "/tmp/7zzs" }, declareErr: errors.New("unsafe executable"), wantErr: true, wantDeclared: "/tmp/7zzs"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conf := good()
			if tt.mutate != nil {
				tt.mutate(conf)
			}
			stubProve(t)
			hcc := newMockContext(t)
			hcc.DeclareExecutableErr = tt.declareErr
			var p SevenZipExtractPlugin
			if err := p.Validate(conf, hcc); (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %t", err, tt.wantErr)
			}
			if tt.wantDeployed && (len(hcc.Executables) != 1 || !strings.HasPrefix(hcc.Executables[0], filepath.Join(hcc.WorkDir, binDirName))) {
				t.Errorf("declared executables = %v, want the embedded binary deployed under the work directory", hcc.Executables)
			}
			if !tt.wantDeployed && tt.wantDeclared == "" && len(hcc.Executables) != 0 {
				t.Errorf("declared executables = %v, want none", hcc.Executables)
			}
			if entries, err := os.ReadDir(filepath.Join(hcc.WorkDir, binDirName)); err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Errorf("cannot read the deployment folder: %v", err)
			} else if len(entries) != 0 {
				t.Errorf("Validate left %d deployed binaries behind", len(entries))
			}
			if tt.wantDeclared != "" && (len(hcc.Executables) != 1 || hcc.Executables[0] != tt.wantDeclared) {
				t.Errorf("declared executables = %v, want %q", hcc.Executables, tt.wantDeclared)
			}
			if p.sze != nil {
				t.Error("Validate must not change the plugin state")
			}
		})
	}
	var p SevenZipExtractPlugin
	if err := p.Validate("x", newMockContext(t)); err == nil {
		t.Error("Validate() with a wrong config type: error = nil")
	}
}

func TestSevenZipExtractPlugin_CloseTwice(t *testing.T) {
	var neverInit SevenZipExtractPlugin
	for range 2 {
		if err := neverInit.Close(t.Context()); err != nil {
			t.Fatalf("Close() on a plugin never initialized error = %v", err)
		}
	}

	binaryPath := filepath.Join(t.TempDir(), "7zzs")
	if err := os.WriteFile(binaryPath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := SevenZipExtractPlugin{bin: &binary{path: binaryPath, deployDir: filepath.Dir(binaryPath)}}
	for range 2 {
		if err := p.Close(t.Context()); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}
	if _, err := os.Stat(binaryPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the deployed binary must be removed (stat error = %v)", err)
	}
}

func TestSevenZipExtractPlugin_unsafeBinaryIsNeverRun(t *testing.T) {
	dir := t.TempDir()
	witness := filepath.Join(dir, "witness")
	binary := filepath.Join(dir, "7zzs")
	script := "#!/bin/sh\necho ran > " + witness + "\n"
	if err := os.WriteFile(binary, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(binary, modeWritableByOthers); err != nil {
		t.Fatal(err)
	}
	hcc := newMockContext(t)
	hcc.DeclareExecutableFunc = func(path string) error {
		_, _, err := plugins.CheckExecutable(path)
		return err
	}
	conf := &Config{SevenZipPath: binary}
	var p SevenZipExtractPlugin
	if err := p.Validate(conf, hcc); err == nil {
		t.Error("Validate() accepted an executable writable by others")
	}
	if err := p.Init(conf, hcc); err == nil {
		t.Error("Init() accepted an executable writable by others")
	}
	if _, err := os.Stat(witness); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the unsafe binary was run (witness stat error = %v)", err)
	}
}

func TestSevenZipExtractPlugin_linkedBinaryIsNeverRun(t *testing.T) {
	dir := t.TempDir()
	witness := filepath.Join(dir, "witness")
	target := filepath.Join(dir, "real-7zzs")
	if err := os.WriteFile(target, []byte("#!/bin/sh\necho ran > "+witness+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, modeExecutableOwner); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "7zzs")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	hcc := newMockContext(t)
	hcc.DeclareExecutableFunc = func(path string) error {
		_, _, err := plugins.CheckExecutable(path)
		return err
	}
	conf := &Config{SevenZipPath: link}
	var p SevenZipExtractPlugin
	if err := p.Validate(conf, hcc); err == nil {
		t.Error("Validate() accepted a binary reached through a user-owned link")
	}
	if err := p.Init(conf, hcc); err == nil {
		t.Error("Init() accepted a binary reached through a user-owned link")
	}
	if _, err := os.Stat(witness); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the binary was run (witness stat error = %v)", err)
	}
}
