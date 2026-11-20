package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/glimps-re/host-connector/pkg/plugins"
	"github.com/glimps-re/host-connector/pkg/plugins/mock"
)

// modeWritableByOthers is the unsafe mode under test.
const (
	modeWritableByOthers fs.FileMode = 0o707
	modeExecutableOwner  fs.FileMode = 0o500
)

func TestSevenZipExtractPlugin_Validate(t *testing.T) {
	good := func() *Config {
		return &Config{MaxFileSize: "100MB", MaxTotalExtractedSize: "3GB", MaxExtractedFiles: 10}
	}
	tests := []struct {
		name         string
		mutate       func(c *Config)
		declareErr   error
		wantErr      bool
		wantDeclared string
	}{
		{name: "valid, embedded binary"},
		{name: "valid, configured binary", mutate: func(c *Config) { c.SevenZipPath = "/opt/7z/7zzs" }, wantDeclared: "/opt/7z/7zzs"},
		{name: "unsafe configured binary", mutate: func(c *Config) { c.SevenZipPath = "/tmp/7zzs" }, declareErr: errors.New("unsafe executable"), wantErr: true, wantDeclared: "/tmp/7zzs"},
		{name: "unparsable max_file_size", mutate: func(c *Config) { c.MaxFileSize = "many" }, wantErr: true},
		{name: "unparsable max_total_extracted_size", mutate: func(c *Config) { c.MaxTotalExtractedSize = "many" }, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conf := good()
			if tt.mutate != nil {
				tt.mutate(conf)
			}
			hcc := mock.NewMockHCContext()
			hcc.DeclareExecutableErr = tt.declareErr
			var p SevenZipExtractPlugin
			if err := p.Validate(conf, hcc); (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %t", err, tt.wantErr)
			}
			if tt.wantDeclared == "" && len(hcc.Executables) != 0 {
				t.Errorf("declared executables = %v, want none", hcc.Executables)
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
	if err := p.Validate("x", mock.NewMockHCContext()); err == nil {
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

	binary := filepath.Join(t.TempDir(), "7zzs")
	if err := os.WriteFile(binary, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := SevenZipExtractPlugin{sze: &sevenZipExtract{sevenZipPath: binary, tmpSevenZip: true}}
	for range 2 {
		if err := p.Close(t.Context()); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}
	if _, err := os.Stat(binary); !errors.Is(err, os.ErrNotExist) {
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
	hcc := mock.NewMockHCContext()
	hcc.DeclareExecutableFunc = func(path string) error {
		_, _, err := plugins.CheckExecutable(path)
		return err
	}
	conf := &Config{MaxFileSize: "1MB", MaxTotalExtractedSize: "1MB", MaxExtractedFiles: 1, SevenZipPath: binary}
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
	hcc := mock.NewMockHCContext()
	hcc.DeclareExecutableFunc = func(path string) error {
		_, _, err := plugins.CheckExecutable(path)
		return err
	}
	conf := &Config{MaxFileSize: "1MB", MaxTotalExtractedSize: "1MB", MaxExtractedFiles: 1, SevenZipPath: link}
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
