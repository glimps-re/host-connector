//go:build linux

package plugins

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Modes under test: named constants, they are what CheckExecutable inspects.
const (
	modeExecOwner      fs.FileMode = 0o500
	modeExecGroupWrite fs.FileMode = 0o770
	modeExecOthersW    fs.FileMode = 0o702
	modeDirOwner       fs.FileMode = 0o700
	modeDirGroupWrite  fs.FileMode = 0o770
	modeDirOthersWrite fs.FileMode = 0o707
	modePlain          fs.FileMode = 0o600
)

func makeBinary(t *testing.T, dir, name string, mode fs.FileMode) string {
	t.Helper()
	if err := os.MkdirAll(dir, modeDirOwner); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, modeDirOwner); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), modePlain); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCheckExecutable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the ownership rules differ for root")
	}
	base := t.TempDir()
	good := makeBinary(t, filepath.Join(base, "good"), "tool", modeExecOwner)
	link := filepath.Join(base, "link")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	notExec := makeBinary(t, filepath.Join(base, "plain"), "tool", modePlain)
	fileOthers := makeBinary(t, filepath.Join(base, "fileothers"), "tool", modeExecOthersW)
	fileGroup := makeBinary(t, filepath.Join(base, "filegroup"), "tool", modeExecGroupWrite)
	dirOthers := makeBinary(t, filepath.Join(base, "dirothers"), "tool", modeExecOwner)
	if err := os.Chmod(filepath.Dir(dirOthers), modeDirOthersWrite); err != nil {
		t.Fatal(err)
	}
	dirGroup := makeBinary(t, filepath.Join(base, "dirgroup"), "tool", modeExecOwner)
	if err := os.Chmod(filepath.Dir(dirGroup), modeDirGroupWrite); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name         string
		path         string
		wantErr      string
		wantWarnings int
		wantResolved string
	}{
		{name: "good binary", path: good, wantResolved: good},
		{name: "user symlink to a safe binary is refused", path: link, wantErr: "symbolic link"},
		{name: "relative path", path: "tool", wantErr: "not absolute"},
		{name: "missing", path: filepath.Join(base, "missing"), wantErr: "not found"},
		{name: "directory", path: filepath.Dir(good), wantErr: "not a regular file"},
		{name: "no execute bit", path: notExec, wantErr: "no execute permission"},
		{name: "file writable by others", path: fileOthers, wantErr: "writable by others"},
		{name: "directory writable by others", path: dirOthers, wantErr: "writable by others"},
		{name: "file writable by the group warns", path: fileGroup, wantWarnings: 1, wantResolved: fileGroup},
		{name: "directory writable by the group warns", path: dirGroup, wantWarnings: 1, wantResolved: dirGroup},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolved, warnings, err := CheckExecutable(tt.path)
			if tt.wantErr != "" {
				if !errors.Is(err, ErrUnsafeExecutable) || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("CheckExecutable() error = %v, want ErrUnsafeExecutable containing %q", err, tt.wantErr)
				}
				if !strings.Contains(err.Error(), "; ") {
					t.Errorf("error %q must give the remedy", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("CheckExecutable() error = %v", err)
			}
			if resolved != tt.wantResolved {
				t.Errorf("resolved = %q, want %q", resolved, tt.wantResolved)
			}
			if len(warnings) != tt.wantWarnings {
				t.Errorf("warnings = %v, want %d", warnings, tt.wantWarnings)
			}
		})
	}
}

func TestCheckPluginFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the ownership rules differ for root")
	}
	base := t.TempDir()
	good := makeBinary(t, filepath.Join(base, "good"), "plugin.so", modePlain)
	othersWritable := makeBinary(t, filepath.Join(base, "others"), "plugin.so", modeExecOthersW)
	linked := filepath.Join(base, "link.so")
	if err := os.Symlink(good, linked); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		path    string
		wantErr string
	}{
		{name: "owned, not writable by others, no execute bit needed", path: good},
		{name: "writable by others", path: othersWritable, wantErr: "writable by others"},
		{name: "reached through a user link", path: linked, wantErr: "symbolic link"},
		{name: "relative", path: "plugin.so", wantErr: "not absolute"},
		{name: "missing", path: filepath.Join(base, "missing.so"), wantErr: "cannot be examined"},
		{name: "directory", path: base, wantErr: "not a regular file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := CheckPluginFile(tt.path)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("CheckPluginFile() error = %v", err)
				}
				return
			}
			if !errors.Is(err, ErrUnsafeExecutable) || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("CheckPluginFile() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestCheckPluginFile_checksTheResolvedDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the ownership rules differ for root")
	}
	base := t.TempDir()
	target := makeBinary(t, filepath.Join(base, "targetdir"), "plugin.so", modePlain)
	if err := os.Chmod(filepath.Dir(target), modeDirOthersWrite); err != nil {
		t.Fatal(err)
	}
	// A path that reaches the file only through the directory writable by
	// others is refused: the check is made on the resolved directory.
	if _, err := CheckPluginFile(target); !errors.Is(err, ErrUnsafeExecutable) {
		t.Fatalf("CheckPluginFile() error = %v, want the directory writable by others refused", err)
	}
}
