//go:build linux

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/glimps-re/host-connector/pkg/plugins"
)

func scriptPath(t *testing.T, body string) string {
	t.Helper()
	return fakeSevenZip(t, body).sevenZipPath
}

func entriesOf(t *testing.T, dir string) []string {
	t.Helper()
	list, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, len(list))
	for i, e := range list {
		names[i] = e.Name()
	}
	return names
}

func TestT24_unsuitableConfiguredBinaryIsRefusedAndLeavesNothingBehind(t *testing.T) {
	prev := proofTimeout
	proofTimeout = 2 * time.Second
	t.Cleanup(func() { proofTimeout = prev })
	tests := map[string]string{
		"exits with code 1": "exit 1",
		"no banner":         "echo hello",
		"hangs":             "sleep 60",
		"endless output":    "yes",
		"writes 100 MB":     "head -c 104857600 /dev/zero",
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			tmp := t.TempDir()
			t.Setenv("TMPDIR", tmp)
			binary := scriptPath(t, body)
			// The script lives in its own folder, outside what the plugin may touch.
			before := entriesOf(t, tmp)
			cfg := realConfig()
			cfg.SevenZipPath = binary

			validateCtx := newMockContext(t)
			var q SevenZipExtractPlugin
			start := time.Now()
			if err := q.Validate(cfg, validateCtx); err == nil {
				t.Fatal("Validate() accepted a binary that is not a 7-Zip")
			}
			initCtx := newMockContext(t)
			var p SevenZipExtractPlugin
			if err := p.Init(cfg, initCtx); err == nil {
				t.Fatal("Init() accepted a binary that is not a 7-Zip")
			}
			if d := time.Since(start); d > 30*time.Second {
				t.Errorf("Validate and Init took %v: the test of the binary must be bounded", d)
			}
			for _, wd := range []string{validateCtx.WorkDir, initCtx.WorkDir} {
				if left := entriesOf(t, wd); len(left) != 0 {
					for _, e := range left {
						if sub := entriesOf(t, filepath.Join(wd, e)); len(sub) != 0 {
							t.Errorf("a failed run left %s/%s holding %v", wd, e, sub)
						}
					}
					if strings.Join(left, ",") != binDirName && len(left) != 0 {
						t.Errorf("a failed run left %v in the work directory", left)
					}
				}
			}
			if after := entriesOf(t, tmp); strings.Join(after, ",") != strings.Join(before, ",") {
				t.Errorf("TMPDIR holds %v after a failed run, was %v", after, before)
			}
			if _, err := os.Stat(binary); err != nil {
				t.Errorf("a configured binary must never be removed: %v", err)
			}
		})
	}
}

func TestT24_configuredRealBinaryIsUsedAndKeptOnClose(t *testing.T) {
	embedded := realPlugin(t).sze.sevenZipPath
	cfg := realConfig()
	cfg.SevenZipPath = embedded
	hcc := newMockContext(t)
	var p SevenZipExtractPlugin
	if err := p.Init(cfg, hcc); err != nil {
		t.Fatalf("Init() with seven_zip_path error = %v", err)
	}
	if len(hcc.Executables) != 1 || hcc.Executables[0] != embedded {
		t.Errorf("declared executables %v, want only %s", hcc.Executables, embedded)
	}
	if left := entriesOf(t, hcc.WorkDir); len(left) != 0 {
		t.Errorf("a configured binary must not be deployed: work directory holds %v", left)
	}
	if err := p.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(embedded); err != nil {
		t.Errorf("Close removed the configured binary: %v", err)
	}
}

func TestT24_olderVersionBannerIsRefused(t *testing.T) {
	// A binary that prints the expected listing but announces 7-Zip 24.09: the
	// protections of the analysis are only established for 25.01.
	sze := fakeBinary(t, "7-Zip (z) 24.09 (x64) : Copyright (c) 1999-2024 Igor Pavlov", refListing, goodExtract)
	err := prove(sze, t.TempDir())
	if err == nil {
		t.Fatal("prove() accepted a 7-Zip 24.09: the version gate is missing")
	}
	if !strings.Contains(err.Error(), "version") {
		t.Errorf("prove() error = %v, want it to name the version", err)
	}
}

func TestT24_unavailableIsNeverAnArchiveVerdict(t *testing.T) {
	for name, path := range map[string]string{
		"missing": filepath.Join(t.TempDir(), "absent"),
		"not executable": func() string {
			p := filepath.Join(t.TempDir(), "7zzs")
			_ = os.WriteFile(p, []byte("#!/bin/sh\n"), 0o600)
			return p
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			sze := fakeSevenZip(t, "exit 0")
			sze.sevenZipPath = path
			bigConfig(sze)
			p := &SevenZipExtractPlugin{sze: sze, logger: sze.logger, consoleLogger: sze.logger}
			_, err := p.ExtractFile(fixture(t, "wildcard.7z"), t.TempDir(), openLimits)
			if !errors.Is(err, plugins.ErrExtractorUnavailable) {
				t.Errorf("ExtractFile() error = %v, want ErrExtractorUnavailable", err)
			}
			if errors.Is(err, plugins.ErrUnsupportedFormat) || errors.Is(err, plugins.ErrEncrypted) {
				t.Errorf("ExtractFile() error = %v: an extractor that cannot run says nothing about the archive", err)
			}
		})
	}
}
