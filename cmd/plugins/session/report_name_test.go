//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/glimps-re/host-connector/pkg/datamodel"
)

// The real session reports are written by the plugin straight into the export
// folders, under the reserved prefix: they never go through the Move action,
// which refuses that prefix.
func TestSessionPlugin_reportsAreWrittenUnderTheReservedPrefix(t *testing.T) {
	exports := []string{t.TempDir(), t.TempDir()}
	hcc := newMockHCC(t)
	plugin := &SessionPlugin{}
	if err := plugin.Init(&Config{ReportTimeout: time.Minute, MaxDuration: 24 * time.Hour, MaxSpoolSize: "1GiB", InflightTimeout: 24 * time.Hour, RootFolder: t.TempDir(), Depth: 1, Delay: time.Hour, Exports: exports}, hcc); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := plugin.Close(t.Context()); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
	start := time.Unix(1_700_000_000, 0)
	session := testSession(t, "team/sub", start, []string{filepath.Join(exports[0], "team"), filepath.Join(exports[1], "team")}, datamodel.Report{Filename: "a"})
	_ = plugin.writeSessionReport(t.Context(), newClosing(session), viaGenerator)

	for _, dir := range session.Paths {
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != 1 {
			t.Fatalf("%s: entries = %v, %v; want the session report", dir, entries, err)
		}
		name := entries[0].Name()
		if !strings.HasPrefix(name, datamodel.SessionReportPrefix) || !strings.HasSuffix(name, ".pdf") || strings.Contains(name, "/") {
			t.Errorf("report name = %q, want %s<session>-<start>.pdf", name, datamodel.SessionReportPrefix)
		}
		if b, err := os.ReadFile(filepath.Clean(filepath.Join(dir, name))); err != nil || len(b) == 0 {
			t.Errorf("report content = %q, %v", b, err)
		}
	}
}
