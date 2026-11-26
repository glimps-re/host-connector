//go:build linux && (e2e || e2e_core)

package core

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	hcquarantine "github.com/glimps-re/host-connector/pkg/quarantine"
	"github.com/glimps-re/host-connector/test/internal/fakes/gmalware"
	"github.com/glimps-re/host-connector/test/internal/harness"
)

// Restoring one empty file does not make every empty file safe; another empty
// file dropped elsewhere is quarantined again.
func TestE2E_aRestoredEmptyFileDoesNotMakeTheOtherEmptyFilesSafe(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		scenario harness.Scenario
	}{
		{
			name: "empty at mitigate, another empty file in another folder",
			scenario: harness.Scenario{
				Agent:  true,
				Config: map[string]any{"unanalyzable_policy": map[string]any{"empty": "mitigate"}},
				Files:  []harness.File{{Path: "empty-a.bin"}},
				Steps: []harness.Step{
					harness.Await("empty-a.bin", harness.Outcome{In: harness.Quarantine, Malware: datamodel.Empty}),
					harness.Restore("empty-a.bin", ""),
					harness.AddFileToInput(harness.File{Path: "elsewhere/empty-b.bin"}),
				},
				Want: map[string]harness.Outcome{
					"empty-a.bin":           {In: harness.Output, Restored: true},
					"elsewhere/empty-b.bin": {In: harness.Quarantine, Malware: datamodel.Empty},
				},
				WantMitigations: []string{"invalid", "invalid"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			harness.Run(t, tt.scenario)
		})
	}
}

// oldRegistry writes a registry of the previous version (with its index on the
// SHA256) holding one restored entry of content, at a location of its own.
func oldRegistry(t *testing.T, content []byte) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "old-registry.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if e := db.Close(); e != nil {
			t.Error(e)
		}
	}()
	for _, stmt := range []string{`CREATE TABLE entries (
	id TEXT PRIMARY KEY,
	sha256 TEXT,
	created_at int NOT NULL,
	updated_at int NOT NULL,
	quarantine TEXT,
	location TEXT,
	restored_at int);`, `CREATE INDEX idx_entries_sha256 ON entries(sha256);`} {
		if _, err = db.ExecContext(t.Context(), stmt); err != nil {
			t.Fatal(err)
		}
	}
	sha, restored := gmalware.SHA256Hex(content), filepath.Join(dir, "old.bin")
	if _, err = db.ExecContext(t.Context(), "INSERT INTO entries(id, sha256, created_at, updated_at, quarantine, location, restored_at) VALUES(?,?,?,?,?,?,?)",
		hcquarantine.ComputeCacheID(restored, sha), sha, 1, 1, filepath.Join(dir, "old.lock"), restored, time.Now().UnixMilli()); err != nil {
		t.Fatal(err)
	}
	return path
}

// A registry of the previous version opens, and a content it restored at one
// location is a new file anywhere else: analyzed and quarantined.
func TestE2E_aContentRestoredInAnOldRegistryIsNotReleasedElsewhere(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		content []byte
	}{
		{name: "a malware restored with the previous version", content: []byte("a malware restored with a registry of the previous version")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			harness.Run(t, harness.Scenario{
				Config: map[string]any{"quarantine": map[string]any{"registry": oldRegistry(t, tt.content)}},
				Files:  []harness.File{{Path: "again.bin", Content: tt.content, Verdict: harness.Malicious}},
				Want: map[string]harness.Outcome{
					"again.bin": {In: harness.Quarantine, Malware: datamodel.MalwareDetected},
				},
			})
		})
	}
}
