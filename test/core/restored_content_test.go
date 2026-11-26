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
		{
			name: "empty files passed, refused by a forbidden path",
			scenario: harness.Scenario{
				Agent: true,
				Config: harness.MergeMaps(harness.PathFilter([]string{`/forbidden/`}, nil),
					map[string]any{"unanalyzable_policy": map[string]any{"empty": "pass"}}),
				Files: []harness.File{{Path: "forbidden/empty-a.bin"}},
				Steps: []harness.Step{
					harness.Await("forbidden/empty-a.bin", harness.Outcome{In: harness.Quarantine, Malware: datamodel.FilteredFilePath}),
					harness.Restore("forbidden/empty-a.bin", ""),
					harness.AddFileToInput(harness.File{Path: "forbidden/elsewhere/empty-b.bin"}),
				},
				Want: map[string]harness.Outcome{
					"forbidden/empty-a.bin":           {In: harness.Output, Restored: true},
					"forbidden/elsewhere/empty-b.bin": {In: harness.Quarantine, Malware: datamodel.FilteredFilePath},
				},
				WantMitigations: []string{"filepath", "filepath"},
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
// SHA256) holding one restored entry of content at restored, or at a location
// of its own when restored is empty.
func oldRegistry(t *testing.T, restored string, content []byte) string {
	t.Helper()
	dir := t.TempDir()
	if restored == "" {
		restored = filepath.Join(dir, "old.bin")
	}
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
	sha := gmalware.SHA256Hex(content)
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
				Config: map[string]any{"quarantine": map[string]any{"registry": oldRegistry(t, "", tt.content)}},
				Files:  []harness.File{{Path: "again.bin", Content: tt.content, Verdict: harness.Malicious}},
				Want: map[string]harness.Outcome{
					"again.bin": {In: harness.Quarantine, Malware: datamodel.MalwareDetected},
				},
			})
		})
	}
}

// Design §4.4, Q3 option A: a registry of the previous version, with its index
// on the SHA256, keeps releasing the file it restored, at its place: delivered
// with the restored mark. The same content anywhere else is a new file,
// analyzed and quarantined.
func TestE2E_aFileRestoredInAnOldRegistryStaysReleasedAtItsPlace(t *testing.T) {
	t.Parallel()
	content := []byte("a malware restored at its place with the previous version")
	gm := gmalware.New(t)
	gm.MarkMalicious(content)
	in := harness.Start(t, gm, harness.Options{Agent: true})
	in.WaitMonitoring(t)
	kept := filepath.Join(in.Input, "tom", "kept.bin")
	elsewhere := filepath.Join(in.Input, "tom", "other", "kept.bin")
	in.Restart(t, map[string]any{"quarantine": map[string]any{"registry": oldRegistry(t, kept, content)}})
	in.Expect.Release(kept, content)

	harness.DropAt(t, kept, content)
	harness.DropAt(t, elsewhere, content)
	in.WaitFor(t, "the released file delivered", func() bool { return in.InOutput("kept.bin") })
	in.AwaitQuarantine(t, elsewhere, content)
	in.WaitFor(t, "the restored entry of the released file", func() bool { return restoredEntryAt(in, kept, content) })
	if restoredEntryAt(in, elsewhere, content) {
		t.Error("the same content elsewhere is reported restored")
	}
}
