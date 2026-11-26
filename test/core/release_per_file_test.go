//go:build linux && (e2e || e2e_core)

package core

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/test/internal/fakes/gmalware"
	"github.com/glimps-re/host-connector/test/internal/harness"
)

// moveOff keeps every file in INPUT and rescans it every second: a released file
// stays where it was restored and is looked at again and again. It is a new map
// each time: MergeMaps writes into its first argument.
func moveOff() map[string]any {
	return map[string]any{
		"actions":    map[string]any{"move": false},
		"monitoring": map[string]any{"period": "1s"},
	}
}

// release quarantines the malware the test dropped at path, then restores it
// through the console, which declares the release to the checker of OUTPUT.
func release(t *testing.T, in *harness.Instance, path string, content []byte) {
	t.Helper()
	in.AwaitQuarantine(t, path, content)
	in.RestoreFile(t, path, content, "")
}

// awaitRestoredEntry waits for the report that says the file at path was
// restored.
func awaitRestoredEntry(t *testing.T, in *harness.Instance, path string, content []byte) {
	t.Helper()
	in.WaitFor(t, "the restored entry of "+path, func() bool { return restoredEntryAt(in, path, content) })
}

func restoredEntryAt(in *harness.Instance, path string, content []byte) bool {
	return slices.ContainsFunc(harness.ReadReports(in)[gmalware.SHA256Hex(content)], func(e datamodel.Report) bool {
		return e.Filename == path && harness.RestoredEntry(e)
	})
}

// staysReleased checks that the released file at path is still there, intact,
// over many rescans, and was never quarantined again.
func staysReleased(t *testing.T, in *harness.Instance, path string, content []byte) {
	t.Helper()
	in.StaysInInput(t, path, content)
	if !in.Gone(in.LockOf(path, content)) {
		t.Errorf("%s was quarantined again after its release", path)
	}
	if got, err := os.ReadFile(filepath.Clean(path)); err != nil || string(got) != string(content) {
		t.Errorf("%s holds %q (%v) after its release, want the released content", path, got, err)
	}
}

// Design §6.2, recipe scenarios 03/07/08/09/15: Tom's malware is released by an
// operator; Jerry deposits the same content later. Jerry's file is a new file,
// analyzed and quarantined; Tom's stays released, with the move on (delivered
// once, restored) or off (rescanned in INPUT, never quarantined again).
func TestE2E_tomsReleaseDoesNotFreeJerrysCopy(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		config map[string]any
		moveOn bool
	}{
		{name: "move off, rescan every second", config: moveOff()},
		{name: "move on", moveOn: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			bad := []byte("Tom's malware, released, then deposited by Jerry " + tt.name)
			gm := gmalware.New(t)
			gm.MarkMalicious(bad)
			in := harness.Start(t, gm, harness.Options{Agent: true, Config: tt.config})
			tom := filepath.Join(in.Input, "tom", "bad.txt")
			jerry := filepath.Join(in.Input, "jerry", "bad.txt")

			harness.DropAt(t, tom, bad)
			release(t, in, tom, bad)
			awaitRestoredEntry(t, in, tom, bad)
			if tt.moveOn {
				in.WaitFor(t, "Tom's file delivered", func() bool { return in.InOutput("bad.txt") })
			}

			harness.DropAt(t, jerry, bad)
			in.AwaitQuarantine(t, jerry, bad)
			if restoredEntryAt(in, jerry, bad) {
				t.Error("Jerry's copy is reported restored")
			}
			if _, err := os.Stat(filepath.Join(in.Output, "jerry", "bad.txt")); err == nil {
				t.Error("Jerry's copy was delivered")
			}
			if tt.moveOn {
				if !in.InOutput("bad.txt") {
					t.Error("Tom's released file left OUTPUT")
				}
				return
			}
			staysReleased(t, in, tom, bad)
		})
	}
}

// It checks the restart over the registry kept on disk: the connector cleans the
// paths it walks, the normalisation itself is covered by the unit tests.
// Design §3: a release is found again whatever the spelling of the location,
// once cleaned. The registry is kept on disk and the connector restarts on its
// INPUT spelled with "..", "//" and "./": the file restored before stays
// released. A folder that only differs by case is another folder (fail-closed).
func TestE2E_aReleaseHoldsUnderAnotherSpellingOfItsFolder(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		spell func(input string) string
	}{
		{name: "the same spelling", spell: func(input string) string { return input }},
		{name: "dot-dot", spell: func(input string) string { return input + "/../" + filepath.Base(input) + "/" }},
		{name: "double slash and dot", spell: func(input string) string { return filepath.Dir(input) + "//./" + filepath.Base(input) + "/." }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			bad := []byte("a malware released, then watched under another spelling " + tt.name)
			gm := gmalware.New(t)
			gm.MarkMalicious(bad)
			registry := filepath.Join(t.TempDir(), "registry.db")
			in := harness.Start(t, gm, harness.Options{Agent: true, Config: harness.MergeMaps(moveOff(), map[string]any{
				"quarantine": map[string]any{"registry": registry},
			})})
			tom := filepath.Join(in.Input, "tom", "bad.txt")
			harness.DropAt(t, tom, bad)
			release(t, in, tom, bad)
			awaitRestoredEntry(t, in, tom, bad)

			in.Restart(t, map[string]any{"paths": []string{tt.spell(in.Input)}})
			staysReleased(t, in, tom, bad)

			upper := filepath.Join(in.Input, "Tom", "bad.txt")
			harness.DropAt(t, upper, bad)
			in.AwaitQuarantine(t, upper, bad)
		})
	}
}

// Design §3 and D-002: a link to a released file is another file, the link is
// never resolved to find a release. Without follow_symlinks the link is not
// delivered as restored; with it, the link is analyzed and quarantined. Either
// way the released file itself stays, intact, and is not quarantined again.
func TestE2E_aLinkToAReleasedFileReleasesNothing(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		follow bool
	}{
		{name: "follow_symlinks off"},
		{name: "follow_symlinks on", follow: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			bad := []byte("a released malware that a link points to " + tt.name)
			gm := gmalware.New(t)
			gm.MarkMalicious(bad)
			in := harness.Start(t, gm, harness.Options{Agent: true, Config: harness.MergeMaps(moveOff(), map[string]any{"follow_symlinks": tt.follow})})
			tom := filepath.Join(in.Input, "tom", "bad.txt")
			harness.DropAt(t, tom, bad)
			release(t, in, tom, bad)
			awaitRestoredEntry(t, in, tom, bad)

			link := filepath.Join(in.Input, "tom", "other", "link.txt")
			if err := os.MkdirAll(filepath.Dir(link), 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(tom, link); err != nil {
				t.Fatal(err)
			}
			if tt.follow {
				lock := in.LockOf(link, bad)
				in.WaitFor(t, "the quarantine of the link", func() bool { return !in.Gone(lock) })
			}
			// Without follow_symlinks the link is ignored without a word: the window
			// of staysReleased covers many rescans of it.
			staysReleased(t, in, tom, bad)
			if !tt.follow && !in.Gone(in.LockOf(link, bad)) {
				t.Error("the link was followed although follow_symlinks is off")
			}
			if restoredEntryAt(in, link, bad) {
				t.Error("the link is reported restored")
			}
		})
	}
}

// Design §3: another content at the released location is another file. It is
// analyzed and filtered (here refused by a forbidden path the released file was
// spared); the released content written back there is released again.
func TestE2E_aReleasedFileChangedInPlaceIsANewFile(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		config  map[string]any
		path    string
		changed []byte
		bad     bool
	}{
		{
			name:    "a clean content refused by the path the release spared",
			config:  harness.PathFilter([]string{`/forbidden/`}, nil),
			path:    "forbidden/f.txt",
			changed: []byte("a clean content written over a released file under a forbidden path"),
		},
		{
			name:    "another malware",
			path:    "f.txt",
			changed: []byte("another malware written over a released file"),
			bad:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			released := []byte("a released malware changed in place " + tt.name)
			gm := gmalware.New(t)
			gm.MarkMalicious(released)
			if tt.bad {
				gm.MarkMalicious(tt.changed)
			}
			in := harness.Start(t, gm, harness.Options{Agent: true, Config: harness.MergeMaps(moveOff(), tt.config)})
			path := filepath.Join(in.Input, "tom", tt.path)
			if !tt.bad {
				in.Expect.Flag(tt.changed)
			}
			harness.DropAt(t, path, released)
			release(t, in, path, released)
			awaitRestoredEntry(t, in, path, released)

			harness.DropAt(t, path, tt.changed)
			in.AwaitQuarantine(t, path, tt.changed)

			harness.DropAt(t, path, released)
			staysReleased(t, in, path, released)
		})
	}
}
