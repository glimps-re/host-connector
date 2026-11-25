//go:build linux && (e2e || e2e_plugins)

package plugins

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/glimps-re/host-connector/test/internal/fakes/gmalware"
	"github.com/glimps-re/host-connector/test/internal/harness"
)

// From TestDecodeConfig_removedKeysAreRefusedWithTheirReplacementNotAsUnknown: a removed key of the extract plugin is refused at start with the global limit that replaces it, and no configured value is logged.
func TestE2E_aRemovedKeyOfTheExtractPluginIsRefusedWithItsReplacement(t *testing.T) {
	t.Parallel()
	const secret = "s3cret-password"
	tests := []struct {
		key, replacement string
	}{
		{key: "max_file_size", replacement: "max_file_size of the main configuration"},
		{key: "max_extracted_files", replacement: "recursive_extract_max_files"},
		{key: "max_total_extracted_size", replacement: "recursive_extract_max_size"},
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			in := harness.Run(t, harness.Scenario{
				Plugins:     map[string]map[string]any{"extract": {tt.key: "1GB", "default_passwords": []string{secret}}},
				WantRefused: tt.replacement,
			})
			log := in.Stderr.String()
			var refusal []string
			for line := range strings.SplitSeq(log, "\n") {
				if strings.Contains(line, tt.replacement) {
					refusal = append(refusal, line)
				}
			}
			if !strings.Contains(strings.Join(refusal, "\n"), tt.key) {
				t.Errorf("the refusal %q does not name the key %s", refusal, tt.key)
			}
			if strings.Contains(strings.Join(refusal, "\n"), "unknown") {
				t.Errorf("the refusal %q is the generic unknown key refusal", refusal)
			}
			if strings.Contains(log, secret) || strings.Contains(log, "1GB") {
				t.Errorf("the log quotes a configured value:\n%s", log)
			}
		})
	}
}

// From TestSevenZipExtractPlugin_configuredRealBinaryIsUsedAndKeptOnClose: a configured 7-Zip extracts the archives and is still there after the stop.
func TestE2E_aConfiguredSevenZipIsUsedAndKeptAfterTheStop(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		file harness.File
		want map[string]harness.Outcome
	}{
		{
			name: "a zip",
			file: archive(t, "a.zip", zipOf, harness.File{Path: "m.txt", Content: []byte(strings.Repeat("a member extracted by the configured 7-Zip ", 20))}),
			want: map[string]harness.Outcome{"a.zip": {In: harness.Output}, "a.zip/m.txt": {Submissions: 1}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bin := sevenZip(t)
			harness.Run(t, harness.Scenario{
				Plugins: map[string]map[string]any{"extract": {"seven_zip_path": bin}},
				Files:   []harness.File{tt.file},
				Steps:   []harness.Step{harness.AwaitDelivered(tt.file.Path), harness.Stop()},
				Want:    tt.want,
			})
			if _, err := os.Stat(bin); err != nil {
				t.Errorf("the configured 7-Zip is gone after the stop: %v", err)
			}
		})
	}
}

// From TestProve_stagesInTheWorkDirectory: with TMPDIR on a folder that does not exist, the start is not refused and the archives are extracted.
// harness.Options has no environment: TMPDIR is set for the whole test process with t.Setenv, so this test is serial (not parallel).
func TestE2E_aMissingTMPDIRDoesNotStopTheExtraction(t *testing.T) {
	tests := []struct {
		name   string
		member []byte
	}{
		{name: "a zip of one member", member: []byte(strings.Repeat("a member extracted without TMPDIR ", 20))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// t.TempDir makes the folder of the test in TMPDIR at its first call,
			// and the later ones below it: it must be called before TMPDIR moves.
			// The build of the binary, if this test is the first, needs a folder
			// of its own (GOTMPDIR).
			t.Setenv("GOTMPDIR", t.TempDir())
			t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "absent"))
			gm := gmalware.New(t, false)
			in := harness.Start(t, gm, harness.Options{Plugins: map[string]map[string]any{"extract": nil}})
			content := zipOf(t, map[string]string{"m.txt": string(tt.member)})
			in.Expect.Archive(content, tt.member)
			in.Drop(t, "a.zip", content)
			in.WaitFor(t, "the delivery of the archive", func() bool { return in.InOutput("a.zip") })
			if n := len(in.NamesOf(t, tt.member)); n != 1 {
				t.Errorf("the member was submitted %d times, want once", n)
			}
		})
	}
}
