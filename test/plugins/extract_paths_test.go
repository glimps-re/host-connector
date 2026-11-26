//go:build linux && (e2e || e2e_plugins)

package plugins

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	hcquarantine "github.com/glimps-re/host-connector/pkg/quarantine"
	"github.com/glimps-re/host-connector/test/internal/fakes/gmalware"
	"github.com/glimps-re/host-connector/test/internal/harness"
)

// P10: the path filters judge the logical path: the real path of a file, and
// for a member of an archive the path of the archive followed by the member's.
// A forbidden path is treated as malware, a skipped one is delivered without
// analysis.
func TestE2E_pathFiltersJudgeTheLogicalPath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		scenario harness.Scenario
	}{
		{
			name: "files and archive members under forbidden and skipped folders",
			scenario: harness.Scenario{
				Plugins: map[string]map[string]any{"extract": nil},
				Config: map[string]any{
					"filepath_filter": map[string]any{
						"forbidden_paths": []string{`/forbidden/`, `\.zip/secret/`},
						"skipped_paths":   []string{`/trusted/`},
					},
				},
				Files: []harness.File{
					{Path: "plain.txt", Content: []byte("an ordinary file")},
					{Path: "trusted/t.txt", Content: []byte("a file in a trusted folder")},
					{Path: "forbidden/f.txt", Content: []byte("a file in a forbidden folder")},
					archive(t, "bad.zip", zipOf,
						harness.File{Path: "secret/x.txt", Content: []byte(strings.Repeat("a member in a forbidden folder of an archive ", 40))},
						harness.File{Path: "open/y.txt", Content: []byte(strings.Repeat("another member, in an allowed folder ", 40))},
					),
					archive(t, "clean.zip", zipOf, harness.File{Path: "open/z.txt", Content: []byte(strings.Repeat("the only member of the clean archive ", 40))}),
				},
				Want: map[string]harness.Outcome{
					"plain.txt":            {In: harness.Output, ServiceVerdict: harness.Given},
					"trusted/t.txt":        {In: harness.Output, NotAnalyzed: datamodel.NotAnalyzedSkippedPath, ServiceVerdict: harness.NotGiven},
					"forbidden/f.txt":      {In: harness.Quarantine, Malware: datamodel.FilteredFilePath},
					"bad.zip":              {In: harness.Quarantine, Malware: datamodel.FilteredFilePath},
					"clean.zip":            {In: harness.Output},
					"clean.zip/open/z.txt": {ServiceVerdict: harness.Given},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			harness.Run(t, tt.scenario)
		})
	}
}

// T51c: the paths rules of the core, with no plugin. A forbidden path (a file,
// a member of an archive) is malware and is quarantined; a skipped folder is
// delivered without analysis, marked skipped-path; a refusal beats a skip.
func TestE2E_corePathRules(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		scenario harness.Scenario
	}{
		{
			name: "forbidden, skipped and both",
			scenario: harness.Scenario{
				Plugins: map[string]map[string]any{"extract": nil},
				Config:  harness.PathFilter([]string{`/forbidden/`, `\.zip/secret/`}, []string{`/tom/trusted/`}),
				Files: []harness.File{
					{Path: "plain.txt", Content: []byte("an ordinary file")},
					{Path: "trusted/t.txt", Content: []byte("a file in a skipped folder")},
					{Path: "forbidden/f.txt", Content: []byte("a file in a forbidden folder")},
					{Path: "trusted/forbidden/b.txt", Content: []byte("forbidden and in a skipped folder")},
					archive(t, "bad.zip", zipOf,
						harness.File{Path: "secret/x.txt", Content: []byte(strings.Repeat("a member in a forbidden folder of an archive ", 40))},
						harness.File{Path: "open/y.txt", Content: []byte(strings.Repeat("another member, in an allowed folder ", 40))},
					),
					archive(t, "clean.zip", zipOf, harness.File{Path: "open/z.txt", Content: []byte(strings.Repeat("the only member of the clean archive ", 40))}),
				},
				Want: map[string]harness.Outcome{
					"plain.txt":               {In: harness.Output},
					"trusted/t.txt":           {In: harness.Output, NotAnalyzed: datamodel.NotAnalyzedSkippedPath, ServiceVerdict: harness.NotGiven},
					"forbidden/f.txt":         {In: harness.Quarantine, Malware: datamodel.FilteredFilePath},
					"trusted/forbidden/b.txt": {In: harness.Quarantine, Malware: datamodel.FilteredFilePath},
					"bad.zip":                 {In: harness.Quarantine, Malware: datamodel.FilteredFilePath},
					"clean.zip":               {In: harness.Output},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			harness.Run(t, tt.scenario)
		})
	}
}

// T51c: a newline inside the name of an archive does not make it escape a
// forbidden path. The rule `^/.*\.zip$` does not cross a newline with `.`, so the
// raw name "pack\nx.zip" would slip under it: the archive is refused all the same.
func TestE2E_aNewlineInAnArchiveNameDoesNotEscapeAForbiddenPath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		scenario harness.Scenario
	}{
		{
			name: "pack<LF>x.zip",
			scenario: harness.Scenario{
				Plugins: map[string]map[string]any{"extract": nil},
				Config:  harness.PathFilter([]string{`^/.*\.zip$`}, nil),
				Files: []harness.File{
					archive(t, "pack\nx.zip", zipOf, harness.File{Path: "a.txt", Content: []byte(strings.Repeat("a member of an archive that a rule forbids ", 40))}),
				},
				Want: map[string]harness.Outcome{
					"pack\nx.zip": {In: harness.Quarantine, Malware: datamodel.FilteredFilePath},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			harness.Run(t, tt.scenario)
		})
	}
}

// T51c: a skipped archive refused because listed members match a forbidden path
// names those members in its report, as if it had been extracted: each appears
// among the malicious members of the archive.
func TestE2E_aRefusedSkippedArchiveNamesItsForbiddenMembers(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		scenario harness.Scenario
	}{
		{
			name: "two executables in a skipped zip",
			scenario: harness.Scenario{
				Plugins: map[string]map[string]any{"extract": nil},
				Config:  harness.PathFilter([]string{`\.exe$`}, []string{`/tom/trusted/`}),
				Files: []harness.File{
					archive(t, "trusted/x.zip", zipOf,
						harness.File{Path: "a.exe", Content: []byte(strings.Repeat("the first executable ", 40))},
						harness.File{Path: "b.exe", Content: []byte(strings.Repeat("the second executable ", 40))},
					),
				},
				Want: map[string]harness.Outcome{
					"trusted/x.zip": {
						In: harness.Quarantine, Malware: datamodel.FilteredFilePath,
						MaliciousMembers: map[string]datamodel.MalwareReason{"a.exe": datamodel.FilteredFilePath, "b.exe": datamodel.FilteredFilePath},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			harness.Run(t, tt.scenario)
		})
	}
}

// T51c, Amendment 3: a skip waives the analysis, never a refusal. An archive in
// a skipped folder is listed, not extracted: a member under a forbidden path
// makes it malware; without such a member it is delivered, skipped-path, and
// none of its members is analyzed.
func TestE2E_aSkippedArchiveIsStillCheckedAgainstTheForbiddenPaths(t *testing.T) {
	t.Parallel()
	doc := []byte(strings.Repeat("a document member ", 40))
	tests := []struct {
		name     string
		scenario harness.Scenario
	}{
		{
			name: "a skipped zip with an executable and one without",
			scenario: harness.Scenario{
				Plugins: map[string]map[string]any{"extract": nil},
				Config:  harness.PathFilter([]string{`\.exe$`}, []string{`/tom/trusted/`}),
				Files: []harness.File{
					archive(t, "trusted/with.zip", zipOf,
						harness.File{Path: "a.exe", Content: []byte(strings.Repeat("an executable member ", 40))},
						harness.File{Path: "b.txt", Content: doc},
					),
					// c.txt does not reuse the bytes of a.exe: what the test flags is keyed by
					// content, and the archive without a forbidden member must not count as malware.
					archive(t, "trusted/without.zip", zipOf,
						harness.File{Path: "b.txt", Content: doc},
						harness.File{Path: "c.txt", Content: []byte(strings.Repeat("a document too, with other bytes ", 40))},
					),
				},
				Want: map[string]harness.Outcome{
					"trusted/with.zip":          {In: harness.Quarantine, Malware: datamodel.FilteredFilePath},
					"trusted/without.zip":       {In: harness.Output, NotAnalyzed: datamodel.NotAnalyzedSkippedPath},
					"trusted/without.zip/b.txt": {ServiceVerdict: harness.NotGiven},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			harness.Run(t, tt.scenario)
		})
	}
}

// p3/T66: a member whose name ends with a zero-width space does not escape
// `\.exe$`: the archive is refused and the member is named in the report.
func TestE2E_aZeroWidthSpaceAfterTheExtensionDoesNotEscapeAForbiddenPath(t *testing.T) {
	t.Parallel()
	const zeroWidthSpace = "\xe2\x80\x8b"
	tests := []struct {
		name     string
		scenario harness.Scenario
	}{
		{
			name: "a.exe<U+200B>",
			scenario: harness.Scenario{
				Plugins: map[string]map[string]any{"extract": nil},
				Config:  harness.PathFilter([]string{`\.exe$`}, nil),
				Files: []harness.File{
					archive(t, "a.zip", zipOf,
						harness.File{Path: "a.exe" + zeroWidthSpace, Content: []byte(strings.Repeat("an executable that hides its extension ", 40))},
						harness.File{Path: "b.txt", Content: []byte(strings.Repeat("a harmless member ", 40))},
					),
				},
				Want: map[string]harness.Outcome{
					"a.zip": {In: harness.Quarantine, Malware: datamodel.FilteredFilePath, MaliciousMembers: map[string]datamodel.MalwareReason{"a.exe" + zeroWidthSpace: datamodel.FilteredFilePath}},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			harness.Run(t, tt.scenario)
		})
	}
}

// p3/T66: a variation selector after the extension does not escape `\.exe$`.
func TestE2E_aVariationSelectorAfterTheExtensionDoesNotEscapeAForbiddenPath(t *testing.T) {
	t.Parallel()
	const variationSelector = "\U0000fe0f"
	tests := []struct {
		name     string
		scenario harness.Scenario
	}{
		{
			name: "a.exe<U+FE0F>",
			scenario: harness.Scenario{
				Plugins: map[string]map[string]any{"extract": nil},
				Config:  harness.PathFilter([]string{`\.exe$`}, nil),
				Files: []harness.File{
					archive(t, "v.zip", zipOf,
						harness.File{Path: "a.exe" + variationSelector, Content: []byte(strings.Repeat("an executable followed by a variation selector ", 40))},
						harness.File{Path: "b.txt", Content: []byte(strings.Repeat("a harmless member next to it ", 40))},
					),
				},
				Want: map[string]harness.Outcome{
					"v.zip": {In: harness.Quarantine, Malware: datamodel.FilteredFilePath, MaliciousMembers: map[string]datamodel.MalwareReason{"a.exe" + variationSelector: datamodel.FilteredFilePath}},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			harness.Run(t, tt.scenario)
		})
	}
}

// D-003: a release lifts the filters for the released archive at its place: it
// is delivered with the restored mark, neither listed nor extracted, whether a
// member matches forbidden_paths or not. The same archive deposited elsewhere is
// not released there: it is extracted and refused for its member.
func TestE2E_aRestoredArchiveIsDeliveredWithoutBeingListed(t *testing.T) {
	t.Parallel()
	detected := []byte(strings.Repeat("a member the service detects ", 40))
	withExe := archive(t, "with.zip", zipOf,
		harness.File{Path: "run.exe", Content: []byte(strings.Repeat("an executable member ", 40))},
		harness.File{Path: "doc.txt", Content: detected, Verdict: harness.Malicious},
	)
	copied := withExe
	copied.Path = "copy/with.zip"
	tests := []struct {
		name     string
		scenario harness.Scenario
	}{
		{
			name: "a restored zip without and one with an executable, and a copy of the latter",
			scenario: harness.Scenario{
				Agent:   true,
				Plugins: map[string]map[string]any{"extract": nil},
				Config:  harness.PathFilter([]string{`\.exe$`}, nil),
				Files: []harness.File{
					archive(t, "without.zip", zipOf,
						harness.File{Path: "a.txt", Content: detected, Verdict: harness.Malicious},
						harness.File{Path: "b.txt", Content: []byte(strings.Repeat("an ordinary member ", 40))},
					),
				},
				Steps: []harness.Step{
					harness.Await("without.zip", harness.Outcome{In: harness.Quarantine, Malware: datamodel.MalwareDetected}),
					harness.Restore("without.zip", ""),
					harness.AwaitDelivered("without.zip"),
					harness.AddFileToInput(withExe),
					harness.Await("with.zip", harness.Outcome{In: harness.Quarantine, Malware: datamodel.MalwareDetected}),
					harness.Restore("with.zip", ""),
					harness.AwaitDelivered("with.zip"),
					harness.AddFileToInput(copied),
				},
				Want: map[string]harness.Outcome{
					"without.zip":   {In: harness.Output, Restored: true},
					"with.zip":      {In: harness.Output, Restored: true},
					"copy/with.zip": {In: harness.Quarantine, Malware: datamodel.MalwareDetected},
				},
				WantMitigations: []string{"malware", "malware", "malware"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := harness.Run(t, tt.scenario)
			reports := harness.ReadReports(in)
			for _, name := range []string{"without.zip", "with.zip"} {
				location := filepath.Join(in.Input, "tom", name)
				for _, entries := range reports {
					for _, e := range entries {
						if e.Filename == location && harness.RestoredEntry(e) && (e.TotalExtractedFile > 0 || len(e.NotAnalyzedExtractedFiles) > 0 || len(e.MaliciousExtractedFiles) > 0) {
							t.Errorf("the restored %s was listed or extracted: %+v", name, e)
						}
					}
				}
			}
		})
	}
}

// encrypted7z builds a 7z with the embedded 7-Zip whose headers and content are
// encrypted with the given password.
func encrypted7z(t *testing.T, password string, members map[string]string) []byte {
	t.Helper()
	bin := sevenZip(t)
	src := t.TempDir()
	paths := make([]string, 0, len(members))
	for name, content := range members {
		harness.Write(t, filepath.Join(src, name), []byte(content))
		paths = append(paths, name)
	}
	archive := filepath.Join(t.TempDir(), "enc.7z")
	if out, err := harness.RunCommand(src, bin, append([]string{"a", "-t7z", "-mhe=on", "-p" + password, archive}, paths...)...); err != nil {
		t.Fatalf("cannot build the archive: %v\n%s", err, out)
	}
	raw, err := os.ReadFile(filepath.Clean(archive))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// D-003: a restored 7z whose names cannot be listed (encrypted headers, no
// known password), with forbidden_paths set, is delivered with the restored
// mark: it is not listed, not submitted, and carries no error. The same archive
// elsewhere is not released there and is quarantined again.
func TestE2E_aRestoredArchiveWhoseNamesCannotBeListedIsDeliveredRestored(t *testing.T) {
	tests := []struct {
		name     string
		password string
	}{
		{name: "a 7z with encrypted headers", password: "not-a-default-password"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gm := gmalware.New(t)
			in := harness.Start(t, gm, harness.Options{Agent: true, Plugins: map[string]map[string]any{"extract": nil}, Config: harness.MergeMaps(harness.PathFilter([]string{`\.exe$`}, nil), map[string]any{
				"unanalyzable_policy": map[string]any{"encrypted": "mitigate"},
				"monitoring":          map[string]any{"period": "2s"},
			})})
			archive := encrypted7z(t, tt.password, map[string]string{"a.txt": strings.Repeat("a secret member ", 40)})
			in.Expect.Flag(archive)
			path := in.Drop(t, "secret.7z", archive)
			id := hcquarantine.ComputeCacheID(path, gmalware.SHA256Hex(archive))
			lock := filepath.Join(in.Quarantine, id+".lock")
			in.WaitFor(t, "the quarantine of the encrypted archive", func() bool { return !in.Gone(lock) && in.Gone(path) })
			before := gm.Submitted.Load()
			if msg := in.WaitAck(t, in.Console.Push(t, "restore", map[string]string{"id": id})); msg != "" {
				t.Fatalf("restore refused: %s", msg)
			}
			in.Expect.Release(path, archive)
			in.WaitFor(t, "the restored archive delivered", func() bool { return in.InOutput("secret.7z") })
			if got := gm.Submitted.Load(); got != before {
				t.Errorf("the restored archive was submitted again (%d submissions, %d before)", got, before)
			}
			var restored *datamodel.Report
			in.WaitFor(t, "the restored entry of the archive", func() bool {
				for _, e := range harness.ReadReports(in)[gmalware.SHA256Hex(archive)] {
					if e.Filename == path && harness.RestoredEntry(e) {
						restored = &e
						return true
					}
				}
				return false
			})
			if restored.Error != "" || restored.NotAnalyzedReason != datamodel.NotAnalyzedRestored {
				t.Errorf("restored entry = error %q, reason %q, want no error and the restored reason", restored.Error, restored.NotAnalyzedReason)
			}

			elsewhere := in.Drop(t, "other/secret.7z", archive)
			otherLock := filepath.Join(in.Quarantine, hcquarantine.ComputeCacheID(elsewhere, gmalware.SHA256Hex(archive))+".lock")
			in.WaitFor(t, "the quarantine of the copy elsewhere", func() bool { return !in.Gone(otherLock) && in.Gone(elsewhere) })
		})
	}
}
