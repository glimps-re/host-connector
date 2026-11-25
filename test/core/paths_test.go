//go:build linux && (e2e || e2e_core)

package core

import (
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/test/internal/harness"
)

// T51c, Amendment 3 ("raw and sanitized names"): a path is matched in its raw
// form and in the form the core prints (control characters replaced). When the
// two differ, a forbidden rule is applied if either matches and a skip only if
// both do. A name ending in a newline is refused by `\.exe[^/]*$` (Go's `$` is
// the end of the text, so `\.exe$` alone would not match even the raw name). A
// control character makes the raw and the sanitized names differ: a file whose
// sanitized name matches the skip rule `a_b\.txt$` but whose raw name does not is
// analyzed. An invalid UTF-8 byte does not change the verdict of `trusted[^/]*`:
// every form of the name matches, and the folder is skipped.
func TestE2E_pathRulesMatchTheRawAndTheSanitizedName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		scenario harness.Scenario
	}{
		{
			name: "a newline, an invalid byte and a control character",
			scenario: harness.Scenario{
				Config: harness.PathFilter(
					[]string{`\.exe[^/]*$`},
					[]string{`/tom/trusted[^/]*/`, `a_b\.txt$`},
				),
				Files: []harness.File{
					{Path: "run.exe\n", Content: []byte("a file whose name ends in .exe and a newline")},
					{Path: "trusted\xff/x.txt", Content: []byte("a file in a folder whose name is not valid UTF-8")},
					{Path: "a\x01b.txt", Content: []byte("a file whose name holds a control character")},
				},
				Want: map[string]harness.Outcome{
					"run.exe\n":         {In: harness.Quarantine, Malware: datamodel.FilteredFilePath},
					"trusted\xff/x.txt": {In: harness.Output, NotAnalyzed: datamodel.NotAnalyzedPolicySkipped, ServiceVerdict: harness.NotGiven},
					"a\x01b.txt":        {In: harness.Output, ServiceVerdict: harness.Given},
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

// p3/T66: the folded form of a name (hidden runes removed) can only add a
// refusal, never widen a skip. `/tom/a\.log$` matches a.log, and the folded form
// of a<U+200B>.log, but not its raw or sanitized form: the file is analyzed.
// `/tom/skipped/.*\.log$` matches every form of skipped/b<U+200B>.log: that file
// is skipped.
func TestE2E_theFoldedNameDoesNotWidenASkipRule(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		scenario harness.Scenario
	}{
		{
			name: "a zero-width space in the name",
			scenario: harness.Scenario{
				Config: harness.PathFilter(nil, []string{`/tom/a\.log$`, `/tom/skipped/.*\.log$`}),
				Files: []harness.File{
					{Path: "a\U0000200b.log", Content: []byte("a file whose hidden rune must not make it match the skip rule")},
					{Path: "skipped/b\U0000200b.log", Content: []byte("a file the skip rule matches in every form")},
				},
				Want: map[string]harness.Outcome{
					"a\U0000200b.log":         {In: harness.Output, ServiceVerdict: harness.Given},
					"skipped/b\U0000200b.log": {In: harness.Output, NotAnalyzed: datamodel.NotAnalyzedPolicySkipped, ServiceVerdict: harness.NotGiven},
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

// p3/T66: a skip needs every form of the name to match. The folded form drops the
// invalid byte of "trusted\xff", so `trusted[_\x{FFFD}]` no longer matches it: the
// file is analyzed, not skipped.
func TestE2E_aSkipRuleThatOnlyMatchesTheMangledFolderNoLongerSkips(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		scenario harness.Scenario
	}{
		{
			name: "an invalid byte in the folder name",
			scenario: harness.Scenario{
				Config: harness.PathFilter(nil, []string{"/tom/trusted[_\\x{FFFD}]/"}),
				Files: []harness.File{
					{Path: "trusted\xff/x.txt", Content: []byte("a file in a folder whose name is not valid UTF-8")},
				},
				Want: map[string]harness.Outcome{
					"trusted\xff/x.txt": {In: harness.Output, ServiceVerdict: harness.Given},
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
