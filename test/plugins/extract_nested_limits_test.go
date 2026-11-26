//go:build linux && (e2e || e2e_plugins)

package plugins

import (
	"fmt"
	"strings"
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/test/internal/harness"
)

// From TestRecursiveExtract_remainingBudgetShrinksFromOneLevelToTheNext: what the first level extracted is taken from the budget of the nested archive.
func TestE2E_theRemainingBudgetShrinksFromOneLevelToTheNext(t *testing.T) {
	t.Parallel()
	var members []harness.File
	for i := range 9 {
		members = append(members, harness.File{Path: fmt.Sprintf("m%d.txt", i), Content: fmt.Appendf(nil, "%-100s", fmt.Sprintf("inner member %d", i))})
	}
	plain := harness.File{Path: "plain.txt", Content: []byte("plain member")}
	inner := archive(t, "inner.zip", zipOf, members...)
	outer := archive(t, "outer.zip", zipOf, plain, inner)
	spent := len(inner.Content) + len(plain.Content)
	dropped := harness.Outcome{In: harness.Output, NotAnalyzedMembers: &harness.MemberList{Reason: datamodel.NotAnalyzedExtractLimit, Count: 1}}
	for _, tt := range []struct {
		name   string
		limits map[string]any
		want   harness.Outcome
	}{
		{name: "10 files, 2 spent, 9 nested members", limits: map[string]any{"recursive_extract_max_files": 10}, want: dropped},
		{name: "room for 8 nested members after the first level", limits: map[string]any{"recursive_extract_max_size": fmt.Sprintf("%dB", spent+8*100+50)}, want: dropped},
	} {
		t.Run(tt.name, func(t *testing.T) {
			harness.Run(t, harness.Scenario{
				Plugins: map[string]map[string]any{"extract": nil},
				Config:  harness.MergeMaps(map[string]any{"unanalyzable_policy": map[string]any{"too_big": "pass"}}, tt.limits),
				Files:   []harness.File{outer},
				Want:    map[string]harness.Outcome{"outer.zip": tt.want},
			})
		})
	}
}

// From TestRecursiveExtract_aLimitSkippedArchiveFollowsTheStricterPolicy: an archive beyond the depth is submitted once, never opened, and follows the stricter of too_big and encrypted.
func TestE2E_anArchiveBeyondTheDepthFollowsTheStricterPolicy(t *testing.T) {
	t.Parallel()
	outer := archive(t, "outer.zip", zipOf,
		harness.File{Path: "ok.txt", Content: []byte(strings.Repeat("a member beside a deep archive ", 20))},
		archive(t, "inner.zip", zipOf, harness.File{Path: "x.txt", Content: []byte(strings.Repeat("a member too deep to be opened ", 20))}),
	)
	inError := harness.Outcome{In: harness.Input, Error: "inner.zip: an extracted file cannot be analyzed: the limits of the extraction left the archive unopened"}
	mitigated := harness.Outcome{In: harness.Quarantine, Malware: datamodel.TooBig}
	passed := harness.Outcome{In: harness.Output, NotAnalyzedMembers: &harness.MemberList{Reason: datamodel.NotAnalyzedExtractLimit, Count: 1, Includes: "inner.zip"}}
	for _, tt := range []struct {
		tooBig, encrypted string
		want              harness.Outcome
	}{
		{tooBig: "error", encrypted: "error", want: inError},
		{tooBig: "error", encrypted: "pass", want: inError},
		{tooBig: "error", encrypted: "mitigate", want: inError},
		{tooBig: "pass", encrypted: "error", want: inError},
		{tooBig: "pass", encrypted: "pass", want: passed},
		{tooBig: "pass", encrypted: "mitigate", want: mitigated},
		{tooBig: "mitigate", encrypted: "error", want: inError},
		{tooBig: "mitigate", encrypted: "pass", want: mitigated},
		{tooBig: "mitigate", encrypted: "mitigate", want: mitigated},
	} {
		t.Run(tt.tooBig+"/"+tt.encrypted, func(t *testing.T) {
			want := map[string]harness.Outcome{
				"outer.zip":                 tt.want,
				"outer.zip/inner.zip":       {Submissions: 1},
				"outer.zip/inner.zip/x.txt": {ServiceVerdict: harness.NotGiven},
			}
			harness.Run(t, harness.Scenario{
				Plugins: map[string]map[string]any{"extract": nil},
				Config: map[string]any{
					"recursive_extract_max_depth": 1,
					"unanalyzable_policy":         map[string]any{"too_big": tt.tooBig, "encrypted": tt.encrypted},
				},
				Files: []harness.File{outer},
				Want:  want,
			})
		})
	}
}

// From TestRecursiveExtract_aLimitSkippedArchiveKnownAsMalwareIsMalware: a detection on an archive beyond the depth wins over policies at pass.
func TestE2E_anArchiveBeyondTheDepthKnownAsMalwareIsMalware(t *testing.T) {
	t.Parallel()
	inner := archive(t, "inner.zip", zipOf, harness.File{Path: "x.txt", Content: []byte(strings.Repeat("a member of a detected archive ", 20))})
	inner.Verdict = harness.Malicious
	for _, tt := range []struct {
		name string
		file harness.File
		want map[string]harness.Outcome
	}{
		{
			name: "a detected zip beyond depth 1",
			file: archive(t, "outer.zip", zipOf, harness.File{Path: "ok.txt", Content: []byte(strings.Repeat("a member beside a detected archive ", 20))}, inner),
			want: map[string]harness.Outcome{
				"outer.zip": {In: harness.Quarantine, Malware: datamodel.MalwareDetected, MaliciousMembers: map[string]datamodel.MalwareReason{"inner.zip": datamodel.MalwareDetected}},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			harness.Run(t, harness.Scenario{
				Plugins: map[string]map[string]any{"extract": nil},
				Config: map[string]any{
					"recursive_extract_max_depth": 1,
					"unanalyzable_policy":         map[string]any{"too_big": "pass", "encrypted": "pass"},
				},
				Files: []harness.File{tt.file},
				Want:  tt.want,
			})
		})
	}
}

// From TestRecursiveExtract_anOrdinaryBinaryIsNotLeftOutNorExtracted: an ordinary binary at the maximum depth is analyzed as the file it is, not left out.
func TestE2E_anOrdinaryBinaryAtTheMaximumDepthIsAnalyzed(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name string
		file harness.File
		want map[string]harness.Outcome
	}{
		{
			name: "a small binary in a zip, depth 1",
			file: archive(t, "a.zip", zipOf, harness.File{Path: "tool.bin", Content: []byte{0x7f, 0x01, 0x02, 0xff, 0xfe, 0x00, 0x10, 0x80}}),
			want: map[string]harness.Outcome{
				"a.zip":          {In: harness.Output, NotAnalyzedMembers: harness.NoMembers()},
				"a.zip/tool.bin": {Submissions: 1},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			harness.Run(t, harness.Scenario{
				Plugins: map[string]map[string]any{"extract": nil},
				Config: map[string]any{
					"recursive_extract_max_depth": 1,
					"unanalyzable_policy":         map[string]any{"too_big": "error", "encrypted": "error"},
				},
				Files: []harness.File{tt.file},
				Want:  tt.want,
			})
		})
	}
}
