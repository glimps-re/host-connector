//go:build linux && (e2e || e2e_plugins)

package plugins

import (
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/test/internal/harness"
)

// From TestMoveAction_copyModeEveryClassOfFileReachesOutputAsAVerifiedPrivateCopy and TestPipeline_aLargeArchiveExtractedAndAnalysedIsCopiedNotPassedByPath: in copy mode an archive, a file skipped by its type, and an archive carrying the too-big reason of a member reach OUTPUT as a private copy.
func TestE2E_copyModeDeliversAPrivateCopyOfArchivesAndSkippedTypes(t *testing.T) {
	t.Parallel()
	copyMode := map[string]any{"move": map[string]any{"mode": "copy"}}
	tooBigPass := func(maxFileSize string) map[string]any {
		return harness.MergeMaps(map[string]any{
			"max_file_size":       maxFileSize,
			"unanalyzable_policy": map[string]any{"too_big": "pass"},
		}, copyMode)
	}
	largeArchive := archive(t, "big.zip", zipOf, harness.File{Path: "member.bin", Content: []byte("a small clean member")})
	if len(largeArchive.Content) <= 100 {
		t.Fatalf("the archive is %d bytes, it must be larger than max_file_size", len(largeArchive.Content))
	}
	noise := make([]byte, 4096)
	rng := rand.New(rand.NewPCG(1, 2)) //nolint:gosec // G404: incompressible test content, not a secret
	for i := range noise {
		noise[i] = byte(rng.Uint32())
	}
	small := harness.File{Path: "small.txt", Content: []byte(strings.Repeat("a small member ", 20))}
	for _, tt := range []struct {
		name     string
		scenario harness.Scenario
	}{
		{
			name: "an archive",
			scenario: harness.Scenario{
				Plugins: map[string]map[string]any{"extract": nil},
				Config:  copyMode,
				Files:   []harness.File{archive(t, "a.zip", zipOf, small)},
				Want:    map[string]harness.Outcome{"a.zip": {In: harness.Output, Delivery: harness.Copied}},
			},
		},
		{
			name: "a file skipped by its type",
			scenario: harness.Scenario{
				Plugins: map[string]map[string]any{"filetype_filter": {"skipped_types": []string{"image/png"}}},
				Config:  copyMode,
				Files:   []harness.File{{Path: "p.png", Content: realPNG(t)}},
				Want:    map[string]harness.Outcome{"p.png": {In: harness.Output, NotAnalyzed: datamodel.NotAnalyzedSkippedType, Delivery: harness.Copied}},
			},
		},
		{
			name: "an archive over max_file_size extracted and analyzed",
			scenario: harness.Scenario{
				Plugins: map[string]map[string]any{"extract": nil},
				Config:  harness.MergeMaps(map[string]any{"max_file_size": "100B"}, copyMode),
				Files:   []harness.File{largeArchive},
				Want:    map[string]harness.Outcome{"big.zip": {In: harness.Output, Delivery: harness.Copied}},
			},
		},
		{
			name: "a small archive carrying the too-big reason of a member",
			scenario: harness.Scenario{
				Plugins: map[string]map[string]any{"extract": nil},
				Config:  tooBigPass("2KiB"),
				Files:   []harness.File{archive(t, "a.zip", zipOf, small, harness.File{Path: "big.bin", Content: make([]byte, 8000)})},
				Want: map[string]harness.Outcome{"a.zip": {
					In: harness.Output, Delivery: harness.Copied,
					NotAnalyzedMembers: &harness.MemberList{Reason: datamodel.NotAnalyzedTooBig, Count: 1, Includes: "big.bin"},
				}},
			},
		},
		{
			name: "an archive over max_file_size carrying the too-big reason of a member",
			scenario: harness.Scenario{
				Plugins: map[string]map[string]any{"extract": nil},
				Config:  tooBigPass("2KiB"),
				Files:   []harness.File{archive(t, "a.zip", zipOf, small, harness.File{Path: "big.bin", Content: noise})},
				Want: map[string]harness.Outcome{"a.zip": {
					In: harness.Output, Delivery: harness.Copied,
					NotAnalyzedMembers: &harness.MemberList{Reason: datamodel.NotAnalyzedTooBig, Count: 1, Includes: "big.bin"},
				}},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			harness.Run(t, tt.scenario)
		})
	}
}
