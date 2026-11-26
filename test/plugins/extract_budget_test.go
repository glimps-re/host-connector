//go:build linux && (e2e || e2e_plugins)

package plugins

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/test/internal/fakes/gmalware"
	"github.com/glimps-re/host-connector/test/internal/harness"
)

// zerosOf gives each member a content of zeros of its size.
func zerosOf(sizes map[string]int) map[string][]byte {
	members := make(map[string][]byte, len(sizes))
	for name, size := range sizes {
		members[name] = make([]byte, size)
	}
	return members
}

// leftOut is what the report of an archive delivered with members left out by
// the limits must say.
type leftOut struct {
	reason   datamodel.NotAnalyzedReason
	count    int
	includes string
}

// writtenOut drops a 7z of the members in a connector started with the
// configuration, waits for its delivery, and returns how much more the work
// folder held at most than before the drop (the deployed 7-Zip and the spool
// are there before) and the report entries of the archive.
func writtenOut(t *testing.T, config map[string]any, members map[string][]byte, extracted []byte) (int64, []datamodel.Report) {
	t.Helper()
	gm := gmalware.New(t)
	in := harness.Start(t, gm, harness.Options{Plugins: map[string]map[string]any{"extract": nil}, Config: config})
	in.WaitMonitoring(t)
	before, err := treeSize(in.Work)
	if err != nil {
		t.Fatal(err)
	}
	work := watchSize(t, in)
	content := sevenZipOf(t, "7z", members)
	in.Expect.Archive(content, extracted)
	in.Expect.Allow(datamodel.NotAnalyzedExtractLimit)
	in.Drop(t, "a.7z", content)
	in.WaitFor(t, "the delivery of the archive", func() bool { return in.InOutput("a.7z") })
	in.WaitFor(t, "the report of the archive", func() bool { return len(in.ReportsOf(t, content)) > 0 })
	largest, err := work.stop()
	if err != nil {
		t.Fatalf("the work folder could not be measured: %v", err)
	}
	return largest - before, in.ReportsOf(t, content)
}

func checkLeftOut(t *testing.T, entries []datamodel.Report, want leftOut) {
	t.Helper()
	for _, e := range entries {
		if e.Error != "" || e.Malicious || e.NotAnalyzedReason != "" {
			t.Errorf("entry error %q malicious %v reason %q, want a clean archive", e.Error, e.Malicious, e.NotAnalyzedReason)
		}
		if e.NotAnalyzedExtractedCount != want.count {
			t.Errorf("%d members not analyzed, want %d", e.NotAnalyzedExtractedCount, want.count)
		}
		for _, m := range e.NotAnalyzedExtractedFiles {
			if m.Reason != want.reason {
				t.Errorf("member %s not analyzed for %q, want %q", m.FileName, m.Reason, want.reason)
			}
		}
		if !slices.ContainsFunc(e.NotAnalyzedExtractedFiles, func(m datamodel.NotAnalyzedFile) bool { return strings.HasSuffix(m.FileName, want.includes) }) {
			t.Errorf("members not analyzed %+v, want %s among them", e.NotAnalyzedExtractedFiles, want.includes)
		}
	}
}

// From TestExtractFile_memberOverTheLimitIsNeverWrittenToDisk: a member over the remaining recursive_extract_max_size is listed extract-limit and never written out.
func TestE2E_aMemberOverTheBudgetIsNeverWrittenOut(t *testing.T) {
	tests := []struct {
		name     string
		members  map[string]int
		config   map[string]any
		want     leftOut
		maxWrite int64
	}{
		{
			name:     "huge.bin of 30 MiB beside small.txt, recursive_extract_max_size 10 MiB",
			members:  map[string]int{"huge.bin": 30 << 20, "small.txt": 10},
			config:   map[string]any{"recursive_extract_max_size": "10MiB", "unanalyzable_policy": map[string]any{"too_big": "pass"}},
			want:     leftOut{reason: datamodel.NotAnalyzedExtractLimit, count: 1, includes: "huge.bin"},
			maxWrite: 1 << 20,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			members := zerosOf(tt.members)
			written, entries := writtenOut(t, tt.config, members, members["small.txt"])
			checkLeftOut(t, entries, tt.want)
			if written > tt.maxWrite {
				t.Errorf("%d bytes were written for a member that must never be extracted", written)
			}
		})
	}
}

// From TestExtractFile_budgetInBytesStopsBeforeWritingTheMembersThatDoNotFit: the members beyond recursive_extract_max_size are listed extract-limit and never written out.
func TestE2E_theBudgetInBytesStopsBeforeWritingTheMembersThatDoNotFit(t *testing.T) {
	tests := []struct {
		name     string
		members  map[string]int
		config   map[string]any
		want     leftOut
		maxWrite int64
	}{
		{
			name:     "four members of 1 MiB, a budget of 2 MiB + 100 bytes",
			members:  map[string]int{"a.bin": 1 << 20, "b.bin": 1 << 20, "c.bin": 1 << 20, "d.bin": 1 << 20},
			config:   map[string]any{"recursive_extract_max_size": fmt.Sprintf("%dB", 2<<20+100), "unanalyzable_policy": map[string]any{"too_big": "pass"}},
			want:     leftOut{reason: datamodel.NotAnalyzedExtractLimit, count: 2, includes: ".bin"},
			maxWrite: 2<<20 + 100 + 2<<20,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			members := zerosOf(tt.members)
			written, entries := writtenOut(t, tt.config, members, members["a.bin"])
			checkLeftOut(t, entries, tt.want)
			if written > tt.maxWrite {
				t.Errorf("%d bytes written, over the budget", written)
			}
		})
	}
}

// From TestExtractFile_budgetInFilesIsExactAndTheRestIsReportedExtractLimit: the budget in files of a 7z is exact and the members beyond it are listed extract-limit.
func TestE2E_theBudgetInFilesIsExactAndTheRestIsListed(t *testing.T) {
	t.Parallel()
	sizes := map[string]int{}
	var members []harness.File
	for i := range 40 {
		name := fmt.Sprintf("m%03d.txt", i)
		sizes[name] = 100 + i
		members = append(members, harness.File{Path: name, Content: make([]byte, 100+i)})
	}
	sevenZ := harness.File{Path: "a.7z", Content: sevenZipOf(t, "7z", zerosOf(sizes)), Members: members}
	analyzed := func(n int) map[string]harness.Outcome {
		want := map[string]harness.Outcome{}
		for i, m := range members {
			want["a.7z/"+m.Path] = harness.Outcome{ServiceVerdict: harness.NotGiven}
			if i < n {
				want["a.7z/"+m.Path] = harness.Outcome{Submissions: 1}
			}
		}
		return want
	}
	tests := []struct {
		name    string
		budget  int
		want    harness.Outcome
		members map[string]harness.Outcome
	}{
		{name: "budget of 10", budget: 10, want: harness.Outcome{In: harness.Output, NotAnalyzedMembers: &harness.MemberList{Reason: datamodel.NotAnalyzedExtractLimit, Count: 30}}, members: analyzed(10)},
		{name: "budget of exactly the members", budget: 40, want: harness.Outcome{In: harness.Output, NotAnalyzedMembers: harness.NoMembers()}, members: analyzed(40)},
		{name: "budget above", budget: 1500, want: harness.Outcome{In: harness.Output, NotAnalyzedMembers: harness.NoMembers()}, members: analyzed(40)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := map[string]harness.Outcome{sevenZ.Path: tt.want}
			maps.Copy(want, tt.members)
			harness.Run(t, harness.Scenario{
				Plugins: map[string]map[string]any{"extract": nil},
				Config:  map[string]any{"recursive_extract_max_files": tt.budget, "unanalyzable_policy": map[string]any{"too_big": "pass"}},
				Files:   []harness.File{sevenZ},
				Want:    want,
			})
		})
	}
}
