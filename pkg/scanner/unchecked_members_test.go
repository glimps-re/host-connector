package scanner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gabriel-vasile/mimetype"
	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	gdetectMock "github.com/glimps-re/go-gdetect/pkg/gdetect/mock"
	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
)

func TestAnalyze_theUncheckedMembersOfADocumentAreBoundedAndCounted(t *testing.T) {
	file := filepath.Join(t.TempDir(), "doc.docx")
	if err := os.WriteFile(file, []byte("content to analyze"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := NewConnector(Config{Roots: []string{filepath.Dir(file)}, WorkDir: t.TempDir(), Workers: 1}, nil, cleanSubmitter())
	if err != nil {
		t.Fatal(err)
	}
	members := make([]datamodel.NotAnalyzedFile, 2*datamodel.MaxListedSubfiles)
	for i := range members {
		members[i] = datamodel.NotAnalyzedFile{FileName: fmt.Sprintf("m%d-%s", i, strings.Repeat("x", 2*datamodel.MaxListedNameLen)), Reason: datamodel.NotAnalyzedExtractLimit}
	}
	input := fileToAnalyze{
		filename: "doc.docx", location: file, sha256: shaOf("content to analyze"), size: int64(len("content to analyze")),
		uncheckedMembers: members, uncheckedCount: datamodel.MaxFileCount + 5,
	}
	res := c.analyze(input, nil)
	if res.Error != nil || res.NotAnalyzedReason != "" || res.FilteredVolume != 0 {
		t.Fatalf("result = %+v, want an analyzed document", res)
	}
	if len(res.NotAnalyzedSubfiles) != datamodel.MaxListedSubfiles || res.NotAnalyzedSubfilesCount != datamodel.MaxFileCount {
		t.Errorf("listed = %d, count = %d, want %d and the saturated count", len(res.NotAnalyzedSubfiles), res.NotAnalyzedSubfilesCount, datamodel.MaxListedSubfiles)
	}
	if name := res.NotAnalyzedSubfiles[0].FileName; len(name) > datamodel.MaxListedNameLen+len("…")*3 {
		t.Errorf("name of %d bytes, want it cut", len(name))
	}
}

// The members are listed if and only if the document is delivered: not
// quarantined, not held in error, on every path out of analyze.
func TestAnalyze_theUncheckedMembersAreListedOnlyForADeliveredDocument(t *testing.T) {
	const content = "content to analyze"
	failing := func(context.Context, string, gdetect.WaitForOptions) (gdetect.Result, error) {
		return gdetect.Result{}, errors.New("service down")
	}
	verdict := func(r gdetect.Result) func(context.Context, string, gdetect.WaitForOptions) (gdetect.Result, error) {
		return func(context.Context, string, gdetect.WaitForOptions) (gdetect.Result, error) { return r, nil }
	}
	waiver := func(string, string, string, bool) *datamodel.Result { return &datamodel.Result{} }
	tests := []struct {
		name       string
		policy     Unanalyzable
		maxSize    int64
		submit     func(context.Context, string, gdetect.WaitForOptions) (gdetect.Result, error)
		scanFile   func(string, string, string, bool) *datamodel.Result
		filter     *PathFilter
		wantListed bool
		wantReason datamodel.NotAnalyzedReason
	}{
		{name: "clean", wantListed: true},
		{name: "a detection", submit: verdict(gdetect.Result{Malware: true, Malwares: []string{"m"}})},
		{name: "analysis_error error", submit: verdict(gdetect.Result{Error: "engine failed"})},
		{name: "analysis_error pass", policy: Unanalyzable{AnalysisError: PolicyPass}, submit: verdict(gdetect.Result{Error: "engine failed"}), wantListed: true, wantReason: datamodel.NotAnalyzedAnalysisError},
		{name: "analysis_error mitigate", policy: Unanalyzable{AnalysisError: PolicyMitigate}, submit: verdict(gdetect.Result{Error: "engine failed"})},
		{name: "a submission that fails", submit: failing},
		{name: "too_big pass on a document over max_file_size", policy: Unanalyzable{TooBig: PolicyPass}, maxSize: 5, wantListed: true, wantReason: datamodel.NotAnalyzedTooBig},
		{name: "too_big error on a document over max_file_size", policy: Unanalyzable{TooBig: PolicyError}, maxSize: 5},
		{name: "too_big mitigate on a document over max_file_size", policy: Unanalyzable{TooBig: PolicyMitigate}, maxSize: 5},
		{name: "a plugin waiver", scanFile: waiver, wantListed: true, wantReason: datamodel.NotAnalyzedPolicySkipped},
		{name: "a forbidden path", filter: mustPathFilter(t, []string{`doc\.docx$`}, nil)},
		{name: "a skipped path", filter: mustPathFilter(t, nil, []string{`doc\.docx$`}), wantListed: true, wantReason: datamodel.NotAnalyzedSkippedPath},
		{name: "a forbidden path beats a skipped one", filter: mustPathFilter(t, []string{`doc\.docx$`}, []string{`\.docx$`})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "doc.docx")
			if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			submit := tt.submit
			if submit == nil {
				submit = verdict(gdetect.Result{})
			}
			maxSize := tt.maxSize
			if maxSize == 0 {
				maxSize = 1 << 20
			}
			c, err := NewConnector(Config{
				Roots: []string{filepath.Dir(file)}, WorkDir: t.TempDir(), Workers: 1,
				Unanalyzable: tt.policy, MaxFileSize: maxSize, PathFilter: tt.filter,
			}, nil, echoReader(&gdetectMock.MockGDetectSubmitter{
				ExtractExpertViewURLMock: func(*gdetect.Result) (string, error) { return "", nil },
				WaitForFileMock:          submit,
			}))
			if err != nil {
				t.Fatal(err)
			}
			if tt.scanFile != nil {
				c.RegisterOnScanFile(tt.scanFile)
			}
			input := fileToAnalyze{
				filename: "doc.docx", location: file, sha256: shaOf(content), size: int64(len(content)),
				uncheckedMembers: []datamodel.NotAnalyzedFile{{FileName: "a", Reason: datamodel.NotAnalyzedExtractLimit}, {FileName: "b", Reason: datamodel.NotAnalyzedExtractLimit}},
				uncheckedCount:   2,
			}
			res := c.analyze(input, nil)
			listed := res.NotAnalyzedSubfilesCount == 2 && len(res.NotAnalyzedSubfiles) == 2
			if listed != tt.wantListed || (!tt.wantListed && (res.NotAnalyzedSubfilesCount != 0 || len(res.NotAnalyzedSubfiles) != 0)) {
				t.Errorf("members listed = %t (%d, %d), want %t; result = malware %t, error %v, analysis error %q, reason %q",
					listed, res.NotAnalyzedSubfilesCount, len(res.NotAnalyzedSubfiles), tt.wantListed, res.Malware, res.Error, res.AnalysisError, res.NotAnalyzedReason)
			}
			if tt.wantListed && res.NotAnalyzedReason != tt.wantReason {
				t.Errorf("reason = %q, want %q", res.NotAnalyzedReason, tt.wantReason)
			}
		})
	}
}

// An ordinary archive over the limits is not a document: it is still left out by
// the limits, held by the policies, and no member is listed as unchecked.
func TestRecursiveExtract_anOrdinaryArchiveOverTheLimitsIsStillLimitSkipped(t *testing.T) {
	prev := ExtractFile
	ExtractFile = func(string, string, plugins.ExtractLimits) (plugins.Extraction, error) {
		t.Error("an archive over the limits is not extracted")
		return plugins.Extraction{}, nil
	}
	t.Cleanup(func() { ExtractFile = prev })
	path := filepath.Join(t.TempDir(), "a.zip")
	if err := os.WriteFile(path, []byte("an archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := NewConnector(Config{Extract: true, WorkDir: t.TempDir(), RecursiveExtractMaxDepth: 3, ExtractMinThreshold: 1, RecursiveExtractMaxFiles: 100, RecursiveExtractMaxSize: 1000}, nil, cleanSubmitter())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(context.WithoutCancel(t.Context())) })
	c.analysisChan = make(chan fileToAnalyze, 1)
	size, files := int64(5000), 30
	zipType := mimetype.Detect([]byte("PK\x03\x04"))
	file := fileToAnalyze{location: path, typeRead: true, mtype: zipType}
	if err = c.recursiveExtract(file, 1, &size, &files, logger); err != nil {
		t.Fatalf("recursiveExtract() error = %v", err)
	}
	got := <-c.analysisChan
	if !got.limitSkipped || got.uncheckedCount != 0 {
		t.Errorf("limitSkipped = %t, uncheckedCount = %d, want an archive left out by the limits", got.limitSkipped, got.uncheckedCount)
	}
}
