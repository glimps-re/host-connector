package scanner

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/glimps-re/host-connector/pkg/quarantine"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	gdetectMock "github.com/glimps-re/go-gdetect/pkg/gdetect/mock"
	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
	quarantineMock "github.com/glimps-re/host-connector/pkg/quarantine/mock"
)

// handled runs one restored file through the pipeline and gives the results the
// actions were given, and the number of analyses that were asked.
func handledRestored(t *testing.T, name string, filter *PathFilter, scanFile plugins.OnScanFile) (results []datamodel.Result, analyses int) {
	t.Helper()
	noOpenInputs(t)
	in := t.TempDir()
	file := filepath.Join(in, name)
	if err := os.WriteFile(file, []byte("restored content"), 0o600); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	capture := &MockAction{HandleMock: func(_ context.Context, _ Source, res datamodel.Result, _ *datamodel.Report) error {
		mu.Lock()
		defer mu.Unlock()
		results = append(results, res)
		return nil
	}}
	submitter := readerTrio(&gdetectMock.MockGDetectSubmitter{
		ExtractExpertViewURLMock: func(*gdetect.Result) (string, error) { return "", nil },
		WaitForReaderMock: func(context.Context, io.Reader, gdetect.WaitForOptions) (gdetect.Result, error) {
			mu.Lock()
			analyses++
			mu.Unlock()
			return gdetect.Result{}, nil
		},
	})
	quarantiner := &quarantineMock.QuarantineMock{
		IsRestoredMock: func(context.Context, string, string) (bool, error) { return true, nil },
	}
	c, err := NewConnector(Config{
		Roots: []string{in}, WorkDir: t.TempDir(), Workers: 1, PathFilter: filter,
		CustomActions: []Action{capture},
	}, quarantiner, submitter)
	if err != nil {
		t.Fatal(err)
	}
	if scanFile != nil {
		c.RegisterOnScanFile(scanFile)
	}
	got := &outcomes{}
	c.config.OnFileDone = got.add
	if err = c.Start(); err != nil {
		t.Fatal(err)
	}
	if err = c.ScanFile(t.Context(), file); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "the file to end", func() bool { return len(got.get()) == 1 })
	c.Close(t.Context())
	mu.Lock()
	defer mu.Unlock()
	return results, analyses
}

// A restored content waives the analysis, never a refusal.
func TestRestored_aRefusalStillWins(t *testing.T) {
	typeRefusal := func(string, string, string, bool) *datamodel.Result {
		return &datamodel.Result{Malware: true, Malwares: []string{"type"}, MalwareReason: datamodel.FilteredFileType}
	}
	typeWaiver := func(string, string, string, bool) *datamodel.Result { return &datamodel.Result{} }
	tests := []struct {
		name         string
		file         string
		filter       *PathFilter
		scanFile     plugins.OnScanFile
		wantMalware  bool
		wantReason   datamodel.MalwareReason
		wantRestored bool
	}{
		{"nothing refuses it", "ok.bin", mustPathFilter(t, []string{`\.exe$`}, nil), nil, false, "", true},
		{"a forbidden path", "run.exe", mustPathFilter(t, []string{`\.exe$`}, nil), nil, true, datamodel.FilteredFilePath, false},
		{"a forbidden type", "ok.bin", nil, typeRefusal, true, datamodel.FilteredFileType, false},
		{"a refusal of a plugin, with an error only", "ok.bin", nil, func(string, string, string, bool) *datamodel.Result {
			return &datamodel.Result{Error: errors.New("refused")}
		}, false, "", false},
		{"a plugin waiver changes nothing", "ok.bin", nil, typeWaiver, false, "", true},
		{"a skipped path changes nothing", "ok.bin", mustPathFilter(t, nil, []string{`ok\.bin$`}), nil, false, "", true},
		{"a forbidden path matched on the raw name", "run.exe\n", mustPathFilter(t, []string{`\.exe\n$`}, nil), nil, true, datamodel.FilteredFilePath, false},
		{"a forbidden path beats a skipped one", "run.exe", mustPathFilter(t, []string{`\.exe$`}, []string{`run\.exe$`}), nil, true, datamodel.FilteredFilePath, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, analyses := handledRestored(t, tt.file, tt.filter, tt.scanFile)
			if len(results) != 1 {
				t.Fatalf("%d results given to the actions, want one", len(results))
			}
			got := results[0]
			if got.Malware != tt.wantMalware || got.MalwareReason != tt.wantReason || got.Restored != tt.wantRestored {
				t.Errorf("result = malware %t, reason %q, restored %t, want %t, %q, %t", got.Malware, got.MalwareReason, got.Restored, tt.wantMalware, tt.wantReason, tt.wantRestored)
			}
			if tt.name == "a refusal of a plugin, with an error only" && got.Error == nil {
				t.Error("the refusal has no error")
			}
			if analyses != 0 {
				t.Errorf("%d analyses, want none: a restored content is never analyzed", analyses)
			}
		})
	}
}

// What becomes of a restored content refused for its path, by the actions that are
// configured: quarantined although restored (its restored mark kept), deleted, or
// left in INPUT with a report; never retried.
func TestRestored_aRefusedContentFollowsTheActions(t *testing.T) {
	tests := []struct {
		name        string
		actions     Actions
		wantQuar    int
		wantDeleted bool
		passes      int
	}{
		{"quarantine on, deletion on", Actions{Quarantine: true, Deleted: true, Log: true}, 1, true, 1},
		{"quarantine on, deletion off", Actions{Quarantine: true, Log: true}, 1, false, 1},
		{"quarantine off, deletion on", Actions{Deleted: true, Log: true}, 0, true, 1},
		{"both off, a second pass", Actions{Log: true}, 0, false, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			noOpenInputs(t)
			in := t.TempDir()
			qdir := t.TempDir()
			const content = "restored content"
			file := filepath.Join(in, "run.exe")
			q, err := quarantine.NewQuarantineHandler(t.Context(), quarantine.Config{Location: qdir, LockPassword: "infected"})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if e := q.Close(); e != nil {
					t.Errorf("Close() error = %v", e)
				}
			})
			restoreContent(t, q, file, content)
			var mu sync.Mutex
			var reports []datamodel.Report
			capture := &MockAction{HandleMock: func(_ context.Context, _ Source, _ datamodel.Result, rep *datamodel.Report) error {
				mu.Lock()
				defer mu.Unlock()
				reports = append(reports, *rep)
				return nil
			}}
			var analyses atomic.Int32
			submitter := readerTrio(&gdetectMock.MockGDetectSubmitter{
				ExtractExpertViewURLMock: func(*gdetect.Result) (string, error) { return "", nil },
				WaitForReaderMock: func(context.Context, io.Reader, gdetect.WaitForOptions) (gdetect.Result, error) {
					analyses.Add(1)
					return gdetect.Result{}, nil
				},
			})
			c, err := NewConnector(Config{
				Roots: []string{in}, WorkDir: t.TempDir(), Workers: 1, PathFilter: mustPathFilter(t, []string{`\.exe$`}, nil),
				Actions: tt.actions, CustomActions: []Action{capture},
			}, q, submitter)
			if err != nil {
				t.Fatal(err)
			}
			got := &outcomes{}
			c.config.OnFileDone = got.add
			if err = c.Start(); err != nil {
				t.Fatal(err)
			}
			for pass := 1; pass <= tt.passes; pass++ {
				if err = c.ScanFile(t.Context(), file); err != nil {
					t.Fatal(err)
				}
				waitUntil(t, "the file to end", func() bool { return len(got.get()) >= pass })
			}
			c.Close(t.Context())
			list := got.get()
			if len(list) != tt.passes {
				t.Errorf("outcomes = %+v, want %d", list, tt.passes)
			}
			for _, o := range list {
				if o.Kind != OutcomeFinal {
					t.Errorf("outcome = %+v, want a final one and no retry", o)
				}
			}
			if analyses.Load() != 0 {
				t.Errorf("%d analyses, want none: the refused restored content is never submitted", analyses.Load())
			}
			locks, err := filepath.Glob(filepath.Join(qdir, "*.lock"))
			if err != nil {
				t.Fatal(err)
			}
			if len(locks) != tt.wantQuar {
				t.Errorf("%d quarantined, want %d", len(locks), tt.wantQuar)
			}
			if restored, restoredErr := q.IsRestored(t.Context(), file, shaOf(content)); restoredErr != nil || !restored {
				t.Errorf("IsRestored() = %t, %v, want the restored mark kept", restored, restoredErr)
			}
			_, statErr := os.Stat(file)
			if gone := statErr != nil; gone != tt.wantDeleted {
				t.Errorf("file gone %t, want %t", gone, tt.wantDeleted)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(reports) != tt.passes {
				t.Fatalf("%d reports, want %d", len(reports), tt.passes)
			}
			for _, rep := range reports {
				if !rep.Malicious || rep.MalwareReason != datamodel.FilteredFilePath || rep.HasBeenRestored {
					t.Errorf("report = %+v, want malware for the path, not marked restored", rep)
				}
			}
		})
	}
}

// refusedWhenRestored gives a refusal that reads as the one of any file: the
// reason of a detection, the location as name, the size of the content.
func TestRefusedWhenRestored_shapesTheRefusal(t *testing.T) {
	noReason := func(string, string, string, bool) *datamodel.Result { return &datamodel.Result{Malware: true} }
	tests := []struct {
		name       string
		file       string
		filter     *PathFilter
		scanFile   plugins.OnScanFile
		wantNil    bool
		wantReason datamodel.MalwareReason
	}{
		{name: "nothing refuses", file: "ok.bin", wantNil: true},
		{name: "a detection without reason is given one", file: "ok.bin", scanFile: noReason, wantReason: datamodel.MalwareDetected},
		{name: "a forbidden path keeps its reason", file: "run.exe", filter: mustPathFilter(t, []string{`\.exe$`}, nil), wantReason: datamodel.FilteredFilePath},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			noOpenInputs(t)
			in := t.TempDir()
			file := filepath.Join(in, tt.file)
			c, err := NewConnector(Config{Roots: []string{in}, WorkDir: t.TempDir(), Workers: 1, PathFilter: tt.filter},
				&quarantineMock.QuarantineMock{}, readerTrio(&gdetectMock.MockGDetectSubmitter{}))
			if err != nil {
				t.Fatal(err)
			}
			if tt.scanFile != nil {
				c.RegisterOnScanFile(tt.scanFile)
			}
			got, err := c.refusedWhenRestored(file, "sha", 16, FileIdentity{}, &ongoing{}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if tt.wantNil {
				if got != nil {
					t.Fatalf("refusal = %+v, want none", got)
				}
				return
			}
			if got == nil || got.MalwareReason != tt.wantReason || got.Filename != file || got.Location != file || got.SHA256 != "sha" || got.FileSize != 16 {
				t.Errorf("refusal = %+v, want reason %q, the location %q as name, its hash and its size", got, tt.wantReason, file)
			}
		})
	}
}

// The chain is told whether the restored file is an archive, as it is for any file.
func TestRefusedWhenRestored_tellsTheChainWhetherItIsAnArchive(t *testing.T) {
	for _, tt := range []struct {
		name    string
		content string
		want    bool
	}{
		{"an archive", zipOf(t, 10), true},
		{"a plain file", "plain text", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			noOpenInputs(t)
			in := t.TempDir()
			file := filepath.Join(in, "f.bin")
			if err := os.WriteFile(file, []byte(tt.content), 0o600); err != nil {
				t.Fatal(err)
			}
			c, err := NewConnector(Config{Roots: []string{in}, WorkDir: t.TempDir(), Workers: 1, Extract: true},
				&quarantineMock.QuarantineMock{}, readerTrio(&gdetectMock.MockGDetectSubmitter{}))
			if err != nil {
				t.Fatal(err)
			}
			var got atomic.Bool
			c.RegisterOnScanFile(func(_, _, _ string, isArchive bool) *datamodel.Result {
				got.Store(isArchive)
				return nil
			})
			if _, err = c.refusedWhenRestored(file, "sha", int64(len(tt.content)), FileIdentity{}, &ongoing{}, nil); err != nil {
				t.Fatal(err)
			}
			if got.Load() != tt.want {
				t.Errorf("isArchive = %t, want %t", got.Load(), tt.want)
			}
		})
	}
}
