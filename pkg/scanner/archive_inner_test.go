package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glimps-re/host-connector/pkg/plugins"

	"github.com/glimps-re/connector-integration/sdk/events"
	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	gdetectMock "github.com/glimps-re/go-gdetect/pkg/gdetect/mock"
	"github.com/glimps-re/host-connector/pkg/datamodel"
)

func archiveCleanSubmitter() *gdetectMock.MockGDetectSubmitter {
	return echoReader(&gdetectMock.MockGDetectSubmitter{
		ExtractExpertViewURLMock: func(*gdetect.Result) (string, error) { return "", nil },
		WaitForFileMock: func(context.Context, string, gdetect.WaitForOptions) (gdetect.Result, error) {
			return gdetect.Result{}, nil
		},
	})
}

func newArchiveForTest(t *testing.T, h *archiveStatusHandler, total int) string {
	t.Helper()
	return h.addStatus(archiveStatus{
		started:         true,
		archiveLocation: "/in/a.zip",
		result:          datamodel.Result{SHA256: "sha"},
		total:           total,
		tmpFolder:       t.TempDir(),
	})
}

func TestArchive_memberErrorMakesArchiveFail(t *testing.T) {
	tests := []struct {
		name          string
		memberErr     error
		wantSentinel  error
		wantArchiveEr bool
	}{
		{"submission failure", errors.New("submit failed"), errInnerTransient, true},
		{"timeout", context.DeadlineExceeded, errInnerTransient, true},
		{"io error", os.ErrPermission, errInnerTransient, true},
		{"unknown cause", errors.New("whatever"), errInnerTransient, true},
		{"inconsistent plugin result", errInconsistentPluginResult, errInnerPermanent, true},
		{"already permanent", errInnerPermanent, errInnerPermanent, true},
		{"too big under the error policy", errFileTooBig, errInnerPermanent, true},
		{"encrypted under the error policy", errEncrypted, errInnerPermanent, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newArchiveStatusHandler()
			id := newArchiveForTest(t, h, 2)
			if _, ok := h.addInnerFileResult(id, "dir/bad.bin", datamodel.Result{Error: tt.memberErr}); !ok {
				t.Fatal("archive not found")
			}
			st, _ := h.getStatus(id)
			if !tt.wantArchiveEr {
				if st.result.Error != nil {
					t.Errorf("archive Error = %v, want nil", st.result.Error)
				}
			} else {
				if !errors.Is(st.result.Error, tt.wantSentinel) {
					t.Errorf("archive Error = %v, want %v", st.result.Error, tt.wantSentinel)
				}
				if errors.Is(tt.wantSentinel, errInnerPermanent) && errors.Is(st.result.Error, errInnerTransient) {
					t.Error("a permanent error must not look transient")
				}
				if !strings.Contains(st.result.Error.Error(), "dir/bad.bin") {
					t.Errorf("archive Error = %v, want the member name", st.result.Error)
				}
			}
			if _, ok := st.result.ErrorSubfiles["dir/bad.bin"]; !ok {
				t.Errorf("ErrorSubfiles = %v, want the member listed", st.result.ErrorSubfiles)
			}
		})
	}
}

func TestArchive_permanentWinsOverTransient(t *testing.T) {
	for _, order := range [][]error{{errors.New("io"), errInconsistentPluginResult}, {errInconsistentPluginResult, errors.New("io")}} {
		h := newArchiveStatusHandler()
		id := newArchiveForTest(t, h, 3)
		for i, e := range order {
			h.addInnerFileResult(id, string(rune('a'+i)), datamodel.Result{Error: e})
		}
		st, _ := h.getStatus(id)
		if !errors.Is(st.result.Error, errInnerPermanent) || !strings.Contains(st.result.Error.Error(), "2 extracted file(s)") {
			t.Errorf("order %v: archive Error = %v, want permanent with the count", order, st.result.Error)
		}
	}
}

func TestArchive_innerAnalysisError(t *testing.T) {
	h := newArchiveStatusHandler()
	id := newArchiveForTest(t, h, 3)
	h.addInnerFileResult(id, "a.bin", datamodel.Result{AnalysisError: "engine failure"})
	st, _ := h.getStatus(id)
	if st.result.AnalysisError != "a.bin: engine failure" || st.result.ErrorSubfiles["a.bin"] != "engine failure" {
		t.Errorf("one analysis error: %+v", st.result)
	}
	h.addInnerFileResult(id, "b.bin", datamodel.Result{AnalysisError: "other"})
	st, _ = h.getStatus(id)
	if st.result.AnalysisError != "a.bin: engine failure (and 1 more)" {
		t.Errorf("two analysis errors: AnalysisError = %q", st.result.AnalysisError)
	}
	if st.result.Error != nil {
		t.Errorf("an analysis error alone must not set Error: %v", st.result.Error)
	}
}

func TestArchive_addInnerError(t *testing.T) {
	h := newArchiveStatusHandler()
	id := newArchiveForTest(t, h, 2)
	finished, ok := h.addInnerError(id, "lost.bin", errors.New("cannot read"))
	if !ok || finished {
		t.Fatalf("addInnerError() = %t, %t; want ok and not finished", finished, ok)
	}
	st, _ := h.getStatus(id)
	if st.total != 1 || !errors.Is(st.result.Error, errInnerTransient) || st.result.ErrorSubfiles["lost.bin"] == "" {
		t.Errorf("status after a lost member: %+v", st)
	}
	finished, _ = h.addInnerError(id, "lost2.bin", errInnerPermanent)
	if !finished {
		t.Error("last lost member must finish the archive")
	}
	st, _ = h.getStatus(id)
	if !errors.Is(st.result.Error, errInnerPermanent) {
		t.Errorf("archive Error = %v, want permanent", st.result.Error)
	}
	if _, ok := h.addInnerError("missing", "x", errors.New("e")); ok {
		t.Error("unknown archive must report not found")
	}
}

func TestArchive_errorSubfilesAreBounded(t *testing.T) {
	h := newArchiveStatusHandler()
	const members = 5000
	id := newArchiveForTest(t, h, members)
	huge := strings.Repeat("n", 60<<10)
	for i := range members {
		h.addInnerFileResult(id, huge+strconv.Itoa(i), datamodel.Result{Error: errors.New(huge)})
	}
	st, _ := h.getStatus(id)
	if got := len(st.result.ErrorSubfiles); got > datamodel.MaxListedSubfiles+1 {
		t.Errorf("ErrorSubfiles has %d entries, want at most %d plus the \"more\" entry", got, datamodel.MaxListedSubfiles)
	}
	if more := st.result.ErrorSubfiles[datamodel.MoreErrorsKey]; more != "4000 more failed file(s) not listed" {
		t.Errorf("more entry = %q, want the 4000 unlisted files counted", more)
	}
	total := 0
	for k, v := range st.result.ErrorSubfiles {
		total += len(k) + len(v)
		if len(k) > datamodel.MaxListedNameLen || len(v) > datamodel.MaxListedNameLen {
			t.Fatalf("an entry is not bounded: key %d bytes, value %d bytes", len(k), len(v))
		}
	}
	if total > (datamodel.MaxListedSubfiles+1)*2*datamodel.MaxListedNameLen {
		t.Errorf("ErrorSubfiles takes %d bytes", total)
	}
	if st.inner.count != members || !strings.Contains(st.result.Error.Error(), "5000 extracted file(s)") {
		t.Errorf("count = %d, Error = %.80v, want every failure counted", st.inner.count, st.result.Error)
	}
	if len(st.result.Error.Error()) > 2*datamodel.MaxListedNameLen {
		t.Errorf("archive Error is %d bytes long", len(st.result.Error.Error()))
	}
}

func TestFinishArchiveAnalysis_memberErrorBlocksAction(t *testing.T) {
	var actionCalled bool
	var scanned datamodel.Result
	c := &Connector{
		action: &MockAction{HandleMock: func(context.Context, Source, datamodel.Result, *datamodel.Report) error {
			actionCalled = true
			return nil
		}},
		archiveStatus:   newArchiveStatusHandler(),
		ongoingAnalysis: sync.Map{},
	}
	c.RegisterOnFileScanned(func(_, _ string, r datamodel.Result) *datamodel.Result {
		scanned = r
		return nil
	})
	location, sha := createTestFile(t, t.TempDir(), "archive content")
	tmp := t.TempDir()
	id := c.archiveStatus.addStatus(archiveStatus{
		started: true, archiveLocation: location, identity: idOf(t, location), tmpFolder: tmp, total: 1,
		result: datamodel.Result{SHA256: sha},
	})
	c.archiveStatus.addInnerFileResult(id, "bad.bin", datamodel.Result{Error: errors.New("submit failed")})
	if err := c.finishArchiveAnalysis(id); err != nil {
		t.Fatalf("finishArchiveAnalysis() error = %v", err)
	}
	if !errors.Is(scanned.Error, errInnerTransient) {
		t.Errorf("OnFileScanned got Error %v, want the archive in error", scanned.Error)
	}
	if !actionCalled {
		t.Error("the actions still run: they refuse an archive with an Error themselves")
	}
	if _, ok := c.archiveStatus.getStatus(id); ok {
		t.Error("status must be deleted")
	}
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Errorf("temporary folder must be removed: %v", err)
	}
}

func TestFinishArchiveAnalysis_changedArchiveNotifiesObserversWithError(t *testing.T) {
	var actionCalled bool
	var scanned datamodel.Result
	c := &Connector{
		action: &MockAction{HandleMock: func(context.Context, Source, datamodel.Result, *datamodel.Report) error {
			actionCalled = true
			return nil
		}},
		archiveStatus:   newArchiveStatusHandler(),
		ongoingAnalysis: sync.Map{},
	}
	c.RegisterOnFileScanned(func(_, _ string, r datamodel.Result) *datamodel.Result {
		scanned = r
		return nil
	})
	location, _ := createTestFile(t, t.TempDir(), "archive content")
	tmp := t.TempDir()
	id := c.archiveStatus.addStatus(archiveStatus{
		started: true, archiveLocation: location, identity: idOf(t, location), tmpFolder: tmp, total: 1, analyzed: 1, finished: true,
		result: datamodel.Result{SHA256: "stale-sha"},
	})
	if err := c.finishArchiveAnalysis(id); err != nil {
		t.Fatalf("finishArchiveAnalysis() error = %v", err)
	}
	if scanned.Error == nil || !strings.Contains(scanned.Error.Error(), "SHA256 mismatch") {
		t.Errorf("OnFileScanned got Error %v, want the SHA256 mismatch", scanned.Error)
	}
	if actionCalled {
		t.Error("no action on an archive that changed during the analysis")
	}
}

func TestRecursiveExtract_lostMemberKeepsArchiveInError(t *testing.T) {
	prev := ExtractFile
	t.Cleanup(func() { ExtractFile = prev })
	ExtractFile = fakeExtractor(func(outputDir string) (uint64, []string, error) {
		return 1, []string{filepath.Join(outputDir, "sub", "missing.bin")}, nil
	})

	var mu sync.Mutex
	var handled []datamodel.Result
	c, err := NewConnector(Config{Extract: true, WorkDir: t.TempDir(), RecursiveExtractMaxDepth: 3, ExtractMinThreshold: 1}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.action = &MockAction{HandleMock: func(_ context.Context, src Source, r datamodel.Result, _ *datamodel.Report) error {
		mu.Lock()
		defer mu.Unlock()
		handled = append(handled, r)
		if src.TooBig {
			t.Error("an extracted archive must not be marked too big, whatever its size")
		}
		return nil
	}}
	t.Cleanup(func() { c.Close(t.Context()) })

	location, sha := createArchive(t, []string{"content"})
	info, err := os.Stat(location)
	if err != nil {
		t.Fatal(err)
	}
	var size int64
	var files int
	archive := fileToAnalyze{sha256: sha, location: location, filename: filepath.Base(location), identity: IdentityOf(info), size: info.Size()}
	if err := c.recursiveExtract(archive, 0, &size, &files, logger); err != nil {
		t.Fatalf("recursiveExtract() error = %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(handled) != 1 {
		t.Fatalf("actions handled %d results, want 1", len(handled))
	}
	got := handled[0]
	if !errors.Is(got.Error, errInnerTransient) {
		t.Errorf("archive Error = %v, want a transient inner error", got.Error)
	}
	if _, ok := got.ErrorSubfiles[filepath.Join("sub", "missing.bin")]; !ok {
		t.Errorf("ErrorSubfiles = %v, want the lost member listed", got.ErrorSubfiles)
	}
}

const (
	readOnlyDir fs.FileMode = 0o500
	ownerDir    fs.FileMode = 0o700
)

func TestRecursiveExtract_subArchiveWithoutTempDirKeepsArchiveInError(t *testing.T) {
	if os.Geteuid() == 0 || runtime.GOOS == "windows" {
		t.Skip("a read-only directory cannot be enforced as root or on windows")
	}
	inner, _ := createArchive(t, []string{"inner content"})
	innerBytes, err := os.ReadFile(filepath.Clean(inner))
	if err != nil {
		t.Fatal(err)
	}

	prev := ExtractFile
	t.Cleanup(func() { ExtractFile = prev })
	var c *Connector
	ExtractFile = fakeExtractor(func(outputDir string) (uint64, []string, error) {
		member := filepath.Join(outputDir, "inner.zip")
		root, err := os.OpenRoot(outputDir)
		if err != nil {
			return 0, nil, err
		}
		defer func() {
			if e := root.Close(); e != nil {
				t.Logf("close root: %v", e)
			}
		}()
		if err := root.WriteFile("inner.zip", innerBytes, 0o600); err != nil {
			return 0, nil, err
		}
		if err := os.Chmod(c.work.extractDir(), readOnlyDir); err != nil {
			return 0, nil, err
		}
		return uint64(len(innerBytes)), []string{member}, nil
	})

	var handled []datamodel.Result
	c, err = NewConnector(Config{Extract: true, WorkDir: t.TempDir(), RecursiveExtractMaxDepth: 3, ExtractMinThreshold: 1}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.action = &MockAction{HandleMock: func(_ context.Context, _ Source, r datamodel.Result, _ *datamodel.Report) error {
		handled = append(handled, r)
		return nil
	}}
	t.Cleanup(func() {
		if err := os.Chmod(c.work.extractDir(), ownerDir); err != nil {
			t.Logf("restore permissions: %v", err)
		}
		c.Close(t.Context())
	})

	location, sha := createArchive(t, []string{"outer content"})
	info, err := os.Stat(location)
	if err != nil {
		t.Fatal(err)
	}
	var size int64
	var files int
	archive := fileToAnalyze{sha256: sha, location: location, filename: filepath.Base(location), identity: IdentityOf(info), size: info.Size()}
	if err := c.recursiveExtract(archive, 0, &size, &files, logger); err != nil {
		t.Fatalf("recursiveExtract() error = %v", err)
	}
	if len(handled) != 1 || !errors.Is(handled[0].Error, errInnerTransient) {
		t.Fatalf("handled = %+v, want one archive in transient error", handled)
	}
	if _, ok := handled[0].ErrorSubfiles["inner.zip"]; !ok {
		t.Errorf("ErrorSubfiles = %v, want inner.zip listed", handled[0].ErrorSubfiles)
	}
}

// runArchiveWithMembers scans an archive of two members, "good.bin" and
// "bad.bin", through the whole pipeline, and returns the results handed to the
// actions (one per top-level archive).
func runArchiveWithMembers(t *testing.T, register func(c *Connector)) []datamodel.Result {
	t.Helper()
	prev := ExtractFile
	t.Cleanup(func() { ExtractFile = prev })
	ExtractFile = fakeExtractor(func(outputDir string) (uint64, []string, error) {
		var files []string
		for name, content := range map[string]string{"good.bin": "good content", "bad.bin": "bad content"} {
			p := filepath.Join(outputDir, name)
			if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
				return 0, nil, err
			}
			files = append(files, p)
		}
		return 24, files, nil
	})
	submitter := echoReader(&gdetectMock.MockGDetectSubmitter{
		ExtractExpertViewURLMock: func(*gdetect.Result) (string, error) { return "", nil },
		WaitForFileMock: func(context.Context, string, gdetect.WaitForOptions) (gdetect.Result, error) {
			return gdetect.Result{}, nil
		},
	})
	c, err := NewConnector(Config{Extract: true, ExtractMinThreshold: 1, Workers: 2, ExtractWorkers: 1, WorkDir: t.TempDir()}, nil, submitter)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var handled []datamodel.Result
	c.action = &MockAction{HandleMock: func(_ context.Context, _ Source, r datamodel.Result, _ *datamodel.Report) error {
		mu.Lock()
		defer mu.Unlock()
		handled = append(handled, r)
		return nil
	}}
	register(c)
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	location, _ := createArchive(t, []string{"outer"})
	if err := c.ScanFile(t.Context(), location); err != nil {
		t.Fatalf("ScanFile() error = %v", err)
	}
	c.Close(t.Context())
	mu.Lock()
	defer mu.Unlock()
	return slices.Clone(handled)
}

func TestArchive_pluginInconsistentResultOnOneMemberIsDefinitive(t *testing.T) {
	handled := runArchiveWithMembers(t, func(c *Connector) {
		c.RegisterOnScanFile(func(filename, location, sha256 string, isArchive bool) *datamodel.Result {
			if isArchive || !strings.HasSuffix(location, "bad.bin") {
				return nil
			}
			return &datamodel.Result{Filename: filename, Location: location, SHA256: sha256, Malwares: []string{"Evil"}}
		})
	})
	if len(handled) != 1 {
		t.Fatalf("handled %d results, want 1", len(handled))
	}
	r := handled[0]
	if !errors.Is(r.Error, errInnerPermanent) {
		t.Errorf("archive Error = %v, want a permanent inner error", r.Error)
	}
	if msg, ok := r.ErrorSubfiles["bad.bin"]; !ok || !strings.Contains(msg, errInconsistentPluginResult.Error()) {
		t.Errorf("ErrorSubfiles = %v, want bad.bin with the inconsistent result error", r.ErrorSubfiles)
	}
	if _, ok := r.ErrorSubfiles["good.bin"]; ok {
		t.Error("good.bin must not be listed in error")
	}
}

func TestArchive_cleanMembersLeaveArchiveClean(t *testing.T) {
	handled := runArchiveWithMembers(t, func(*Connector) {})
	if len(handled) != 1 || handled[0].Error != nil || len(handled[0].ErrorSubfiles) != 0 {
		t.Errorf("handled = %+v, want one clean result", handled)
	}
}

func TestRecursiveExtract_emptyMemberIsStillIgnored(t *testing.T) {
	prev := ExtractFile
	t.Cleanup(func() { ExtractFile = prev })
	ExtractFile = fakeExtractor(func(outputDir string) (uint64, []string, error) {
		root, err := os.OpenRoot(outputDir)
		if err != nil {
			return 0, nil, err
		}
		defer func() {
			if e := root.Close(); e != nil {
				t.Logf("close root: %v", e)
			}
		}()
		if err := root.WriteFile("empty.bin", nil, 0o600); err != nil {
			return 0, nil, err
		}
		return 0, []string{filepath.Join(outputDir, "empty.bin")}, nil
	})
	var handled []datamodel.Result
	c, err := NewConnector(Config{Extract: true, WorkDir: t.TempDir(), ExtractMinThreshold: 1}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.action = &MockAction{HandleMock: func(_ context.Context, _ Source, r datamodel.Result, _ *datamodel.Report) error {
		handled = append(handled, r)
		return nil
	}}
	t.Cleanup(func() { c.Close(t.Context()) })
	location, sha := createArchive(t, []string{"content"})
	info, err := os.Stat(location)
	if err != nil {
		t.Fatal(err)
	}
	var size int64
	var files int
	archive := fileToAnalyze{sha256: sha, location: location, filename: filepath.Base(location), identity: IdentityOf(info), size: info.Size()}
	if err := c.recursiveExtract(archive, 0, &size, &files, logger); err != nil {
		t.Fatal(err)
	}
	if len(handled) != 1 || handled[0].Error != nil || len(handled[0].ErrorSubfiles) != 0 {
		t.Errorf("handled = %+v, want one clean result: an empty member is ignored as before", handled)
	}
}

func TestFinishArchiveAnalysis_subArchiveErrorReachesTopLevelArchive(t *testing.T) {
	var handled []datamodel.Result
	c := &Connector{
		action: &MockAction{HandleMock: func(_ context.Context, _ Source, r datamodel.Result, _ *datamodel.Report) error {
			handled = append(handled, r)
			return nil
		}},
		archiveStatus:   newArchiveStatusHandler(),
		ongoingAnalysis: sync.Map{},
	}
	topLocation, topSHA := createTestFile(t, t.TempDir(), "top archive")
	topID := c.archiveStatus.addStatus(archiveStatus{
		started: true, archiveLocation: topLocation, identity: idOf(t, topLocation), tmpFolder: t.TempDir(), total: 1,
		result: datamodel.Result{SHA256: topSHA},
	})
	subID := c.archiveStatus.addStatus(archiveStatus{
		started: true, archiveLocation: "/tmp/gmhost-x/extract/x-1/inner.zip", tmpFolder: t.TempDir(), total: 1,
		result:        datamodel.Result{SHA256: "sub"},
		parentArchive: parentArchive{statusID: topID, relPath: "inner.zip"},
	})
	c.archiveStatus.addInnerFileResult(subID, "deep/bad.bin", datamodel.Result{Error: errInconsistentPluginResult})
	if err := c.finishArchiveAnalysis(subID); err != nil {
		t.Fatalf("finishArchiveAnalysis() error = %v", err)
	}
	if len(handled) != 1 {
		t.Fatalf("actions handled %d results, want 1 (the top-level archive)", len(handled))
	}
	got := handled[0]
	if !errors.Is(got.Error, errInnerPermanent) {
		t.Errorf("top-level Error = %v, want the permanent cause propagated through two levels", got.Error)
	}
	if _, ok := got.ErrorSubfiles["inner.zip"]; !ok {
		t.Errorf("ErrorSubfiles = %v, want inner.zip listed", got.ErrorSubfiles)
	}
}

func TestArchive_longNamesWithSamePrefixStayDistinct(t *testing.T) {
	h := newArchiveStatusHandler()
	id := newArchiveForTest(t, h, 2)
	prefix := strings.Repeat("p", 2*datamodel.MaxListedNameLen)
	h.addInnerFileResult(id, prefix+"one", datamodel.Result{Error: errors.New("e1")})
	h.addInnerFileResult(id, prefix+"two", datamodel.Result{Error: errors.New("e2")})
	st, _ := h.getStatus(id)
	if len(st.result.ErrorSubfiles) != 2 {
		t.Errorf("ErrorSubfiles = %d entries, want 2: truncated names must not collide", len(st.result.ErrorSubfiles))
	}
}

// The same path twice (two members of an archive with one name) is two failed
// files, both listed: the second no longer overwrites the first.
func TestArchive_theSamePathTwiceIsListedTwice(t *testing.T) {
	h := newArchiveStatusHandler()
	id := newArchiveForTest(t, h, 2)
	h.addInnerFileResult(id, "dup.bin", datamodel.Result{Error: errors.New("first")})
	h.addInnerFileResult(id, "dup.bin", datamodel.Result{Error: errors.New("second")})
	st, _ := h.getStatus(id)
	if len(st.result.ErrorSubfiles) != 2 {
		t.Fatalf("ErrorSubfiles = %v, want both members listed", st.result.ErrorSubfiles)
	}
	if _, ok := st.result.ErrorSubfiles["dup.bin"]; !ok {
		t.Error("the first member lost its own name")
	}
	second := false
	for k, v := range st.result.ErrorSubfiles {
		if strings.HasPrefix(k, "dup.bin-") && v == "second" {
			second = true
		}
	}
	if !second {
		t.Errorf("the second member is not listed under its hashed name: %v", st.result.ErrorSubfiles)
	}
}

// A member named like the key of the count of the files not listed does not take
// it: it is listed under another key.
func TestArchive_aMemberNamedLikeTheCountKeyIsRenamed(t *testing.T) {
	h := newArchiveStatusHandler()
	id := newArchiveForTest(t, h, 1)
	h.addInnerFileResult(id, datamodel.MoreErrorsKey, datamodel.Result{Error: errors.New("sneaky")})
	st, _ := h.getStatus(id)
	if _, taken := st.result.ErrorSubfiles[datamodel.MoreErrorsKey]; taken {
		t.Errorf("a member took the key of the count: %v", st.result.ErrorSubfiles)
	}
	if len(st.result.ErrorSubfiles) != 1 {
		t.Errorf("ErrorSubfiles = %v, want the member listed", st.result.ErrorSubfiles)
	}
}

// The same name failing through both ways in (a result and an error) is listed as
// many times as it failed: the archive keeps the state of the keys between the
// two, so none takes the key of another.
func TestArchive_aNameFailingThroughBothWaysInIsListedEachTime(t *testing.T) {
	h := newArchiveStatusHandler()
	id := newArchiveForTest(t, h, 4)
	h.addInnerFileResult(id, "dup.bin", datamodel.Result{Error: errors.New("one")})
	h.addInnerError(id, "dup.bin", errors.New("two"))
	h.addInnerFileResult(id, "dup.bin", datamodel.Result{Error: errors.New("three")})
	h.addInnerError(id, "dup.bin", errors.New("four"))
	st, _ := h.getStatus(id)
	if len(st.result.ErrorSubfiles) != 4 {
		t.Fatalf("ErrorSubfiles = %v, want the four failures listed", st.result.ErrorSubfiles)
	}
	values := map[string]bool{}
	counters := 0
	for k, v := range st.result.ErrorSubfiles {
		values[v] = true
		if strings.Contains(k, "~") {
			counters++
		}
	}
	if len(values) != 4 || counters != 2 {
		t.Errorf("values %v, %d keys with a counter: want the four errors, and a counter for the third and fourth", values, counters)
	}
}

// An archive with more failed members than can be listed still adds up once the
// report is bounded: what the scanner lists, plus what it counts, plus what the
// bound itself leaves out, is the number of failures.
func TestArchive_theFailuresAddUpAfterTheReportIsBounded(t *testing.T) {
	const failed = 1500
	h := newArchiveStatusHandler()
	id := newArchiveForTest(t, h, failed)
	for i := range failed {
		h.addInnerFileResult(id, fmt.Sprintf("member%05d", i), datamodel.Result{Error: errors.New("e")})
	}
	st, _ := h.getStatus(id)
	r := datamodel.Report{ErrorExtractedFiles: maps.Clone(st.result.ErrorSubfiles)}
	r.Bound()
	got := datamodel.ListedErrors(r.ErrorExtractedFiles) + datamodel.ParseMoreErrors(r.ErrorExtractedFiles[datamodel.MoreErrorsKey])
	if got != failed {
		t.Errorf("listed plus not listed = %d, want %d", got, failed)
	}
}

// The keys the scanner makes are kept as they are by Report.Bound, which would
// otherwise cut them again and merge entries.
func TestArchive_errorKeysSurviveBound(t *testing.T) {
	h := newArchiveStatusHandler()
	id := newArchiveForTest(t, h, 50)
	prefix := strings.Repeat("p", 2*datamodel.MaxListedNameLen)
	for i := range 50 {
		h.addInnerFileResult(id, fmt.Sprintf("%s%03d", prefix, i), datamodel.Result{Error: errors.New("e")})
	}
	st, _ := h.getStatus(id)
	made := maps.Clone(st.result.ErrorSubfiles)
	if len(made) != 50 {
		t.Fatalf("%d keys, want 50", len(made))
	}
	r := datamodel.Report{ErrorExtractedFiles: maps.Clone(made)}
	r.Bound()
	if len(r.ErrorExtractedFiles) != 50 {
		t.Errorf("Bound left %d keys of 50", len(r.ErrorExtractedFiles))
	}
	for k := range made {
		if _, ok := r.ErrorExtractedFiles[k]; !ok {
			t.Fatal("Bound renamed a key of the scanner")
		}
	}
}

// Names that differ only in bytes that are not UTF-8 stay two entries once the
// result is written as JSON.
func TestArchive_errorKeysThatAreNotUTF8StayDistinctInJSON(t *testing.T) {
	h := newArchiveStatusHandler()
	id := newArchiveForTest(t, h, 2)
	h.addInnerFileResult(id, "a\xffb", datamodel.Result{Error: errors.New("one")})
	h.addInnerFileResult(id, "a\xfeb", datamodel.Result{Error: errors.New("two")})
	st, _ := h.getStatus(id)
	raw, err := json.Marshal(st.result.ErrorSubfiles)
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]string
	if err = json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if len(back) != 2 {
		t.Errorf("%d entries after the JSON round trip, want 2: %s", len(back), raw)
	}
}

func TestArchive_noMutationOnceFinishIsClaimed(t *testing.T) {
	h := newArchiveStatusHandler()
	id := newArchiveForTest(t, h, 3)
	if _, claimed, found := h.claimFinish(id); !claimed || !found {
		t.Fatal("claimFinish() failed")
	}
	if _, ok := h.addInnerFileResult(id, "late.bin", datamodel.Result{Error: errors.New("late")}); ok {
		t.Error("addInnerFileResult() after the finish was claimed must refuse")
	}
	if _, ok := h.addInnerError(id, "late2.bin", errors.New("late")); ok {
		t.Error("addInnerError() after the finish was claimed must refuse")
	}
	if _, ok := h.decreaseTotal(id); ok {
		t.Error("decreaseTotal() after the finish was claimed must refuse")
	}
	st, _ := h.getStatus(id)
	if st.total != 3 || st.analyzed != 0 || len(st.result.ErrorSubfiles) != 0 || st.result.Error != nil {
		t.Errorf("status mutated after the finish was claimed: %+v", st)
	}
}

func TestRecursiveExtract_lastMemberLostWhileOthersAreInFlight(t *testing.T) {
	prev := ExtractFile
	t.Cleanup(func() { ExtractFile = prev })
	ExtractFile = fakeExtractor(func(outputDir string) (uint64, []string, error) {
		root, err := os.OpenRoot(outputDir)
		if err != nil {
			return 0, nil, err
		}
		defer func() {
			if e := root.Close(); e != nil {
				t.Logf("close root: %v", e)
			}
		}()
		if err := root.WriteFile("ok.bin", []byte("fine content"), 0o600); err != nil {
			return 0, nil, err
		}
		return 12, []string{filepath.Join(outputDir, "ok.bin"), filepath.Join(outputDir, "lost.bin")}, nil
	})
	var mu sync.Mutex
	var handled []datamodel.Result
	var scanned int
	c, err := NewConnector(Config{Extract: true, WorkDir: t.TempDir(), ExtractMinThreshold: 1, Workers: 2}, nil, archiveCleanSubmitter())
	if err != nil {
		t.Fatal(err)
	}
	c.action = &MockAction{HandleMock: func(_ context.Context, _ Source, r datamodel.Result, _ *datamodel.Report) error {
		mu.Lock()
		defer mu.Unlock()
		handled = append(handled, r)
		return nil
	}}
	c.RegisterOnFileScanned(func(_, _ string, _ datamodel.Result) *datamodel.Result {
		mu.Lock()
		defer mu.Unlock()
		scanned++
		return nil
	})
	t.Cleanup(func() { c.Close(t.Context()) })

	location, sha := createArchive(t, []string{"content"})
	info, err := os.Stat(location)
	if err != nil {
		t.Fatal(err)
	}
	var size int64
	var files int
	archive := fileToAnalyze{sha256: sha, location: location, filename: filepath.Base(location), identity: IdentityOf(info), size: info.Size()}
	if err := c.recursiveExtract(archive, 0, &size, &files, logger); err != nil {
		t.Fatalf("recursiveExtract() = %v, want nil: the lost member was recorded, the archive lives on", err)
	}
	mu.Lock()
	if len(handled) != 0 || scanned != 0 {
		t.Errorf("archive finished too early: %d actions, %d notifications", len(handled), scanned)
	}
	mu.Unlock()

	// The member in flight ends the archive: exactly one finish.
	select {
	case in := <-c.analysisChan:
		c.processFile(in)
	default:
		t.Fatal("the intact member must be waiting for analysis")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(handled) != 1 || scanned != 1 {
		t.Fatalf("%d actions and %d notifications, want exactly one finish", len(handled), scanned)
	}
	if !errors.Is(handled[0].Error, errInnerTransient) || handled[0].ErrorSubfiles["lost.bin"] == "" {
		t.Errorf("archive result = %+v, want the lost member recorded", handled[0])
	}
}

func TestMemberCause(t *testing.T) {
	pathErr := &fs.PathError{Op: "open", Path: "/tmp/gmhost-1/extract/x-1/sub/a.bin", Err: os.ErrPermission}
	got := memberCause(pathErr)
	if strings.Contains(got.Error(), "/tmp/gmhost-1") || !errors.Is(got, os.ErrPermission) {
		t.Errorf("memberCause() = %v, want the cause without the temporary path", got)
	}
	plain := errors.New("plain")
	if !errors.Is(memberCause(plain), plain) {
		t.Error("an error without path is kept as is")
	}
}

func TestRecursiveExtract_extractionFailureClassification(t *testing.T) {
	tests := []struct {
		name      string
		extractor func(string, string, plugins.ExtractLimits) (plugins.Extraction, error)
		wantErr   bool
	}{
		{"a file typed as an archive that the extractor refuses is not a plain file", func(string, string, plugins.ExtractLimits) (plugins.Extraction, error) {
			return plugins.Extraction{}, fmt.Errorf("x: %w", plugins.ErrUnsupportedFormat)
		}, true},
		{"encrypted goes to the policy of the encrypted files", func(string, string, plugins.ExtractLimits) (plugins.Extraction, error) {
			return plugins.Extraction{}, fmt.Errorf("x: %w", plugins.ErrEncrypted)
		}, false},
		{"any other failure is an extract error", func(string, string, plugins.ExtractLimits) (plugins.Extraction, error) {
			return plugins.Extraction{}, errors.New("7z killed")
		}, true},
		{"nothing extracted while members were left out by the limits is an error under the default policy", func(string, string, plugins.ExtractLimits) (plugins.Extraction, error) {
			return plugins.Extraction{Skipped: []datamodel.NotAnalyzedFile{{FileName: "big.bin", Reason: datamodel.NotAnalyzedTooBig}}, SkippedCount: 1}, nil
		}, true},
		{"an extract-error entry is an error", func(string, string, plugins.ExtractLimits) (plugins.Extraction, error) {
			return plugins.Extraction{Skipped: []datamodel.NotAnalyzedFile{{FileName: "a.7z", Reason: datamodel.NotAnalyzedExtractError}}, SkippedCount: 1}, nil
		}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prev := ExtractFile
			t.Cleanup(func() { ExtractFile = prev })
			ExtractFile = tt.extractor
			c, err := NewConnector(Config{Extract: true, WorkDir: t.TempDir(), RecursiveExtractMaxDepth: 3, ExtractMinThreshold: 1}, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			c.action = &MockAction{HandleMock: func(context.Context, Source, datamodel.Result, *datamodel.Report) error { return nil }}
			t.Cleanup(func() { c.Close(t.Context()) })
			submitter := archiveCleanSubmitter()
			var submitted atomic.Int32
			submitter.WaitForFileMock = func(context.Context, string, gdetect.WaitForOptions) (gdetect.Result, error) {
				submitted.Add(1)
				return gdetect.Result{}, nil
			}
			echoReader(submitter)
			c.submitter = submitter
			location, sha := createArchive(t, []string{"content"})
			info, err := os.Stat(location)
			if err != nil {
				t.Fatal(err)
			}
			var size int64
			var files int
			archive := fileToAnalyze{sha256: sha, location: location, filename: filepath.Base(location), identity: IdentityOf(info), size: info.Size()}
			err = c.recursiveExtract(archive, 0, &size, &files, logger)
			if tt.wantErr != (err != nil && (strings.Contains(err.Error(), "extract-error") || strings.Contains(err.Error(), "limits of the extraction") || strings.Contains(err.Error(), "damaged or inconsistent"))) {
				t.Errorf("recursiveExtract() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && submitted.Load() != 0 {
				t.Error("an archive in error must never be submitted as a plain file")
			}
		})
	}
}

// fakeExtractor adapts a function that fills outputDir to plugins.ExtractFile.
func fakeExtractor(extract func(outputDir string) (size uint64, files []string, err error)) plugins.ExtractFile {
	return func(_, outputDir string, _ plugins.ExtractLimits) (plugins.Extraction, error) {
		size, files, err := extract(outputDir)
		return plugins.Extraction{Size: size, Files: files}, err
	}
}

func TestDefaultExtractor_onlyAnUnknownTypeIsAPlainFile(t *testing.T) {
	dir := t.TempDir()
	text := filepath.Join(dir, "note.txt")
	if err := os.WriteFile(text, []byte("just text"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ExtractFile(text, t.TempDir(), plugins.ExtractLimits{}); !errors.Is(err, plugins.ErrUnsupportedFormat) {
		t.Errorf("ExtractFile(text) error = %v, want ErrUnsupportedFormat", err)
	}

	full, _ := createArchive(t, []string{"some content that makes the archive longer than a few bytes"})
	raw, err := os.ReadFile(filepath.Clean(full))
	if err != nil {
		t.Fatal(err)
	}
	cut := "cut.zip"
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if e := root.Close(); e != nil {
			t.Error(e)
		}
	}()
	if err := root.WriteFile(cut, raw[:len(raw)/2], 0o600); err != nil {
		t.Fatal(err)
	}
	cut = filepath.Join(dir, cut)
	if _, err := ExtractFile(cut, t.TempDir(), plugins.ExtractLimits{}); err == nil || errors.Is(err, plugins.ErrUnsupportedFormat) {
		t.Errorf("ExtractFile(truncated zip) error = %v, want an extraction error that is not ErrUnsupportedFormat", err)
	}
}

func TestRecursiveExtract_unavailableExtractorIsNotAnArchiveVerdict(t *testing.T) {
	rec := &recordingEventHandler{}
	prevEvents, prevExtract := EventHandler, ExtractFile
	EventHandler = rec
	t.Cleanup(func() { EventHandler, ExtractFile = prevEvents, prevExtract })
	unavailable := true
	ExtractFile = func(_, outputDir string, _ plugins.ExtractLimits) (plugins.Extraction, error) {
		if unavailable {
			return plugins.Extraction{}, fmt.Errorf("7z: %w", plugins.ErrExtractorUnavailable)
		}
		p := filepath.Join(outputDir, "a.txt")
		if err := os.WriteFile(p, []byte("a"), 0o600); err != nil {
			return plugins.Extraction{}, err
		}
		return plugins.Extraction{Size: 1, Files: []string{p}}, nil
	}
	c, err := NewConnector(Config{Extract: true, WorkDir: t.TempDir(), RecursiveExtractMaxDepth: 3, ExtractMinThreshold: 1}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.action = &MockAction{HandleMock: func(context.Context, Source, datamodel.Result, *datamodel.Report) error { return nil }}
	submitter := archiveCleanSubmitter()
	var submitted atomic.Int32
	submitter.WaitForFileMock = func(context.Context, string, gdetect.WaitForOptions) (gdetect.Result, error) {
		submitted.Add(1)
		return gdetect.Result{}, nil
	}
	echoReader(submitter)
	c.submitter = submitter
	t.Cleanup(func() { c.Close(t.Context()) })

	run := func() error {
		location, sha := createArchive(t, []string{"content"})
		info, err := os.Stat(location)
		if err != nil {
			t.Fatal(err)
		}
		var size int64
		var files int
		return c.recursiveExtract(fileToAnalyze{sha256: sha, location: location, filename: filepath.Base(location), size: info.Size()}, 0, &size, &files, logger)
	}
	for range 3 {
		err := run()
		if err == nil || !errors.Is(err, plugins.ErrExtractorUnavailable) || strings.Contains(err.Error(), "extract-error") {
			t.Fatalf("recursiveExtract() error = %v, want an extractor-unavailable error that is not an extract-error", err)
		}
	}
	if submitted.Load() != 0 {
		t.Error("an archive that could not be extracted must not be submitted")
	}
	if rec.errors != 1 || rec.resolutions != 0 {
		t.Errorf("events: %d errors, %d resolutions, want one error raised once", rec.errors, rec.resolutions)
	}
	unavailable = false
	if err := run(); err != nil {
		t.Fatalf("recursiveExtract() once the extractor works error = %v", err)
	}
	if rec.resolutions != 1 {
		t.Errorf("resolutions = %d, want the error resolved at the first extraction that worked", rec.resolutions)
	}
}

// failingEventHandler fails its first failures calls, then records.
type failingEventHandler struct {
	events.NoopEventHandler
	failErrors, failResolutions int
	errors, resolutions         int
}

func (f *failingEventHandler) NotifyError(context.Context, events.ErrorEventType, error) error {
	f.errors++
	if f.failErrors > 0 {
		f.failErrors--
		return errors.New("manager unreachable")
	}
	return nil
}

func (f *failingEventHandler) NotifyResolution(context.Context, string, ...events.ErrorEventType) error {
	f.resolutions++
	if f.failResolutions > 0 {
		f.failResolutions--
		return errors.New("manager unreachable")
	}
	return nil
}

func TestRecursiveExtract_alertIsResolvedWhenTheExtractorRunsAgainWhateverTheArchive(t *testing.T) {
	rec := &recordingEventHandler{}
	prevEvents, prevExtract := EventHandler, ExtractFile
	EventHandler = rec
	t.Cleanup(func() { EventHandler, ExtractFile = prevEvents, prevExtract })
	outcome := fmt.Errorf("7z: %w", plugins.ErrExtractorUnavailable)
	ExtractFile = func(string, string, plugins.ExtractLimits) (plugins.Extraction, error) {
		return plugins.Extraction{}, outcome
	}
	c, err := NewConnector(Config{Extract: true, WorkDir: t.TempDir(), RecursiveExtractMaxDepth: 3, ExtractMinThreshold: 1}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.action = &MockAction{HandleMock: func(context.Context, Source, datamodel.Result, *datamodel.Report) error { return nil }}
	c.submitter = archiveCleanSubmitter()
	t.Cleanup(func() { c.Close(t.Context()) })
	run := func() {
		location, sha := createArchive(t, []string{"content"})
		info, err := os.Stat(location)
		if err != nil {
			t.Fatal(err)
		}
		var size int64
		var files int
		_ = c.recursiveExtract(fileToAnalyze{sha256: sha, location: location, filename: filepath.Base(location), size: info.Size()}, 0, &size, &files, logger)
	}
	run()
	outcome = fmt.Errorf("x: %w", plugins.ErrUnsupportedFormat)
	run()
	if rec.errors != 1 || rec.resolutions != 1 {
		t.Errorf("events: %d errors, %d resolutions, want the alert resolved by a file that is not an archive", rec.errors, rec.resolutions)
	}
}

func TestExtractorAlert_isRetriedWhenTheManagerCannotBeReached(t *testing.T) {
	fh := &failingEventHandler{failErrors: 1, failResolutions: 1}
	prev := EventHandler
	EventHandler = fh
	t.Cleanup(func() { EventHandler = prev })
	c := &Connector{}
	c.extractorUnavailable(plugins.ErrExtractorUnavailable)
	c.extractorUnavailable(plugins.ErrExtractorUnavailable)
	if fh.errors != 2 {
		t.Errorf("error notifications = %d, want a second attempt after the failed one", fh.errors)
	}
	c.extractorAvailable()
	c.extractorAvailable()
	if fh.resolutions != 2 {
		t.Errorf("resolution notifications = %d, want a second attempt after the failed one", fh.resolutions)
	}
	c.extractorAvailable()
	if fh.resolutions != 2 {
		t.Errorf("a resolved alert must not be resolved again (%d)", fh.resolutions)
	}
}

func TestRecursiveExtract_unavailableExtractorOnANestedArchiveLeavesTheTopArchiveUnfinished(t *testing.T) {
	prevExtract := ExtractFile
	t.Cleanup(func() { ExtractFile = prevExtract })
	inner, _ := createArchive(t, []string{"inner content"})
	innerBytes, err := os.ReadFile(filepath.Clean(inner))
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	ExtractFile = func(_, outputDir string, _ plugins.ExtractLimits) (plugins.Extraction, error) {
		calls++
		if calls > 1 {
			return plugins.Extraction{}, fmt.Errorf("7z: %w", plugins.ErrExtractorUnavailable)
		}
		root, err := os.OpenRoot(outputDir)
		if err != nil {
			return plugins.Extraction{}, err
		}
		defer func() {
			if e := root.Close(); e != nil {
				t.Error(e)
			}
		}()
		if err := root.WriteFile("inner.zip", innerBytes, 0o600); err != nil {
			return plugins.Extraction{}, err
		}
		return plugins.Extraction{Size: uint64(len(innerBytes)), Files: []string{filepath.Join(outputDir, "inner.zip")}}, nil
	}
	var handled atomic.Int32
	c, err := NewConnector(Config{Extract: true, WorkDir: t.TempDir(), RecursiveExtractMaxDepth: 3, ExtractMinThreshold: 1}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.action = &MockAction{HandleMock: func(context.Context, Source, datamodel.Result, *datamodel.Report) error {
		handled.Add(1)
		return nil
	}}
	c.submitter = archiveCleanSubmitter()
	t.Cleanup(func() { c.Close(t.Context()) })

	location, sha := createArchive(t, []string{"outer"})
	info, err := os.Stat(location)
	if err != nil {
		t.Fatal(err)
	}
	var size int64
	var files int
	err = c.recursiveExtract(fileToAnalyze{sha256: sha, location: location, filename: filepath.Base(location), size: info.Size()}, 0, &size, &files, logger)
	if !errors.Is(err, plugins.ErrExtractorUnavailable) {
		t.Fatalf("recursiveExtract() error = %v, want ErrExtractorUnavailable to reach the caller", err)
	}
	if handled.Load() != 0 {
		t.Error("the top archive must not get a definitive result for a passing failure of the extractor")
	}
}

func TestRecursiveExtract_abandonedNestedArchiveLeavesNoFolderNorStatus(t *testing.T) {
	prevExtract := ExtractFile
	t.Cleanup(func() { ExtractFile = prevExtract })
	inner, _ := createArchive(t, []string{"inner content"})
	innerBytes, err := os.ReadFile(filepath.Clean(inner))
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	ExtractFile = func(_, outputDir string, _ plugins.ExtractLimits) (plugins.Extraction, error) {
		calls++
		if calls > 1 {
			return plugins.Extraction{}, fmt.Errorf("7z: %w", plugins.ErrExtractorUnavailable)
		}
		root, err := os.OpenRoot(outputDir)
		if err != nil {
			return plugins.Extraction{}, err
		}
		defer func() {
			if e := root.Close(); e != nil {
				t.Error(e)
			}
		}()
		// A plain member goes to the workers first, the sub-archive fails after.
		if err := root.WriteFile("a-plain.txt", []byte("plain member"), 0o600); err != nil {
			return plugins.Extraction{}, err
		}
		if err := root.WriteFile("b-inner.zip", innerBytes, 0o600); err != nil {
			return plugins.Extraction{}, err
		}
		return plugins.Extraction{Size: 12, Files: []string{filepath.Join(outputDir, "a-plain.txt"), filepath.Join(outputDir, "b-inner.zip")}}, nil
	}
	var handled atomic.Int32
	c, err := NewConnector(Config{Extract: true, WorkDir: t.TempDir(), RecursiveExtractMaxDepth: 3, ExtractMinThreshold: 1}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.action = &MockAction{HandleMock: func(context.Context, Source, datamodel.Result, *datamodel.Report) error {
		handled.Add(1)
		return nil
	}}
	c.submitter = archiveCleanSubmitter()
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(t.Context()) })

	location, sha := createArchive(t, []string{"outer"})
	info, err := os.Stat(location)
	if err != nil {
		t.Fatal(err)
	}
	var size int64
	var files int
	err = c.recursiveExtract(fileToAnalyze{sha256: sha, location: location, filename: filepath.Base(location), size: info.Size()}, 0, &size, &files, logger)
	if !errors.Is(err, plugins.ErrExtractorUnavailable) {
		t.Fatalf("recursiveExtract() error = %v, want ErrExtractorUnavailable", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		entries, _ := os.ReadDir(c.work.extractDir())
		c.archiveStatus.RLock()
		pending := len(c.archiveStatus.statusByID)
		c.archiveStatus.RUnlock()
		if len(entries) == 0 && pending == 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	entries, err := os.ReadDir(c.work.extractDir())
	if err != nil {
		t.Fatal(err)
	}
	c.archiveStatus.RLock()
	pending := len(c.archiveStatus.statusByID)
	c.archiveStatus.RUnlock()
	if len(entries) != 0 || pending != 0 {
		t.Errorf("%d folders and %d archive statuses left after an abandoned archive, want none", len(entries), pending)
	}
	if handled.Load() != 0 {
		t.Error("an abandoned archive must get no action")
	}
	if _, err := os.Stat(location); err != nil {
		t.Errorf("the top archive must stay in place: %v", err)
	}
}

func TestAnalyzeArchiveFile_nestedArchiveIsPresentedByItsLogicalPath(t *testing.T) {
	c := &Connector{
		action:          &MockAction{HandleMock: func(context.Context, Source, datamodel.Result, *datamodel.Report) error { return nil }},
		archiveStatus:   newArchiveStatusHandler(),
		ongoingAnalysis: sync.Map{},
	}
	var names, locations []string
	c.RegisterOnScanFile(func(name, location, _ string, isArchive bool) *datamodel.Result {
		if isArchive {
			names, locations = append(names, name), append(locations, location)
		}
		return &datamodel.Result{Filename: "chosen by the plugin", Malware: true, Malwares: []string{"m"}}
	})
	temp := filepath.Join(t.TempDir(), "extract-1", "b.zip")
	id := c.archiveStatus.addStatus(archiveStatus{archiveLocation: temp, tmpFolder: t.TempDir(), total: 1})
	in := fileToAnalyze{
		archiveID:          id,
		archiveLocation:    temp,
		archiveLogicalPath: "/in/alice/a.zip/b.zip",
		filename:           "y.exe",
		logicalPath:        "/in/alice/a.zip/b.zip/y.exe",
		location:           filepath.Join(filepath.Dir(temp), "y.exe"),
	}
	if err := c.analyzeArchiveFile(in); err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || names[0] != "/in/alice/a.zip/b.zip" || locations[0] != temp {
		t.Errorf("plugin saw names %v and locations %v, want the logical path of b.zip and its real location", names, locations)
	}
}

func TestRecursiveExtract_budgetShrinksFromOneLevelToTheNext(t *testing.T) {
	prevExtract := ExtractFile
	t.Cleanup(func() { ExtractFile = prevExtract })
	inner, _ := createArchive(t, []string{"inner"})
	innerBytes, err := os.ReadFile(filepath.Clean(inner))
	if err != nil {
		t.Fatal(err)
	}
	var seen []plugins.ExtractLimits
	ExtractFile = func(_, outputDir string, limits plugins.ExtractLimits) (plugins.Extraction, error) {
		seen = append(seen, limits)
		if len(seen) > 1 {
			return plugins.Extraction{}, fmt.Errorf("%w", plugins.ErrUnsupportedFormat)
		}
		root, err := os.OpenRoot(outputDir)
		if err != nil {
			return plugins.Extraction{}, err
		}
		defer func() {
			if e := root.Close(); e != nil {
				t.Error(e)
			}
		}()
		if err := root.WriteFile("a.txt", []byte("aaaa"), 0o600); err != nil {
			return plugins.Extraction{}, err
		}
		if err := root.WriteFile("b-inner.zip", innerBytes, 0o600); err != nil {
			return plugins.Extraction{}, err
		}
		return plugins.Extraction{Size: 100, Files: []string{filepath.Join(outputDir, "a.txt"), filepath.Join(outputDir, "b-inner.zip")}}, nil
	}
	c, err := NewConnector(Config{Extract: true, WorkDir: t.TempDir(), RecursiveExtractMaxDepth: 3, ExtractMinThreshold: 1, MaxFileSize: 1000, RecursiveExtractMaxFiles: 10, RecursiveExtractMaxSize: 5000}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.action = &MockAction{HandleMock: func(context.Context, Source, datamodel.Result, *datamodel.Report) error { return nil }}
	c.submitter = archiveCleanSubmitter()
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(t.Context()) })
	location, sha := createArchive(t, []string{"outer"})
	info, err := os.Stat(location)
	if err != nil {
		t.Fatal(err)
	}
	var size int64
	var files int
	if err := c.recursiveExtract(fileToAnalyze{sha256: sha, location: location, filename: filepath.Base(location), size: info.Size()}, 0, &size, &files, logger); err != nil {
		t.Fatal(err)
	}
	if len(seen) < 2 {
		t.Fatalf("ExtractFile called %d times, want the sub-archive extracted too", len(seen))
	}
	want0 := plugins.ExtractLimits{MaxFileSize: 1000, MaxFiles: 10, MaxTotalSize: 5000}
	want1 := plugins.ExtractLimits{MaxFileSize: 1000, MaxFiles: 8, MaxTotalSize: 4900}
	if seen[0] != want0 || seen[1] != want1 {
		t.Errorf("limits = %+v then %+v, want %+v then %+v: the budget of the second level is what the first one left", seen[0], seen[1], want0, want1)
	}
}
