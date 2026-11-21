package scanner

import (
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
)

func TestArchiveContract_errorIsOrderIndependent(t *testing.T) {
	bad := datamodel.Result{Error: errors.New("submit failed")}
	clean := datamodel.Result{}
	orders := map[string][]datamodel.Result{
		"error first": {bad, clean, clean},
		"error last":  {clean, clean, bad},
		"error mid":   {clean, bad, clean},
	}
	for name, results := range orders {
		t.Run(name, func(t *testing.T) {
			h := newArchiveStatusHandler()
			id := newArchiveForTest(t, h, len(results))
			var finished bool
			for i, r := range results {
				finished, _ = h.addInnerFileResult(id, fmt.Sprintf("m%d", i), r)
			}
			if !finished {
				t.Fatal("archive must be finished after all members")
			}
			st, _ := h.getStatus(id)
			if !errors.Is(st.result.Error, errInnerTransient) {
				t.Errorf("archive Error = %v, want errInnerTransient whatever the order", st.result.Error)
			}
			if !datamodel.IsExtractedErrorsSummary(st.result.Error.Error()) {
				t.Errorf("archive Error %q is not recognized as the summary of its failed members", st.result.Error)
			}
		})
	}
}

func TestArchiveContract_tooBigOrEncryptedMemberUnderErrorPolicyIsPermanentWhateverTheOrder(t *testing.T) {
	bad := datamodel.Result{Error: errors.New("submit failed")}
	for name, member := range map[string]datamodel.Result{
		"too big":   {Error: errFileTooBig},
		"encrypted": {Error: errEncrypted},
	} {
		for order, results := range map[string][]datamodel.Result{
			"first": {member, bad, {}},
			"last":  {{}, bad, member},
		} {
			t.Run(name+" "+order, func(t *testing.T) {
				h := newArchiveStatusHandler()
				id := newArchiveForTest(t, h, len(results))
				for i, r := range results {
					h.addInnerFileResult(id, fmt.Sprintf("m%d", i), r)
				}
				st, _ := h.getStatus(id)
				if !errors.Is(st.result.Error, errInnerPermanent) || errors.Is(st.result.Error, errInnerTransient) {
					t.Errorf("archive Error = %v, want errInnerPermanent", st.result.Error)
				}
				if !datamodel.IsExtractedErrorsSummary(st.result.Error.Error()) {
					t.Errorf("archive Error %q is not recognized as the summary of its failed members", st.result.Error)
				}
			})
		}
	}
}

func TestArchiveContract_membersPassedWithoutAnalysisAreListedAndLeaveNoError(t *testing.T) {
	h := newArchiveStatusHandler()
	id := newArchiveForTest(t, h, 3)
	passed := datamodel.Result{FileSize: 42, NotAnalyzedReason: datamodel.NotAnalyzedTooBig}
	for i, r := range []datamodel.Result{{}, passed, {}} {
		h.addInnerFileResult(id, fmt.Sprintf("m%d", i), r)
	}
	st, _ := h.getStatus(id)
	if st.result.Error != nil {
		t.Errorf("archive Error = %v, want nil", st.result.Error)
	}
	want := []datamodel.NotAnalyzedFile{{FileName: "m1", Size: 42, Reason: datamodel.NotAnalyzedTooBig}}
	if !reflect.DeepEqual(st.result.NotAnalyzedSubfiles, want) || st.result.NotAnalyzedSubfilesCount != 1 {
		t.Errorf("NotAnalyzedSubfiles = %+v (count %d), want %+v", st.result.NotAnalyzedSubfiles, st.result.NotAnalyzedSubfilesCount, want)
	}
}

func TestArchiveContract_notAnalyzedListIsBoundedAndCountIsExact(t *testing.T) {
	h := newArchiveStatusHandler()
	n := datamodel.MaxListedSubfiles + 50
	id := newArchiveForTest(t, h, n)
	for i := range n {
		h.addInnerFileResult(id, fmt.Sprintf("m%d", i), datamodel.Result{NotAnalyzedReason: datamodel.NotAnalyzedEncrypted})
	}
	st, _ := h.getStatus(id)
	if len(st.result.NotAnalyzedSubfiles) != datamodel.MaxListedSubfiles || st.result.NotAnalyzedSubfilesCount != n {
		t.Errorf("listed %d, count %d, want %d and %d", len(st.result.NotAnalyzedSubfiles), st.result.NotAnalyzedSubfilesCount, datamodel.MaxListedSubfiles, n)
	}
}

func BenchmarkMergeResult_fullNotAnalyzedLists(b *testing.B) {
	base := datamodel.Result{}
	for i := range datamodel.MaxListedSubfiles {
		base = mergeResult(base, datamodel.Result{NotAnalyzedReason: datamodel.NotAnalyzedTooBig}, fmt.Sprintf("m%d", i), nil)
	}
	member := datamodel.Result{NotAnalyzedReason: datamodel.NotAnalyzedTooBig}
	b.ReportAllocs()
	for b.Loop() {
		_ = mergeResult(base, member, "one-more", nil)
	}
}

func TestArchiveContract_emptyMemberKeepsBehaviour(t *testing.T) {
	h := newArchiveStatusHandler()
	id := newArchiveForTest(t, h, 2)
	h.decreaseTotal(id)
	finished, _ := h.addInnerFileResult(id, "ok", datamodel.Result{})
	if !finished {
		t.Error("archive must finish when the empty member is dropped from the total")
	}
	st, _ := h.getStatus(id)
	if st.result.Error != nil || len(st.result.ErrorSubfiles) != 0 {
		t.Errorf("empty member must not mark the archive: Error=%v ErrorSubfiles=%v", st.result.Error, st.result.ErrorSubfiles)
	}
}

func TestArchiveContract_concurrentMemberErrors(t *testing.T) {
	const n = 200
	h := newArchiveStatusHandler()
	id := newArchiveForTest(t, h, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			name := fmt.Sprintf("m%d", i)
			switch i % 3 {
			case 0:
				h.addInnerFileResult(id, name, datamodel.Result{Error: errors.New("x")})
			case 1:
				h.addInnerError(id, name, errors.New("lost"))
			default:
				h.addInnerFileResult(id, name, datamodel.Result{})
			}
		})
	}
	wg.Wait()
	st, _ := h.getStatus(id)
	if !st.finished {
		t.Error("archive must be finished once all members are accounted for")
	}
	if !errors.Is(st.result.Error, errInnerTransient) {
		t.Errorf("archive Error = %v, want errInnerTransient", st.result.Error)
	}
	if got, want := len(st.result.ErrorSubfiles), 2*n/3; got < want-1 || got > want+1 {
		t.Errorf("ErrorSubfiles = %d entries, want about %d", got, want)
	}
}
