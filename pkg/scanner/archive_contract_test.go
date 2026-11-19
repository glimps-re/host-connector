package scanner

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
)

func TestArchiveContract_errorIsOrderIndependent(t *testing.T) {
	bad := datamodel.Result{Error: errors.New("submit failed")}
	clean := datamodel.Result{}
	tooBig := datamodel.Result{Error: errFileTooBig}
	orders := map[string][]datamodel.Result{
		"error first":                   {bad, clean, clean},
		"error last":                    {clean, clean, bad},
		"error mid":                     {clean, bad, clean},
		"too big then error then clean": {tooBig, bad, clean},
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
		})
	}
}

func TestArchiveContract_cleanAndTooBigMembersLeaveNoError(t *testing.T) {
	h := newArchiveStatusHandler()
	id := newArchiveForTest(t, h, 3)
	for i, r := range []datamodel.Result{{}, {Error: errFileTooBig}, {}} {
		h.addInnerFileResult(id, fmt.Sprintf("m%d", i), r)
	}
	st, _ := h.getStatus(id)
	if st.result.Error != nil {
		t.Errorf("archive Error = %v, want nil (too big has its own policy)", st.result.Error)
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
