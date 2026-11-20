//go:build linux

package scanner

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/quarantine"
)

// A content restored from quarantine must not be quarantined again when it is
// deposited at another path, and the report must say it was restored.
func TestT14a_aRestoredContentDepositedElsewhereIsNotQuarantinedAgain(t *testing.T) {
	qdir := t.TempDir()
	q, err := quarantine.NewQuarantineHandler(t.Context(), quarantine.Config{Location: qdir, LockPassword: "infected"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if e := q.Close(); e != nil {
			t.Errorf("Close() error = %v", e)
		}
	})

	// B is quarantined, then restored by the operator.
	first := filepath.Join(t.TempDir(), "restored-by-the-operator.bin")
	if err = os.WriteFile(first, []byte(originalContent), 0o600); err != nil {
		t.Fatal(err)
	}
	_, id, err := q.Quarantine(t.Context(), first, shaOf(originalContent), []string{"m"})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(first); err != nil {
		t.Fatal(err)
	}
	if err = q.Restore(t.Context(), id); err != nil {
		t.Fatal(err)
	}
	locksBefore, err := filepath.Glob(filepath.Join(qdir, "*.lock"))
	if err != nil {
		t.Fatal(err)
	}

	// The same content arrives at a new path; the service would call it malware.
	var f *swapFixture
	f = newSwapFixture(t, serviceSubmitter(&f, nil))
	var mu sync.Mutex
	var results []datamodel.Result
	var reports []datamodel.Report
	f.c.quarantiner = q
	f.c.action = NewMultiAction(&ReportAction{}, NewQuarantineAction(q), &MockAction{HandleMock: func(_ context.Context, _ string, r datamodel.Result, rep *datamodel.Report) error {
		mu.Lock()
		defer mu.Unlock()
		results = append(results, r)
		reports = append(reports, *rep)
		return nil
	}})
	f.run(t)

	locksAfter, err := filepath.Glob(filepath.Join(qdir, "*.lock"))
	if err != nil {
		t.Fatal(err)
	}
	if len(locksAfter) != len(locksBefore) {
		t.Errorf("quarantine holds %d container(s), was %d: a restored content must not be quarantined again", len(locksAfter), len(locksBefore))
	}
	if _, serr := os.Stat(f.file); serr != nil {
		t.Errorf("the deposited file must be left alone: %v", serr)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(results) != 1 {
		t.Fatalf("the actions ran %d time(s), want once: the restored file is handled, not skipped", len(results))
	}
	for _, r := range results {
		if !r.Restored {
			t.Errorf("a file whose content was restored reached the actions as a plain result: %+v", r)
		}
	}
	for _, rep := range reports {
		if !rep.HasBeenRestored {
			t.Errorf("the report does not say the content was restored: %+v", rep)
		}
	}
}
