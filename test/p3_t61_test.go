//go:build linux && e2e

package test

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	hcquarantine "github.com/glimps-re/host-connector/pkg/quarantine"
)

// restoredEntries returns the report entries of the content that say it was
// restored, tolerating a report being written.
func restoredEntries(in *instance, content []byte) (restored, others []datamodel.Report) {
	reports, _ := readSessionReports(in.export)
	for _, e := range reports[sha256Hex(content)] {
		if restoredEntry(e) {
			restored = append(restored, e)
		} else {
			others = append(others, e)
		}
	}
	return restored, others
}

// T61: a restored file that is delivered is listed as not analyzed with the
// reason "restored": it was not analyzed, so it must not pass for analyzed.
// The detection that quarantined it earlier stays in the reports, and an
// ordinary file of the same run carries no reason.
func TestE2E_aRestoredFileIsListedAsNotAnalyzed(t *testing.T) {
	gm := newGMalware(t, false)
	in := startInstance(t, gm, options{agent: true})
	bad := []byte("this content is a malware, restored then reported as not analyzed")
	clean := []byte("an ordinary file that is analyzed")
	gm.MarkMalicious(bad)
	in.expect.release(bad)
	path := in.drop(t, "bad.txt", bad)
	id := hcquarantine.ComputeCacheID(path, sha256Hex(bad))
	lock := filepath.Join(in.quarantine, id+".lock")
	in.waitFor(t, "the quarantine", func() bool { return !in.gone(lock) })
	in.waitFor(t, "the malware to leave INPUT", func() bool { return in.gone(path) })
	if msg := in.console.WaitAck(t, in.console.Push(t, "restore", map[string]string{"id": id})); msg != "" {
		t.Fatalf("restore refused: %s", msg)
	}
	in.drop(t, "clean.txt", clean)
	in.waitFor(t, "the restored file to be delivered", func() bool { return in.inOutput("bad.txt") })
	in.waitFor(t, "the clean file to be delivered", func() bool { return in.inOutput("clean.txt") })
	in.waitFor(t, "the restored entry in a session report", func() bool {
		restored, _ := restoredEntries(in, bad)
		return len(restored) > 0
	})
	in.waitFor(t, "the clean file in a session report", func() bool { return len(readReports(in)[sha256Hex(clean)]) > 0 })

	restored, others := restoredEntries(in, bad)
	if len(restored) != 1 {
		t.Fatalf("%d restored entries, want 1: %+v", len(restored), restored)
	}
	r := restored[0]
	if r.NotAnalyzedReason != datamodel.NotAnalyzedRestored {
		t.Errorf("reason of the restored file = %q, want %q", r.NotAnalyzedReason, datamodel.NotAnalyzedRestored)
	}
	if !r.HasBeenRestored {
		t.Error("the restored entry does not carry the restored mark")
	}
	if r.Malicious || r.Error != "" || len(r.NotAnalyzedExtractedFiles) != 0 {
		t.Errorf("the restored entry = %+v, want delivered with no detection, no error, no member", r)
	}
	if !slices.ContainsFunc(others, func(e datamodel.Report) bool { return e.Malicious }) {
		t.Error("the detection that quarantined the file is gone from the reports")
	}
	for _, e := range readReports(in)[sha256Hex(clean)] {
		if e.NotAnalyzedReason != "" || e.HasBeenRestored || e.Error != "" {
			t.Errorf("the ordinary file = %+v, want analyzed with no reason", e)
		}
	}
}

// readReports reads the session reports, tolerating one being written.
func readReports(in *instance) map[string][]datamodel.Report {
	reports, _ := readSessionReports(in.export)
	return reports
}
