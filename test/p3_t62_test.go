//go:build linux && e2e

package test

import (
	"slices"
	"strings"
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
)

// documentEntry returns the report entry of a delivered document.
func documentEntry(t *testing.T, in *instance, doc []byte) datamodel.Report {
	t.Helper()
	entries := in.reportsOf(t, doc)
	if len(entries) != 1 {
		t.Fatalf("%d report entries for the document, want 1: %+v", len(entries), entries)
	}
	return entries[0]
}

// T62: a docx, a jar or an apk over the check limits (10,001 entries) is
// analyzed whole and delivered as a plain file, under the default policies. It
// counts as analyzed, and its members are listed as not analyzed for the
// extract limit, with the exact count.
func TestE2E_anOverLimitDocumentIsDeliveredWithItsMembersUnchecked(t *testing.T) {
	gm := newGMalware(t, false)
	in := startInstance(t, gm, options{extract: true})
	in.expect.allow(datamodel.NotAnalyzedExtractLimit)
	docs := map[string][]byte{}
	for _, kind := range []string{"docx", "jar", "apk"} {
		doc := bigDocument(t, kind, "delivered "+kind, overLimitEntries, false)
		docs[kind] = doc
		in.drop(t, "big."+kind, doc)
	}
	for kind := range docs {
		in.waitFor(t, "the "+kind+" to be delivered", func() bool { return in.inOutput("big." + kind) })
	}
	in.waitFor(t, "the session report", func() bool { return in.reportCount() > 0 })
	for kind, doc := range docs {
		if _, analyzed := gm.Given(sha256Hex(doc)); !analyzed {
			t.Errorf("%s: the document was not analyzed whole by the service", kind)
		}
		if names := gm.SubmittedNames(doc); len(names) != 1 || !strings.HasSuffix(names[0], "/big."+kind) {
			t.Errorf("%s: submitted as %q, want its own path", kind, names)
		}
		for _, v := range overLimitViolations(documentEntry(t, in, doc), overLimitEntries, entryNamesOf(t, doc)) {
			t.Errorf("%s: %s", kind, v)
		}
	}
}

// T62: a detection on an over-limit document still quarantines it: it never
// reaches OUTPUT, and its report lists no unchecked member, as the detection
// is the outcome.
func TestE2E_anOverLimitDocumentThatIsMalwareIsQuarantined(t *testing.T) {
	gm := newGMalware(t, false)
	in := startInstance(t, gm, options{extract: true})
	doc := bigDocument(t, "docx", "malicious", overLimitEntries, false)
	gm.MarkMalicious(doc)
	path := in.drop(t, "bad.docx", doc)
	in.quarantinedFile(t, path, doc)
	in.waitFor(t, "the session report", func() bool { return in.reportCount() > 0 })
	entries := in.reportsOf(t, doc)
	if !slices.ContainsFunc(entries, func(e datamodel.Report) bool { return e.Malicious }) {
		t.Error("no report entry says the document is malicious")
	}
	for _, e := range entries {
		if len(e.NotAnalyzedExtractedFiles) != 0 || e.NotAnalyzedExtractedCount != 0 {
			t.Errorf("the quarantined document lists %d unchecked members (count %d), want none", len(e.NotAnalyzedExtractedFiles), e.NotAnalyzedExtractedCount)
		}
	}
}

// T62: the relief is for documents only. An ordinary zip over the limits is
// still left out and held in INPUT, whatever its entries; a document of the
// same run is delivered, so the difference is the type, not the load.
func TestE2E_anOrdinaryZipOverTheLimitsIsStillHeld(t *testing.T) {
	gm := newGMalware(t, false)
	in := startInstance(t, gm, options{extract: true})
	in.expect.allow(datamodel.NotAnalyzedExtractLimit)
	plain := bigPlainZip(t, "ordinary", overLimitEntries)
	doc := bigDocument(t, "docx", "control", overLimitEntries, false)
	path := in.drop(t, "big.zip", plain)
	in.drop(t, "ctl.docx", doc)
	in.waitFor(t, "the document to be delivered", func() bool { return in.inOutput("ctl.docx") })
	in.staysInInput(t, path, plain)
	in.heldWith(t, plain, "left out by the limits of the extraction")
}
