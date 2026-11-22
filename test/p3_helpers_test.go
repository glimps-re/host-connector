//go:build linux

package test

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
)

// overLimitEntries is one entry more than the default recursive_extract_max_files.
const overLimitEntries = 10001

// documentHeads are the first entries that type a zip as a document: the
// type is read from the names of the first entries.
var documentHeads = map[string][]string{
	"docx": {"[Content_Types].xml", "word/document.xml"},
	"jar":  {"META-INF/MANIFEST.MF"},
	"apk":  {"AndroidManifest.xml", "classes.dex"},
}

// paddingName is the name of the n-th padding entry of a big document.
func paddingName(n int) string { return fmt.Sprintf("pad/%05d.txt", n) }

// bigDocument builds a zip typed as the kind of document (docx, jar or apk)
// that holds exactly entries entries. The head entries carry the unique text,
// so that two documents never share a SHA256 and the fake service never
// answers from a previous verdict. With encrypted, the last entry is a real
// ZipCrypto member named secret.bin, copied raw from the fixture of the
// extract plugin.
func bigDocument(t *testing.T, kind, unique string, entries int, encrypted bool) []byte {
	t.Helper()
	var raw []byte
	if encrypted {
		var err error
		raw, err = os.ReadFile(filepath.Join("..", "cmd", "plugins", "extract", "testdata", "t17a", "enc_zipcrypto.zip"))
		if err != nil {
			t.Fatal(err)
		}
	}
	return bigDocumentWith(t, kind, unique, entries, raw, false)
}

// bigDocumentWith is bigDocument whose last entry, secret.bin, is the first
// member of the zip rawZip, copied as it is (nil for none). With clearFlag the
// encryption flag of the member is cleared in its local and central headers,
// while its method and data stay those of an encrypted member.
func bigDocumentWith(t *testing.T, kind, unique string, entries int, rawZip []byte, clearFlag bool) []byte {
	t.Helper()
	heads, ok := documentHeads[kind]
	if !ok {
		t.Fatalf("unknown document kind %q", kind)
	}
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	add := func(name, data string) {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = io.WriteString(w, data); err != nil {
			t.Fatal(err)
		}
	}
	for _, h := range heads {
		add(h, unique+" "+h+" "+strings.Repeat("document body ", 20))
	}
	padded := entries - len(heads)
	if rawZip != nil {
		padded--
	}
	for n := range padded {
		add(paddingName(n), "p")
	}
	if rawZip != nil {
		src, err := zip.NewReader(bytes.NewReader(rawZip), int64(len(rawZip)))
		if err != nil || len(src.File) == 0 {
			t.Fatalf("the encrypted zip is unreadable: %v", err)
		}
		f := src.File[0]
		if f.Flags&1 == 0 {
			t.Fatal("the first member of the encrypted zip is not encrypted")
		}
		raw, err := f.OpenRaw()
		if err != nil {
			t.Fatal(err)
		}
		hdr := f.FileHeader
		hdr.Name = "secret.bin"
		if clearFlag {
			hdr.Flags &^= 1
		}
		w, err := zw.CreateRaw(&hdr)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = io.Copy(w, raw); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// bigPlainZip is bigDocument for an ordinary archive: nothing in its entry
// names types it as a document.
func bigPlainZip(t *testing.T, unique string, entries int) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for n := range entries {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: paddingName(n), Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		data := "p"
		if n == 0 {
			data = unique + strings.Repeat(" first member ", 20)
		}
		if _, err = io.WriteString(w, data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// overLimitViolations judges the report entry of a document delivered although
// it is over the check limits: analyzed whole (no reason, no error, not
// malicious), its members listed as not analyzed for the extract limit, with
// the exact count; the listed names are entries of the document.
func overLimitViolations(e datamodel.Report, wantCount int, entryNames map[string]bool) (violations []string) {
	if e.NotAnalyzedReason != "" {
		violations = append(violations, fmt.Sprintf("the document itself is not analyzed: %q", e.NotAnalyzedReason))
	}
	if e.Error != "" {
		violations = append(violations, "the document is in error: "+e.Error)
	}
	if e.Malicious {
		violations = append(violations, "the document is malicious")
	}
	if e.NotAnalyzedExtractedCount != wantCount {
		violations = append(violations, fmt.Sprintf("not analyzed count = %d, want %d", e.NotAnalyzedExtractedCount, wantCount))
	}
	listed := len(e.NotAnalyzedExtractedFiles)
	if listed == 0 || listed > datamodel.MaxListedSubfiles {
		violations = append(violations, fmt.Sprintf("%d members listed, want 1 to %d", listed, datamodel.MaxListedSubfiles))
	}
	if listed > e.NotAnalyzedExtractedCount {
		violations = append(violations, "more members listed than counted")
	}
	seen := map[string]bool{}
	for _, m := range e.NotAnalyzedExtractedFiles {
		if m.Reason != datamodel.NotAnalyzedExtractLimit {
			violations = append(violations, fmt.Sprintf("member %q has the reason %q, want %q", m.FileName, m.Reason, datamodel.NotAnalyzedExtractLimit))
		}
		if !entryNames[m.FileName] {
			violations = append(violations, fmt.Sprintf("member %q is not an entry of the document", m.FileName))
		}
		if seen[m.FileName] {
			violations = append(violations, fmt.Sprintf("member %q is listed twice", m.FileName))
		}
		seen[m.FileName] = true
	}
	return violations
}

// entryNamesOf returns the names of the entries of a zip.
func entryNamesOf(t *testing.T, doc []byte) map[string]bool {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(doc), int64(len(doc)))
	if err != nil {
		t.Fatal(err)
	}
	names := make(map[string]bool, len(zr.File))
	for _, f := range zr.File {
		names[f.Name] = true
	}
	return names
}

func TestBigDocument(t *testing.T) {
	for kind, heads := range documentHeads {
		for _, encrypted := range []bool{false, true} {
			doc := bigDocument(t, kind, "u1", overLimitEntries, encrypted)
			zr, err := zip.NewReader(bytes.NewReader(doc), int64(len(doc)))
			if err != nil {
				t.Fatal(err)
			}
			if len(zr.File) != overLimitEntries {
				t.Errorf("%s encrypted=%v: %d entries, want %d", kind, encrypted, len(zr.File), overLimitEntries)
			}
			for i, h := range heads {
				if zr.File[i].Name != h {
					t.Errorf("%s: entry %d = %q, want %q", kind, i, zr.File[i].Name, h)
				}
			}
			if names := entryNamesOf(t, doc); len(names) != overLimitEntries || !names["secret.bin"] != !encrypted {
				t.Errorf("%s encrypted=%v: %d distinct names", kind, encrypted, len(names))
			}
			var secrets []string
			for _, f := range zr.File {
				if f.Flags&1 != 0 {
					secrets = append(secrets, f.Name)
				}
			}
			switch {
			case encrypted && !slices.Equal(secrets, []string{"secret.bin"}):
				t.Errorf("%s: encrypted members = %v, want secret.bin", kind, secrets)
			case !encrypted && len(secrets) != 0:
				t.Errorf("%s: encrypted members = %v, want none", kind, secrets)
			}
			if len(doc) > 3<<20 {
				t.Errorf("%s: %d bytes, the headers are meant to be cheap", kind, len(doc))
			}
		}
	}
	if bytes.Equal(bigDocument(t, "docx", "u1", 20, false), bigDocument(t, "docx", "u2", 20, false)) {
		t.Error("two documents with different unique texts are equal")
	}
	plain := bigPlainZip(t, "u", 20)
	zr, err := zip.NewReader(bytes.NewReader(plain), int64(len(plain)))
	if err != nil || len(zr.File) != 20 {
		t.Fatalf("plain zip: %d entries, %v", len(zr.File), err)
	}
	for _, heads := range documentHeads {
		if slices.Contains(heads, zr.File[0].Name) {
			t.Errorf("the first entry %q of the plain zip types it as a document", zr.File[0].Name)
		}
	}
}

func TestOuterWithDocument(t *testing.T) {
	doc := bigDocument(t, "docx", "inner", 5, true)
	outer := outerWithDocument(t, "u", doc)
	zr, err := zip.NewReader(bytes.NewReader(outer), int64(len(outer)))
	if err != nil {
		t.Fatal(err)
	}
	if len(zr.File) != overLimitEntries-1 {
		t.Fatalf("%d entries, want %d (below the limit of 10000 on its own)", len(zr.File), overLimitEntries-1)
	}
	last := zr.File[len(zr.File)-1]
	rc, err := last.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rc.Close() }()
	got, err := io.ReadAll(rc)
	if err != nil || last.Name != "doc.docx" || !bytes.Equal(got, doc) {
		t.Errorf("last entry = %q, %d bytes, %v; want doc.docx holding the document", last.Name, len(got), err)
	}
	seen := nestedMembers("u")
	for i, m := range seen {
		rc, err := zr.File[i].Open()
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil || !bytes.Equal(data, m) {
			t.Errorf("file %d = %q, want %q", i, data, m)
		}
	}
}

func TestOverLimitViolations(t *testing.T) {
	names := map[string]bool{"pad/00001.txt": true, "pad/00002.txt": true}
	good := datamodel.Report{
		NotAnalyzedExtractedCount: 10001,
		NotAnalyzedExtractedFiles: []datamodel.NotAnalyzedFile{
			{FileName: "pad/00001.txt", Reason: datamodel.NotAnalyzedExtractLimit},
			{FileName: "pad/00002.txt", Reason: datamodel.NotAnalyzedExtractLimit},
		},
	}
	if v := overLimitViolations(good, 10001, names); len(v) != 0 {
		t.Fatalf("a right entry has violations: %v", v)
	}
	tests := []struct {
		name   string
		change func(r *datamodel.Report)
		want   string
	}{
		{"document not analyzed", func(r *datamodel.Report) { r.NotAnalyzedReason = datamodel.NotAnalyzedExtractLimit }, "not analyzed"},
		{"error", func(r *datamodel.Report) { r.Error = "boom" }, "in error"},
		{"malicious", func(r *datamodel.Report) { r.Malicious = true }, "malicious"},
		{"count", func(r *datamodel.Report) { r.NotAnalyzedExtractedCount = 2 }, "count = 2"},
		{"no member", func(r *datamodel.Report) { r.NotAnalyzedExtractedFiles = nil }, "0 members listed"},
		{"other reason", func(r *datamodel.Report) { r.NotAnalyzedExtractedFiles[0].Reason = datamodel.NotAnalyzedEncrypted }, "has the reason"},
		{"foreign name", func(r *datamodel.Report) { r.NotAnalyzedExtractedFiles[0].FileName = "x" }, "not an entry"},
		{"twice", func(r *datamodel.Report) { r.NotAnalyzedExtractedFiles[1].FileName = "pad/00001.txt" }, "twice"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := good
			r.NotAnalyzedExtractedFiles = slices.Clone(good.NotAnalyzedExtractedFiles)
			tt.change(&r)
			v := overLimitViolations(r, 10001, names)
			if !slices.ContainsFunc(v, func(s string) bool { return strings.Contains(s, tt.want) }) {
				t.Errorf("violations = %v, want one with %q", v, tt.want)
			}
		})
	}
}

// outerWithDocument builds a zip of overLimitEntries-2 plain small files
// followed by the document as doc.docx, overLimitEntries-1 entries in all, so
// the extraction budget the document gets is spent by its parent: the first files carry text the fake
// service can see, the others a single byte.
func outerWithDocument(t *testing.T, unique string, document []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	add := func(name string, data []byte) {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	for n := range overLimitEntries - 2 {
		data := []byte("p")
		if n < nestedSeen {
			data = []byte(fmt.Sprintf("%s plain file %d %s", unique, n, strings.Repeat("filler ", 20)))
		}
		add(paddingName(n), data)
	}
	add("doc.docx", document)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// nestedSeen is how many of the plain files of outerWithDocument carry text.
const nestedSeen = 5

// nestedMembers returns the contents of the plain files of outerWithDocument
// that carry text.
func nestedMembers(unique string) (members [][]byte) {
	for n := range nestedSeen {
		members = append(members, []byte(fmt.Sprintf("%s plain file %d %s", unique, n, strings.Repeat("filler ", 20))))
	}
	return members
}
