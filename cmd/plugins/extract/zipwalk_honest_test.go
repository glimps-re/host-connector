package main

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/glimps-re/host-connector/pkg/plugins"
)

// goZip is a zip written by Go's writer, which streams the entries it deflates
// (data descriptors) and writes folders as stored entries.
func goZip(t *testing.T, names ...string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for i, name := range names {
		method := zip.Deflate
		if i == 0 && name == "mimetype" {
			method = zip.Store
		}
		w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: method})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(name, "/") {
			if _, err = w.Write(bytes.Repeat([]byte("<doc>content</doc>"), 50)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// Whatever the tool that wrote them, honest archives stay clean, in extraction and
// in check-only mode: the documents and packages that T48 delivers whole, and the
// zips that are extracted.
func TestRealSevenZip_honestZipsOfTheCommonWritersAreClean(t *testing.T) {
	jar := rawZip{entries: []rawEntry{jarFolder("META-INF/"), fileEntry("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n"), jarFolder("com/"), jarFolder("com/x/"), fileEntry("com/x/A.class", "CAFEBABE")}}.bytes(t)
	apk := rawZip{entries: []rawEntry{fileEntry("AndroidManifest.xml", "<manifest/>"), fileEntry("classes.dex", "dex"), fileEntry("META-INF/CERT.RSA", "sig")}, signingBlock: true}.bytes(t)
	zip64 := rawZip{entries: []rawEntry{func() rawEntry { f := fileEntry("big.bin", "abc"); f.zip64Local, f.zip64Central = true, true; return f }(), folderEntry("d/")}, zip64Directory: true}.bytes(t)
	streamed := rawZip{entries: []rawEntry{func() rawEntry {
		f := fileEntry("s.txt", "streamed")
		f.descriptor, f.localComp, f.localUncomp = 4, 0, 0
		return f
	}(), folderEntry("d/")}}.bytes(t)
	samples := map[string][]byte{
		"docx":             goZip(t, "[Content_Types].xml", "_rels/.rels", "word/document.xml", "word/_rels/document.xml.rels"),
		"xlsx":             goZip(t, "[Content_Types].xml", "_rels/.rels", "xl/workbook.xml", "xl/worksheets/sheet1.xml"),
		"pptx":             goZip(t, "[Content_Types].xml", "ppt/presentation.xml", "ppt/slides/slide1.xml"),
		"odt":              goZip(t, "mimetype", "content.xml", "META-INF/manifest.xml"),
		"epub":             goZip(t, "mimetype", "META-INF/container.xml", "OEBPS/content.opf", "OEBPS/ch1.xhtml"),
		"go, with folders": goZip(t, "d/", "d/a.txt", "d/e/", "d/e/b.txt"),
		"jar":              jar,
		"apk":              apk,
		"zip64":            zip64,
		"streamed":         streamed,
	}
	for name, content := range samples {
		for mode, limits := range map[string]plugins.ExtractLimits{"extraction": extractionMode, "check only": checkOnlyMode} {
			t.Run(name+"/"+mode, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "sample.zip")
				if err := os.WriteFile(path, content, 0o600); err != nil {
					t.Fatal(err)
				}
				if _, err := realPlugin(t).ExtractFile(path, t.TempDir(), limits); err != nil {
					t.Errorf("error = %v, want a clean archive", err)
				}
			})
		}
	}
}

// The archives that 7-Zip, Python and Info-ZIP write (testdata/honest).
func TestRealSevenZip_zipsWrittenByOtherToolsAreClean(t *testing.T) {
	samples, err := filepath.Glob(filepath.Join("testdata", "honest", "*.zip"))
	if err != nil || len(samples) == 0 {
		t.Skipf("no honest sample: %v", err)
	}
	for _, sample := range samples {
		for mode, limits := range map[string]plugins.ExtractLimits{"extraction": extractionMode, "check only": checkOnlyMode} {
			t.Run(filepath.Base(sample)+"/"+mode, func(t *testing.T) {
				if _, err := realPlugin(t).ExtractFile(sample, t.TempDir(), limits); err != nil {
					t.Errorf("error = %v, want a clean archive", err)
				}
			})
		}
	}
}
