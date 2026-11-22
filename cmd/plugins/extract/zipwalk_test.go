package main

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"context"
	le "encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"runtime"
	"slices"
	"testing"
	"time"
)

func flated(t *testing.T, data string) []byte {
	t.Helper()
	var buf bytes.Buffer
	fw, err := flate.NewWriter(&buf, flate.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.WriteString(fw, data); err != nil {
		t.Fatal(err)
	}
	if err = fw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func wantAnomaly(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, errZipStructure) {
		t.Errorf("walkZip() = %v, want an anomaly", err)
	}
}

func TestWalkZip_folderEntries(t *testing.T) {
	plain := fileEntry("a.txt", "0123456789")
	const unixDir = 0x41ED << 16
	const amigaDir = 0x0800 << 16
	filler := bytes.Repeat([]byte("X"), 100_000)
	nonEnding := bytes.Repeat([]byte{0x00, 0x00, 0x00, 0xff, 0xff}, 5)
	hidden := func(e rawEntry) rawEntry {
		e.data, e.centralComp, e.localComp = filler, uint64(len(filler)), uint64(len(filler))
		return e
	}
	tests := []struct {
		name    string
		folder  rawEntry
		zip64   bool
		wantErr bool
		// folderData says that the refusal is the one of a folder that holds data
		// (errFolderData), not of the headers that do not add up.
		folderData bool
	}{
		{name: "an empty stored folder", folder: folderEntry("d/")},
		{name: "a folder deflated on its own", folder: rawEntry{name: "d/", method: zipMethodDeflate, data: deflateEmptyData, localComp: 2, centralComp: 2}},
		{name: "a jar folder: descriptor, empty deflate block", folder: jarFolder("d/")},
		{name: "a jar folder, ZIP64 descriptor", folder: rawEntry{name: "d/", method: zipMethodDeflate, data: deflateEmptyData, centralComp: 2, descriptor: 4}},
		{name: "a folder marked by the DOS attribute", folder: rawEntry{name: "d", attrs: dosFolder}},
		{name: "a folder marked by the Unix mode", folder: rawEntry{name: "d", attrs: unixDir}},
		{name: "a backslash folder of the FAT host", folder: rawEntry{name: "d\\", madeBy: zipHostFAT << 8}},
		{name: "a backslash folder of the NTFS host", folder: rawEntry{name: "d\\", madeBy: zipHostNTFS << 8}},
		{name: "an Amiga folder", folder: rawEntry{name: "d", madeBy: zipHostAmiga << 8, attrs: amigaDir}},
		{name: "ZIP64 sizes and directory, empty", folder: rawEntry{name: "d/", zip64Local: true, zip64Central: true}, zip64: true},
		{name: "ZIP64 sizes, 100 KB behind", folder: hidden(rawEntry{name: "d/", zip64Local: true, zip64Central: true}), zip64: true, wantErr: true, folderData: true},
		{name: "central 0/0, a stored local entry of 100 KB", folder: hidden(rawEntry{name: "d/"}), wantErr: true, folderData: true},
		{name: "a backslash folder of the FAT host with 100 KB", folder: hidden(rawEntry{name: "evil\\", madeBy: zipHostFAT << 8}), wantErr: true, folderData: true},
		{name: "a backslash folder of the NTFS host with 100 KB", folder: hidden(rawEntry{name: "evil\\", madeBy: zipHostNTFS << 8}), wantErr: true, folderData: true},
		{name: "an Amiga folder with 100 KB", folder: hidden(rawEntry{name: "d", madeBy: zipHostAmiga << 8, attrs: amigaDir}), wantErr: true, folderData: true},
		{name: "central 0/2 but local 0/0", folder: rawEntry{name: "d/", method: zipMethodDeflate, centralComp: 2}, wantErr: true},
		{name: "central 0/0 but local 2 bytes", folder: rawEntry{name: "d/", method: zipMethodDeflate, data: deflateEmptyData, localComp: 2}, wantErr: true},
		{name: "two bytes that are not the empty block", folder: rawEntry{name: "d/", method: zipMethodDeflate, data: []byte{0xAB, 0xCD}, localComp: 2, centralComp: 2}, wantErr: true, folderData: true},
		{name: "two bytes of a stored entry", folder: rawEntry{name: "d/", data: deflateEmptyData, localComp: 2, centralComp: 2}, wantErr: true, folderData: true},
		{name: "central 0/5", folder: rawEntry{name: "d/", data: []byte("hello"), centralComp: 5}, wantErr: true},
		{name: "a descriptor and a stream that yields data", folder: rawEntry{name: "d/", method: zipMethodDeflate, data: flated(t, "payload"), centralComp: 9, descriptor: 2}, wantErr: true},
		{name: "a descriptor and a stream that does not end in 16 bytes", folder: rawEntry{name: "d/", method: zipMethodDeflate, data: nonEnding, centralComp: 20, descriptor: 2}, wantErr: true},
		{name: "a descriptor and no data at all", folder: rawEntry{name: "d/", method: zipMethodDeflate, descriptor: 2}, wantErr: true, folderData: true},
		{name: "a descriptor with a stored entry", folder: rawEntry{name: "d/", data: deflateEmptyData, centralComp: 2, descriptor: 2}, wantErr: true, folderData: true},
		{name: "an empty block with bytes behind it, in the length the directory gives", folder: rawEntry{name: "d/", method: zipMethodDeflate, data: append(bytes.Clone(deflateEmptyData), []byte("PK\x03\x04")...), localComp: 6, centralComp: 6}, wantErr: true, folderData: true},
		{name: "a deflate folder of 0/0 with a stream behind it", folder: rawEntry{name: "d/", method: zipMethodDeflate, data: flated(t, "payload")}, wantErr: true},
		{name: "a deflate folder of 0/0 and nothing behind it", folder: rawEntry{name: "d/", method: zipMethodDeflate}, wantErr: true, folderData: true},
		{name: "a folder whose local method is not the one of the directory", folder: rawEntry{name: "d/", method: zipMethodStored, centralMethod: new(uint16(zipMethodDeflate))}, wantErr: true},
		{name: "a deflate folder whose stream yields data, in a length the directory gives", folder: rawEntry{name: "d/", method: zipMethodDeflate, data: flated(t, "payload"), localComp: uint64(len(flated(t, "payload"))), centralComp: uint64(len(flated(t, "payload")))}, wantErr: true, folderData: true},
		{name: "a bzip2 folder", folder: rawEntry{name: "d/", method: 12, data: []byte("BZh9"), localComp: 4, centralComp: 4}, wantErr: true, folderData: true},
		{name: "an encrypted folder", folder: rawEntry{name: "d/", flags: zipFlagEncrypted}, wantErr: true, folderData: true},
		{name: "a Unix folder with data", folder: hidden(rawEntry{name: "d", attrs: unixDir}), wantErr: true, folderData: true},
		{name: "a DOS folder with data", folder: hidden(rawEntry{name: "d", attrs: dosFolder}), wantErr: true, folderData: true},
		{name: "a folder with a name that has a line feed", folder: hidden(rawEntry{name: "n\nl/"}), wantErr: true, folderData: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := rawZip{entries: []rawEntry{plain, tt.folder}, zip64Directory: tt.zip64}.bytes(t)
			err := walkBytes(b, 2, 1)
			switch {
			case tt.wantErr:
				wantAnomaly(t, err)
				if got := errors.Is(err, errFolderData); got != tt.folderData {
					t.Errorf("walkZip() = %v, folder data %t, want %t", err, got, tt.folderData)
				}
			case err != nil:
				t.Errorf("walkZip() = %v, want the folder accepted", err)
			}
		})
	}
	t.Run("a folder of the Unix host with a backslash is a file", func(t *testing.T) {
		if err := walkBytes(rawZip{entries: []rawEntry{plain, func() rawEntry { e := fileEntry("evil\\", "data"); e.madeBy = 3 << 8; return e }()}}.bytes(t), 2, 0); err != nil {
			t.Errorf("walkZip() = %v, want a file with a backslash accepted", err)
		}
	})
}

func TestWalkZip_countsTheFoldersTheListingSaw(t *testing.T) {
	b := rawZip{entries: []rawEntry{fileEntry("a.txt", "x"), folderEntry("d/")}}.bytes(t)
	if err := walkBytes(b, 2, 1); err != nil {
		t.Errorf("walkZip() = %v, want the folder seen by both", err)
	}
	wantAnomaly(t, walkBytes(b, 2, 2))
	files := rawZip{entries: []rawEntry{fileEntry("a.txt", "x"), fileEntry("b.txt", "y")}}.bytes(t)
	wantAnomaly(t, walkBytes(files, 2, 1))
}

func TestWalkZip_structure(t *testing.T) {
	good := rawZip{entries: []rawEntry{folderEntry("d/"), folderEntry("e/")}}.bytes(t)
	cases := []struct {
		name    string
		zip     []byte
		entries int
	}{
		{"fewer entries than 7-Zip listed", good, 3},
		{"more entries than 7-Zip listed", good, 1},
		{"no end of directory", bytes.Repeat([]byte("X"), 100), 2},
		{"a file shorter than an end of directory", []byte("PK"), 2},
		{"a directory cut short", append(append([]byte{}, good[:len(good)-zipEOCDLen-20]...), good[len(good)-zipEOCDLen:]...), 2},
		{"a bad signature in the directory", bytes.Replace(good, []byte("PK\x01\x02"), []byte("PK\x01\x09"), 1), 2},
		{"a bad local header", bytes.Replace(good, []byte("PK\x03\x04"), []byte("PK\x03\x09"), 1), 2},
		{"an entry without a name", rawZip{entries: []rawEntry{folderEntry("d/"), folderEntry("")}}.bytes(t), 2},
		{"a zip on several disks", func() []byte {
			b := bytes.Clone(good)
			b[len(b)-zipEOCDLen+4] = 1
			return b
		}(), 2},
		{"a local header offset out of the file", func() []byte {
			b := bytes.Clone(good)
			i := bytes.LastIndex(b, []byte("PK\x01\x02"))
			b[i+45] = 0x7f
			return b
		}(), 2},
		{"the directory out of the file", func() []byte {
			b := bytes.Clone(good)
			b[len(b)-zipEOCDLen+19] = 0x7f
			return b
		}(), 2},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) { wantAnomaly(t, walkBytes(tt.zip, tt.entries, 0)) })
	}
	t.Run("the honest zip is accepted", func(t *testing.T) {
		if err := walkBytes(good, 2, 2); err != nil {
			t.Errorf("walkZip() = %v", err)
		}
	})
	t.Run("a record in the comment that ends the file is a second end, whatever it points to", func(t *testing.T) {
		for _, junk := range []string{string(eocd(nil, 7, 0, 0, "")), string(eocd(nil, 2, 0, 0, ""))} {
			b := rawZip{entries: []rawEntry{folderEntry("d/"), folderEntry("e/")}, comment: junk}.bytes(t)
			wantAnomaly(t, walkBytes(b, 2, 2))
		}
	})
	t.Run("an empty zip", func(t *testing.T) {
		if err := walkBytes(rawZip{}.bytes(t), 0, 0); err != nil {
			t.Errorf("walkZip() = %v", err)
		}
	})
	t.Run("data before an empty directory", func(t *testing.T) {
		wantAnomaly(t, walkBytes(append([]byte("junk"), rawZip{}.bytes(t)[:0]...), 0, 0))
		b := append([]byte("junk"), eocd(nil, 0, 0, 4, "")...)
		wantAnomaly(t, walkBytes(b, 0, 0))
	})
	zip64 := rawZip{entries: []rawEntry{folderEntry("d/")}, zip64Directory: true}.bytes(t)
	for name, b := range map[string][]byte{
		"no ZIP64 locator":      bytes.Replace(zip64, []byte("PK\x06\x07"), []byte("PK\x06\x09"), 1),
		"no ZIP64 record":       bytes.Replace(zip64, []byte("PK\x06\x06"), []byte("PK\x06\x09"), 1),
		"a record out of range": func() []byte { b := bytes.Clone(zip64); b[len(b)-zipEOCDLen-zipLocatorLen+15] = 0x7f; return b }(),
	} {
		t.Run(name, func(t *testing.T) { wantAnomaly(t, walkBytes(b, 1, 0)) })
	}
}

// What the directory does not list: records between the entries, after the last
// one, before the first, entries at the same place.
func TestWalkZip_contiguity(t *testing.T) {
	record := rawZip{entries: []rawEntry{fileEntry("evil.exe", "MZ-hidden")}}.bytes(t)
	record = record[:bytes.LastIndex(record, []byte("PK\x01\x02"))]
	tests := []struct {
		name    string
		zip     rawZip
		folders int
		wantErr bool
	}{
		{name: "files, stored", zip: rawZip{entries: []rawEntry{fileEntry("a", "1"), fileEntry("b", "22")}}},
		{name: "files and folders", zip: rawZip{entries: []rawEntry{folderEntry("d/"), fileEntry("d/a", "1"), jarFolder("e/")}}, folders: 2},
		{name: "a record behind an empty folder", zip: rawZip{entries: func() []rawEntry { f := folderEntry("d/"); f.slack = record; return []rawEntry{f, fileEntry("a", "1")} }()}, folders: 1, wantErr: true},
		{name: "a record behind a jar folder", zip: rawZip{entries: func() []rawEntry { f := jarFolder("d/"); f.slack = record; return []rawEntry{f, fileEntry("a", "1")} }()}, folders: 1, wantErr: true},
		{name: "a record behind a file, in a zip with no folder", zip: rawZip{entries: func() []rawEntry {
			f := fileEntry("a", "1")
			f.slack = record
			return []rawEntry{f, fileEntry("b", "2")}
		}()}, wantErr: true},
		{name: "a record behind the last file", zip: rawZip{entries: func() []rawEntry {
			f := fileEntry("a", "1")
			f.slack = record
			return []rawEntry{fileEntry("b", "2"), f}
		}()}, wantErr: true},
		{name: "one byte of slack that is not zero", zip: rawZip{entries: func() []rawEntry { f := fileEntry("a", "1"); f.slack = []byte{1}; return []rawEntry{f} }()}, wantErr: true},
		{name: "zeros between two entries", zip: rawZip{entries: func() []rawEntry {
			f := fileEntry("a", "1")
			f.slack = make([]byte, 2994)
			return []rawEntry{f, fileEntry("b", "2")}
		}()}},
		{name: "zeros after the last entry", zip: rawZip{entries: func() []rawEntry { f := fileEntry("a", "1"); f.slack = make([]byte, 100); return []rawEntry{f} }()}},
		{name: "zeros and then one byte that is not", zip: rawZip{entries: func() []rawEntry {
			f := fileEntry("a", "1")
			f.slack = append(make([]byte, 100), 7)
			return []rawEntry{f, fileEntry("b", "2")}
		}()}, wantErr: true},
		{name: "a record behind zeros", zip: rawZip{entries: func() []rawEntry {
			f := fileEntry("a", "1")
			f.slack = append(make([]byte, 100), record...)
			return []rawEntry{f, fileEntry("b", "2")}
		}()}, wantErr: true},
		{name: "zeros before an APK signing block", zip: rawZip{entries: []rawEntry{func() rawEntry { f := fileEntry("a", "1"); f.slack = make([]byte, 11180); return f }()}, signingBlock: true}},
		{name: "a non-zero byte before an APK signing block", zip: rawZip{entries: []rawEntry{func() rawEntry { f := fileEntry("a", "1"); f.slack = append(make([]byte, 1000), 1); return f }()}, signingBlock: true}, wantErr: true},
		{name: "two entries at the same place", zip: rawZip{entries: []rawEntry{fileEntry("a", "1"), func() rawEntry { f := fileEntry("b", "1"); f.centralOnly, f.sameOffsetAs = true, 1; return f }()}}, wantErr: true},
		{name: "a descriptor of 12 bytes", zip: rawZip{entries: []rawEntry{func() rawEntry {
			f := fileEntry("a", "abc")
			f.descriptor = 1
			f.localComp, f.localUncomp = 0, 0
			return f
		}(), fileEntry("b", "2")}}},
		{name: "a descriptor of 16 bytes", zip: rawZip{entries: []rawEntry{func() rawEntry {
			f := fileEntry("a", "abc")
			f.descriptor = 2
			f.localComp, f.localUncomp = 0, 0
			return f
		}(), fileEntry("b", "2")}}},
		{name: "a descriptor of 20 bytes", zip: rawZip{entries: []rawEntry{func() rawEntry {
			f := fileEntry("a", "abc")
			f.descriptor = 3
			f.localComp, f.localUncomp = 0, 0
			return f
		}(), fileEntry("b", "2")}}},
		{name: "a descriptor of 24 bytes", zip: rawZip{entries: []rawEntry{func() rawEntry {
			f := fileEntry("a", "abc")
			f.descriptor = 4
			f.localComp, f.localUncomp = 0, 0
			return f
		}(), fileEntry("b", "2")}}},
		{name: "a descriptor that is not the one of the directory", zip: rawZip{entries: []rawEntry{func() rawEntry {
			f := fileEntry("a", "abc")
			f.descriptor, f.localComp, f.localUncomp, f.badDescriptor = 2, 0, 0, true
			return f
		}(), fileEntry("b", "2")}}, wantErr: true},
		{name: "a flagged descriptor that is not there", zip: rawZip{entries: []rawEntry{func() rawEntry { f := fileEntry("a", "abc"); f.flags = zipFlagDescriptor; return f }(), fileEntry("b", "2")}}, wantErr: true},
		{name: "ZIP64 entries and directory", zip: rawZip{entries: []rawEntry{func() rawEntry { f := fileEntry("a", "abc"); f.zip64Local, f.zip64Central = true, true; return f }(), fileEntry("b", "2")}, zip64Directory: true}},
		{name: "an APK signing block before the directory", zip: rawZip{entries: []rawEntry{fileEntry("a", "1")}, signingBlock: true}},
		{name: "a signing block and no entry", zip: rawZip{signingBlock: true}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := tt.zip.bytes(t)
			err := walkBytes(b, len(tt.zip.entries), tt.folders)
			if tt.wantErr {
				wantAnomaly(t, err)
			} else if err != nil {
				t.Errorf("walkZip() = %v, want a clean zip", err)
			}
		})
	}
	t.Run("a signing block whose sizes disagree", func(t *testing.T) {
		b := rawZip{entries: []rawEntry{fileEntry("a", "1")}, signingBlock: true}.bytes(t)
		i := bytes.LastIndex(b, []byte(zipSigBlockMagic))
		b[i-8]++
		wantAnomaly(t, walkBytes(b, 1, 0))
	})
	t.Run("space before the directory that is not a signing block", func(t *testing.T) {
		wantAnomaly(t, walkBytes(rawZip{entries: func() []rawEntry {
			f := fileEntry("a", "1")
			f.slack = bytes.Repeat([]byte{1}, 64)
			return []rawEntry{f}
		}()}.bytes(t), 1, 0))
	})
	t.Run("data before the first entry", func(t *testing.T) {
		wantAnomaly(t, walkBytes(rawZip{entries: []rawEntry{fileEntry("a", "1")}, prefix: []byte("MZ-stub")}.bytes(t), 1, 0))
	})
	t.Run("a decoy directory in the comment that is a valid copy of the real one", func(t *testing.T) {
		good := rawZip{entries: []rawEntry{fileEntry("a", "1"), folderEntry("d/")}}
		if err := walkBytes(good.bytes(t), 2, 1); err != nil {
			t.Fatalf("walkZip() = %v, want the zip without a decoy accepted", err)
		}
		good.decoy = true
		wantAnomaly(t, walkBytes(good.bytes(t), 2, 1))
	})
}

// Honest writers: the zips that Go writes, streaming and not, with and without
// folders.
func TestWalkZip_aZipWrittenByGo(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, h := range []zip.FileHeader{
		{Name: "[Content_Types].xml", Method: zip.Deflate},
		{Name: "word/", Method: zip.Store},
		{Name: "word/document.xml", Method: zip.Deflate},
		{Name: "word/media/", Method: zip.Store},
		{Name: "word/media/a.png", Method: zip.Store},
	} {
		w, err := zw.CreateHeader(&h)
		if err != nil {
			t.Fatal(err)
		}
		if h.Name[len(h.Name)-1] != '/' {
			if _, err = w.Write(bytes.Repeat([]byte("<x/>"), 100)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := walkBytes(buf.Bytes(), 5, 2); err != nil {
		t.Errorf("walkZip() = %v, want the zip of Go accepted", err)
	}
}

// Only the headers are read: a member that declares 2 GiB under a folder costs
// nothing, whatever it holds.
func TestWalkZip_neverDecompressesAMember(t *testing.T) {
	big := rawEntry{name: "d/zeros", method: zipMethodDeflate, data: []byte("not a deflate stream"), localComp: 20, localUncomp: 2 << 30, centralComp: 20, centralUncomp: 2 << 30}
	b := rawZip{entries: []rawEntry{folderEntry("d/"), big}}.bytes(t)
	start := time.Now()
	if err := walkBytes(b, 2, 1); err != nil {
		t.Fatalf("walkZip() = %v", err)
	}
	if took := time.Since(start); took > slowdown*time.Second {
		t.Errorf("the walk took %v", took)
	}
}

// 1 M central entries that alternate between two local headers, with saturated sizes
// and extra fields of 65535 bytes: refused after the first pass, in time and
// memory. The time depends on the machine: it is logged, and asserted only with
// HC_WORST_CASE_TIME=1.
func TestWalkZip_aThrashingDirectoryIsRefusedFast(t *testing.T) {
	const n = 1_000_000
	extra := bytes.Repeat([]byte{0}, 65535-20)
	entries := make([]rawEntry, n)
	for i := range entries {
		switch {
		case i < 2:
			entries[i] = rawEntry{name: fmt.Sprintf("d%d/", i), zip64Local: true, zip64Central: true, localExtra: extra}
		default:
			entries[i] = rawEntry{name: "x/", zip64Central: true, centralOnly: true, sameOffsetAs: 1 + i%2}
		}
	}
	b := rawZip{entries: entries, zip64Directory: true}.bytes(t)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	start := time.Now()
	err := walkBytes(b, n, 2)
	took := time.Since(start)
	runtime.ReadMemStats(&after)
	wantAnomaly(t, err)
	allocated := after.TotalAlloc - before.TotalAlloc
	t.Logf("%d entries (%d MB): refused in %v, %d MB allocated", n, len(b)>>20, took, allocated>>20)
	if allocated > 16<<20 {
		t.Errorf("refused with %d MB allocated, want under 16 MB", allocated>>20)
	}
	if os.Getenv("HC_WORST_CASE_TIME") == "1" && took > 2*slowdown*time.Second {
		t.Errorf("refused in %v, want under 2 s", took)
	}
}

func TestWalkZip_theZip64FieldOfALocalHeader(t *testing.T) {
	e := fileEntry("a", "1")
	e.zip64Local, e.zip64Central = true, true
	for name, extra := range map[string][]byte{"no padding": nil, "alignment padding after it": bytes.Repeat([]byte{0}, 4000)} {
		e.localExtra = extra
		if err := walkBytes(rawZip{entries: []rawEntry{e}, zip64Directory: true}.bytes(t), 1, 0); err != nil {
			t.Errorf("%s: walkZip() = %v, want the zip accepted", name, err)
		}
	}
	e.localExtra, e.extraBefore = nil, bytes.Repeat([]byte{0}, 100)
	wantAnomaly(t, walkBytes(rawZip{entries: []rawEntry{e}, zip64Directory: true}.bytes(t), 1, 0))
}

func TestWalkZip_theDeadline(t *testing.T) {
	entries := make([]rawEntry, 5000)
	for i := range entries {
		entries[i] = folderEntry(fmt.Sprintf("d%05d/", i))
	}
	b := rawZip{entries: entries, zip64Directory: true}.bytes(t)
	prev := zipWalkDeadline
	zipWalkDeadline = time.Nanosecond
	t.Cleanup(func() { zipWalkDeadline = prev })
	err := walkBytes(b, len(entries), len(entries))
	wantAnomaly(t, err)
	if !errors.Is(err, errZipStructure) || errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("walkZip() = %v, want an anomaly that is not a retry", err)
	}
	t.Run("the context of the caller is not an anomaly", func(t *testing.T) {
		zipWalkDeadline = prev
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := walkZip(ctx, bytes.NewReader(b), int64(len(b)), len(entries), len(entries))
		if !errors.Is(err, context.Canceled) || errors.Is(err, errZipStructure) {
			t.Errorf("walkZip() = %v, want the cancellation of the caller", err)
		}
	})
}

// The time depends on the machine: it is logged, and asserted only with
// HC_WORST_CASE_TIME=1.
func TestWalkZip_aMillionFolders(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a zip of a million folders")
	}
	const n = 1_000_000
	scaleWalkDeadline(t)
	entries := make([]rawEntry, n)
	for i := range entries {
		entries[i] = folderEntry(fmt.Sprintf("folder-%07d/", i))
	}
	b := rawZip{entries: entries, zip64Directory: true}.bytes(t)
	start := time.Now()
	if err := walkBytes(b, n, n); err != nil {
		t.Fatalf("walkZip() = %v", err)
	}
	took := time.Since(start)
	t.Logf("%d folder entries (%d MB): %v", n, len(b)>>20, took)
	if os.Getenv("HC_WORST_CASE_TIME") == "1" && took > 2*slowdown*time.Second {
		t.Errorf("the walk took %v, the target is 2 s", took)
	}
}

func benchmarkWalk(b *testing.B, z rawZip) {
	b.Helper()
	data := z.bytes(b)
	n := countListed(z.entries)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for b.Loop() {
		if err := walkBytes(data, n, 0); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkWalkZip_folders(b *testing.B) {
	entries := make([]rawEntry, 10_000)
	for i := range entries {
		entries[i] = folderEntry(fmt.Sprintf("folder-%05d/", i))
	}
	data := rawZip{entries: entries}.bytes(b)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for b.Loop() {
		if err := walkBytes(data, len(entries), len(entries)); err != nil {
			b.Fatal(err)
		}
	}
}

// The costlier shapes: descriptors, ZIP64, a signing block, a directory in another
// order, and many unlisted zero records.
func BenchmarkWalkZip_files(b *testing.B) {
	entries := make([]rawEntry, 10_000)
	for i := range entries {
		entries[i] = fileEntry(fmt.Sprintf("dir/file-%05d.txt", i), "0123456789")
	}
	b.Run("plain", func(b *testing.B) { benchmarkWalk(b, rawZip{entries: entries}) })
	b.Run("permuted", func(b *testing.B) { benchmarkWalk(b, rawZip{entries: entries, permuteCentral: true}) })
	b.Run("descriptors", func(b *testing.B) {
		d := slices.Clone(entries)
		for i := range d {
			d[i].descriptor, d[i].localComp, d[i].localUncomp = 4, 0, 0
		}
		benchmarkWalk(b, rawZip{entries: d})
	})
	b.Run("ZIP64", func(b *testing.B) {
		d := slices.Clone(entries)
		for i := range d {
			d[i].zip64Local, d[i].zip64Central = true, true
		}
		benchmarkWalk(b, rawZip{entries: d, zip64Directory: true})
	})
	b.Run("signing block", func(b *testing.B) {
		benchmarkWalk(b, rawZip{entries: entries, signingBlock: true})
	})
	b.Run("zero records", func(b *testing.B) {
		d := make([]rawEntry, 0, 2*len(entries))
		for _, e := range entries {
			d = append(d, zeroRecord("", nil), e)
		}
		benchmarkWalk(b, rawZip{entries: d})
	})
}

type failingReaderAt struct{ err error }

func (f failingReaderAt) ReadAt([]byte, int64) (int, error) { return 0, f.err }

// A file that cannot be read is a failure to retry, never an anomaly: the walk
// only refuses what it saw.
func TestWalkZip_aFailureToReadIsNotAnAnomaly(t *testing.T) {
	boom := errors.New("input/output error")
	if _, err := walkZip(context.Background(), failingReaderAt{boom}, 1<<20, 1, 0); !errors.Is(err, boom) || errors.Is(err, errZipStructure) {
		t.Errorf("walkZip() = %v, want the failure itself", err)
	}
	if _, err := walkZipFolders(context.Background(), t.TempDir()+"/missing.zip", 1, 0); err == nil || errors.Is(err, errZipStructure) {
		t.Errorf("walkZipFolders() = %v, want an I/O error", err)
	}
}

// segment is a run of a virtual file: bytes, or zeros.
type segment struct {
	data  []byte
	zeros int64
}

// sparseFile is a ReaderAt over segments, so that a file of tens of megabytes of
// zeros costs nothing.
type sparseFile []segment

func (s sparseFile) size() (n int64) {
	for _, seg := range s {
		n += int64(len(seg.data)) + seg.zeros
	}
	return n
}

func (s sparseFile) ReadAt(p []byte, off int64) (int, error) {
	n := 0
	pos := int64(0)
	for _, seg := range s {
		length := int64(len(seg.data)) + seg.zeros
		for n < len(p) && off+int64(n) >= pos && off+int64(n) < pos+length {
			at := off + int64(n) - pos
			if at < int64(len(seg.data)) {
				n += copy(p[n:], seg.data[at:])
			} else {
				p[n] = 0
				n++
			}
		}
		pos += length
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// signedZip is a zip of one file whose directory is preceded by space of the given
// size: a record that starts where the space does, followed by zeros.
func signedZip(t *testing.T, blockSize uint64) sparseFile {
	t.Helper()
	whole := rawZip{entries: []rawEntry{fileEntry("a.txt", "0123456789")}}.bytes(t)
	cdAt := bytes.LastIndex(whole, []byte("PK\x01\x02"))
	entries, directory := whole[:cdAt], bytes.Clone(whole[cdAt:])
	block := blockSize + 8
	le.LittleEndian.PutUint32(directory[len(directory)-zipEOCDLen+16:], u32(uint64(max(cdAt, 0))+block))
	head := put64(nil, blockSize)
	tail := put64(nil, blockSize)
	tail = append(tail, zipSigBlockMagic...)
	zeros := int64(min(block, math.MaxInt64)) - int64(len(head)) - int64(len(tail))
	return sparseFile{{data: append(bytes.Clone(entries), head...)}, {zeros: zeros}, {data: append(tail, directory...)}}
}

// A block of one valid pair that fills 2 MiB: only the bound refuses it.
func TestWalkZip_aSigningBlockOverTheBound(t *testing.T) {
	whole := rawZip{entries: []rawEntry{fileEntry("a.txt", "0123456789")}}.bytes(t)
	cdAt := bytes.LastIndex(whole, []byte("PK\x01\x02"))
	entries, directory := whole[:cdAt], bytes.Clone(whole[cdAt:])
	size := uint64(zipMaxSigBlock + 1<<20)
	le.LittleEndian.PutUint32(directory[len(directory)-zipEOCDLen+16:], u32(uint64(max(cdAt, 0))+size+8))
	pairLen := size - 24 - 8
	head := put64(nil, size)
	head = put64(head, pairLen)
	head = put32(head, 0x7109871a)
	tail := put64(nil, size)
	tail = append(tail, zipSigBlockMagic...)
	zeros := int64(min(size, math.MaxInt64)) + 8 - int64(len(head)) - int64(len(tail))
	file := sparseFile{{data: append(bytes.Clone(entries), head...)}, {zeros: zeros}, {data: append(tail, directory...)}}
	_, err := walkZip(context.Background(), file, file.size(), 1, 0)
	wantAnomaly(t, err)
}

// The APK Signing Block is bounded and parsed: a block whose first dword is the
// signature of a local record, and which holds a record up to the directory, is a
// record that readers see and 7-Zip does not.
func TestWalkZip_aForgedSigningBlock(t *testing.T) {
	tests := []struct {
		name string
		size uint64
	}{
		{"the size is a local signature, 67 MB of record", uint64(zipLocalSignature)},
		{"zeros between the sizes: no pair", 1 << 20},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := signedZip(t, tt.size)
			_, err := walkZip(context.Background(), file, file.size(), 1, 0)
			wantAnomaly(t, err)
		})
	}
}

// The shapes of a forged signing block, each refused; the honest one is accepted.
func TestWalkZip_aSigningBlockThatIsNotWhatItSays(t *testing.T) {
	good := rawZip{entries: []rawEntry{fileEntry("a.txt", "1")}, signingBlock: true}.bytes(t)
	if err := walkBytes(good, 1, 0); err != nil {
		t.Fatalf("walkZip() = %v, want the honest block accepted", err)
	}
	magicAt := bytes.LastIndex(good, []byte(zipSigBlockMagic))
	trailing := magicAt - 8
	pair := trailing - 16
	head := pair - 8
	patch := func(f func(b []byte)) []byte { b := bytes.Clone(good); f(b); return b }
	tests := map[string][]byte{
		"the trailing size is not the extent":  patch(func(b []byte) { b[trailing]++ }),
		"the leading size is not the trailing": patch(func(b []byte) { b[head]++ }),
		"a pair that runs past the block":      patch(func(b []byte) { b[pair+1] = 0xff }),
		"a pair shorter than its id":           patch(func(b []byte) { b[pair] = 2 }),
		"a pair that leaves bytes over":        patch(func(b []byte) { b[pair] = 4 }),
		"a local signature inside the block":   patch(func(b []byte) { copy(b[pair+12:], "PK\x03\x04") }),
		"a magic that is not the one":          patch(func(b []byte) { b[magicAt]++ }),
	}
	for name, b := range tests {
		t.Run(name, func(t *testing.T) { wantAnomaly(t, walkBytes(b, 1, 0)) })
	}
}

// A zip stored in a zip (a fat jar, a war): its end of directory is data, and no
// reader takes it for the end of the outer one.
func TestWalkZip_aZipStoredInAZip(t *testing.T) {
	inner := rawZip{entries: []rawEntry{fileEntry("Inner.class", "CAFEBABE"), folderEntry("lib/")}}.bytes(t)
	innerEntry := func() rawEntry { return fileEntry("BOOT-INF/lib/inner.jar", string(inner)) }
	for name, entries := range map[string][]rawEntry{
		"first": {innerEntry(), fileEntry("META-INF/MANIFEST.MF", "x")},
		"last":  {fileEntry("META-INF/MANIFEST.MF", "x"), innerEntry()},
		"two":   {innerEntry(), fileEntry("a", "1"), func() rawEntry { e := innerEntry(); e.name = "b.jar"; return e }()},
	} {
		t.Run(name, func(t *testing.T) {
			if err := walkBytes(rawZip{entries: entries}.bytes(t), len(entries), 0); err != nil {
				t.Errorf("walkZip() = %v, want the fat jar accepted", err)
			}
		})
	}
}

// What a streaming reader goes by: the local header must say what the directory
// says.
func TestWalkZip_theLocalHeaderIsTheOneOfTheDirectory(t *testing.T) {
	forged := fileEntry("a.bin", "0123456789")
	forged.localComp, forged.localUncomp = 0, 0
	renamed := fileEntry("a.txt", "0123456789")
	renamed.centralName = "../a.txt"
	sameLength := fileEntry("a.txt", "0123456789")
	sameLength.centralName = "b.txt"
	zip64 := fileEntry("a.bin", "0123456789")
	zip64.zip64Local, zip64.zip64Central = true, true
	zip64.localComp = 9
	tests := []struct {
		name    string
		entry   rawEntry
		wantErr bool
	}{
		{"the same", fileEntry("a.txt", "0123456789"), false},
		{"local sizes of 0 for a file of 10 bytes, no descriptor", forged, true},
		{"another name of another length", renamed, true},
		{"another name of the same length", sameLength, true},
		{"ZIP64 sizes that differ", zip64, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := walkBytes(rawZip{entries: []rawEntry{tt.entry}, zip64Directory: tt.entry.zip64Central}.bytes(t), 1, 0)
			if tt.wantErr {
				wantAnomaly(t, err)
			} else if err != nil {
				t.Errorf("walkZip() = %v", err)
			}
		})
	}
}

// A directory in another order than the file: every header is a read of its own,
// with no block of copying per entry. The time depends on the machine: it is
// logged, and asserted only with HC_WORST_CASE_TIME=1.
func TestWalkZip_aPermutedDirectory(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a zip of a million entries")
	}
	const n = 1_000_000
	scaleWalkDeadline(t)
	entries := make([]rawEntry, n)
	for i := range entries {
		entries[i] = folderEntry(fmt.Sprintf("folder-%07d/", i))
	}
	b := rawZip{entries: entries, zip64Directory: true, permuteCentral: true}.bytes(t)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	start := time.Now()
	err := walkBytes(b, n, n)
	took := time.Since(start)
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatalf("walkZip() = %v", err)
	}
	allocated := after.TotalAlloc - before.TotalAlloc
	t.Logf("%d entries in another order (%d MB): %v, %d MB allocated", n, len(b)>>20, took, allocated>>20)
	if allocated > 16<<20 {
		t.Errorf("walked with %d MB allocated, want under 16 MB", allocated>>20)
	}
	if os.Getenv("HC_WORST_CASE_TIME") == "1" && took > 2*slowdown*time.Second {
		t.Errorf("walked in %v, want under 2 s", took)
	}
}

func TestWalkZip_aControlCharacterInANameIsNoted(t *testing.T) {
	b := rawZip{entries: []rawEntry{fileEntry("a\nb.txt", "x"), fileEntry("c.txt", "y")}}.bytes(t)
	found, err := walkZip(context.Background(), bytes.NewReader(b), int64(len(b)), 2, 0)
	if err != nil || !found.controlNames {
		t.Errorf("walkZip() = %+v, %v, want no anomaly and the name noted", found, err)
	}
	b = rawZip{entries: []rawEntry{fileEntry("a.txt", "x")}}.bytes(t)
	if found, err = walkZip(context.Background(), bytes.NewReader(b), int64(len(b)), 1, 0); err != nil || found.controlNames {
		t.Errorf("walkZip() = %+v, %v, want nothing noted", found, err)
	}
}

// zeroRecord is a local record that the directory does not list, as an APK signer
// leaves: stored, sizes 0, a name and an extra field of zero bytes.
func zeroRecord(name string, extra []byte) rawEntry {
	return rawEntry{name: name, unlisted: true, localExtra: extra}
}

func stampRecord(size int, name string) rawEntry {
	data := bytes.Repeat([]byte{0xAB}, size)
	n := uint64(len(data))
	return rawEntry{name: name, unlisted: true, data: data, localComp: n, localUncomp: n}
}

// What amendment 9 lets by, each with the mutation that is refused.
func TestWalkZip_unlistedRecordsThatCarryNothing(t *testing.T) {
	plain := fileEntry("a.txt", "0123456789")
	zero2 := string(make([]byte, 2))
	tests := []struct {
		name    string
		entries []rawEntry
		wantErr bool
	}{
		{"a zero record at offset 0", []rawEntry{zeroRecord("", nil), plain}, false},
		{"a zero record with a zero name and extra", []rawEntry{zeroRecord(zero2, make([]byte, 4)), plain}, false},
		{"a zero record between entries", []rawEntry{plain, zeroRecord("", nil), fileEntry("b.txt", "bb")}, false},
		{"a zero record after the last entry", []rawEntry{plain, zeroRecord("", make([]byte, 6))}, false},
		{"two zero records", []rawEntry{zeroRecord("", nil), zeroRecord("", nil), plain}, false},
		{"a zero record with a name byte that is not zero", []rawEntry{zeroRecord("a\x00", nil), plain}, true},
		{"a zero record with an extra byte that is not zero", []rawEntry{zeroRecord("", []byte{0, 0, 1}), plain}, true},
		{"a zero record that is deflated", []rawEntry{func() rawEntry { r := zeroRecord("", nil); r.method = zipMethodDeflate; return r }(), plain}, true},
		{"a zero record with a descriptor flag", []rawEntry{func() rawEntry { r := zeroRecord("", nil); r.flags = zipFlagDescriptor; return r }(), plain}, true},
		{"a zero record that is encrypted", []rawEntry{func() rawEntry { r := zeroRecord("", nil); r.flags = zipFlagEncrypted; return r }(), plain}, true},
		{"a record of size 1", []rawEntry{func() rawEntry {
			r := zeroRecord("", nil)
			r.data, r.localComp, r.localUncomp = []byte{0}, 1, 1
			return r
		}(), plain}, true},
		{"a record of 0 bytes whose sizes differ", []rawEntry{func() rawEntry { r := zeroRecord("", nil); r.localUncomp = 1; return r }(), plain}, true},
		{"one stamp", []rawEntry{plain, stampRecord(32, stampName)}, false},
		{"a stamp at offset 0", []rawEntry{stampRecord(32, stampName), plain}, false},
		{"a stamp with a short extra field", []rawEntry{plain, func() rawEntry { r := stampRecord(32, stampName); r.localExtra = make([]byte, 8); return r }()}, false},
		{"two stamps", []rawEntry{plain, stampRecord(32, stampName), stampRecord(32, stampName)}, true},
		{"a stamp of 33 bytes", []rawEntry{plain, stampRecord(33, stampName)}, true},
		{"a stamp of 31 bytes", []rawEntry{plain, stampRecord(31, stampName)}, true},
		{"a stamp with another name", []rawEntry{plain, stampRecord(32, "stamp-cert-sha257")}, true},
		{"a stamp with a long extra field", []rawEntry{plain, func() rawEntry { r := stampRecord(32, stampName); r.localExtra = make([]byte, 9); return r }()}, true},
		{"a deflated stamp", []rawEntry{plain, func() rawEntry { r := stampRecord(32, stampName); r.method = zipMethodDeflate; return r }()}, true},
		{"a stamp with a descriptor flag", []rawEntry{plain, func() rawEntry { r := stampRecord(32, stampName); r.flags = zipFlagDescriptor; return r }()}, true},
		{"a stamp that is encrypted", []rawEntry{plain, func() rawEntry { r := stampRecord(32, stampName); r.flags = zipFlagEncrypted; return r }()}, true},
		{"an unlisted record of a file", []rawEntry{plain, func() rawEntry { r := fileEntry("evil.exe", "MZ"); r.unlisted = true; return r }()}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := walkBytes(rawZip{entries: tt.entries}.bytes(t), countListed(tt.entries), 0)
			if tt.wantErr {
				wantAnomaly(t, err)
			} else if err != nil {
				t.Errorf("walkZip() = %v, want the zip accepted", err)
			}
		})
	}
}

// countListed is what 7-Zip lists of the entries: those of the directory, and when
// the first record is not one of them, one more entry for each record that the
// directory does not list.
func countListed(entries []rawEntry) int {
	listed, unlisted := 0, 0
	for _, e := range entries {
		if e.unlisted {
			unlisted++
		} else {
			listed++
		}
	}
	if len(entries) > 0 && entries[0].unlisted {
		return listed + unlisted
	}
	return listed
}

// The entries 7-Zip lists beyond those of the directory are the records the
// directory does not list, all of them when one comes first and none otherwise
// (counted with 7-Zip 25.01). Any other count is a listing that is not the
// directory.
func TestWalkZip_theExtraEntriesAreTheUnlistedRecords(t *testing.T) {
	a, b := fileEntry("a.txt", "0123456789"), fileEntry("b.txt", "bb")
	zero := zeroRecord("", nil)
	tests := []struct {
		name    string
		entries []rawEntry
		listed  int
		wantErr bool
	}{
		{"nothing unlisted", []rawEntry{a, b}, 2, false},
		{"a prefix", []rawEntry{zero, a, b}, 3, false},
		{"a prefix and a record between", []rawEntry{zero, a, zero, b}, 4, false},
		{"a prefix and two records between", []rawEntry{zero, a, zero, zero, b}, 5, false},
		{"a prefix and a last record", []rawEntry{zero, a, b, zero}, 4, false},
		{"a prefix and a stamp", []rawEntry{zero, a, b, stampRecord(32, stampName)}, 4, false},
		{"a record between and none first", []rawEntry{a, zero, b}, 2, false},
		{"two records between and none first", []rawEntry{a, zero, zero, b}, 2, false},
		{"a last record and none first", []rawEntry{a, b, zero}, 2, false},
		{"a record between and none first, one more listed", []rawEntry{a, zero, b}, 3, true},
		{"a last record and none first, one more listed", []rawEntry{a, b, zero}, 3, true},
		{"one more listed with no record at all", []rawEntry{a, b}, 3, true},
		{"two more listed with no record at all", []rawEntry{a, b}, 4, true},
		{"one more listed than the prefix explains", []rawEntry{zero, a, zero, b}, 3, true},
		{"one fewer listed than the records explain", []rawEntry{zero, a, zero, b}, 5, true},
		{"fewer listed than the directory holds", []rawEntry{a, b}, 1, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := walkBytes(rawZip{entries: tt.entries}.bytes(t), tt.listed, 0)
			if tt.wantErr {
				wantAnomaly(t, err)
			} else if err != nil {
				t.Errorf("walkZip() = %v, want the zip accepted", err)
			}
		})
	}
}

// The entries of the directory fill it exactly: bytes left in it are room for what
// the listing does not show, and a directory cut short is read past its end.
func TestWalkZip_theEntriesFillTheDirectory(t *testing.T) {
	whole := rawZip{entries: []rawEntry{fileEntry("a.txt", "0123456789"), fileEntry("b.txt", "bb")}}.bytes(t)
	if err := walkBytes(whole, 2, 0); err != nil {
		t.Fatalf("walkZip() = %v, want the zip accepted", err)
	}
	at := len(whole) - zipEOCDLen + 12
	size := le.LittleEndian.Uint32(whole[at:])
	for _, patched := range []uint32{size + 1, size - 1} {
		b := bytes.Clone(whole)
		le.LittleEndian.PutUint32(b[at:], patched)
		wantAnomaly(t, walkBytes(b, 2, 0))
	}
}

// Only the ASCII letters fold, and the length is the same.
func TestWalkZip_localAndCentralNames(t *testing.T) {
	tests := []struct {
		name, local, central string
		wantErr              bool
	}{
		{"the same", "word/a.xml", "word/a.xml", false},
		{"ASCII case only", "customXML/item1.xml", "customXml/item1.xml", false},
		{"EVIL and evil", "EVIL", "evil", false},
		{"other letters", "evil", "abcd", true},
		{"another length", "evil", "evils", true},
		{"a non-ASCII case pair", "éa.txt", "Éa.txt", true},
		{"a byte above ASCII that would fold in Unicode", "K", "K", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := fileEntry(tt.local, "0123456789")
			e.centralName = tt.central
			err := walkBytes(rawZip{entries: []rawEntry{e}}.bytes(t), 1, 0)
			if tt.wantErr {
				wantAnomaly(t, err)
			} else if err != nil {
				t.Errorf("walkZip() = %v", err)
			}
		})
	}
}

// What the local header says of the method and the encryption is what the directory
// says, for every entry.
func TestWalkZip_localMethodAndEncryptionOfAFile(t *testing.T) {
	f := fileEntry("a.bin", "0123456789")
	f.centralMethod = new(uint16(zipMethodDeflate))
	wantAnomaly(t, walkBytes(rawZip{entries: []rawEntry{f}}.bytes(t), 1, 0))
	g := fileEntry("a.bin", "0123456789")
	g.flags = zipFlagEncrypted
	b := rawZip{entries: []rawEntry{g}}.bytes(t)
	i := bytes.LastIndex(b, []byte("PK\x01\x02"))
	b[i+8] = 0 // the directory says the entry is not encrypted
	wantAnomaly(t, walkBytes(b, 1, 0))
}

// A decoy end of directory in the comment followed by one byte: the last signature
// is not the end of the file, and the real one is no longer the one that counts.
func TestWalkZip_aDecoyFollowedByAByte(t *testing.T) {
	good := rawZip{entries: []rawEntry{fileEntry("a", "1"), folderEntry("d/")}}
	if err := walkBytes(good.bytes(t), 2, 1); err != nil {
		t.Fatalf("walkZip() = %v, want the zip accepted", err)
	}
	good.decoy = true
	b := append(good.bytes(t), 'X')
	// the comment of the real record now ends one byte before the file does
	i := bytes.LastIndex(b[:len(b)-1-zipEOCDLen-1], []byte("PK\x05\x06"))
	le.LittleEndian.PutUint16(b[i+20:], le.LittleEndian.Uint16(b[i+20:])+1)
	wantAnomaly(t, walkBytes(b, 2, 1))
	wantAnomaly(t, walkBytes(append(rawZip{entries: []rawEntry{fileEntry("a", "1")}}.bytes(t), 'X'), 1, 0))
}

func TestWalkZip_aSigningBlockOfOneMiBAndOne(t *testing.T) {
	whole := rawZip{entries: []rawEntry{fileEntry("a.txt", "0123456789")}}.bytes(t)
	cdAt := bytes.LastIndex(whole, []byte("PK\x01\x02"))
	entries, directory := whole[:cdAt], bytes.Clone(whole[cdAt:])
	for size, wantErr := range map[uint64]bool{zipMaxSigBlock: false, zipMaxSigBlock + 1: true} {
		d := bytes.Clone(directory)
		le.LittleEndian.PutUint32(d[len(d)-zipEOCDLen+16:], u32(uint64(max(len(entries), 0))+size+8))
		head := put64(nil, size)
		head = put64(head, size-24-8)
		head = put32(head, 0x7109871a)
		tail := put64(nil, size)
		tail = append(tail, zipSigBlockMagic...)
		zeros := int64(min(size, math.MaxInt64)) + 8 - int64(len(head)) - int64(len(tail))
		file := sparseFile{{data: append(bytes.Clone(entries), head...)}, {zeros: zeros}, {data: append(tail, d...)}}
		_, err := walkZip(context.Background(), file, file.size(), 1, 0)
		if wantErr {
			wantAnomaly(t, err)
		} else if err != nil {
			t.Errorf("a block of %d bytes: walkZip() = %v, want it accepted", size, err)
		}
	}
}

// A record skipped while a candidate end of an entry is tried counts for nothing
// when that candidate is refused: neither the count of records nor the one stamp
// allowed carries over to the candidate that holds.
func TestWalkZip_aRefusedCandidateEndLeavesNoTrace(t *testing.T) {
	hdr := make([]byte, zipLocalLen, zipLocalLen+len(stampName)+stampSize)
	le.LittleEndian.PutUint32(hdr, zipLocalSignature)
	le.LittleEndian.PutUint32(hdr[18:], stampSize)
	le.LittleEndian.PutUint32(hdr[22:], stampSize)
	le.LittleEndian.PutUint16(hdr[26:], uint16(len(stampName)))
	stamp := append(append(hdr, stampName...), make([]byte, stampSize)...)
	const start, first = 0, 10
	data := append(append(make([]byte, first), stamp...), "XXXXX"...)
	second := uint64(len(data))
	w := &zipWalk{r: bytes.NewReader(data), usize: second, offsets: []uint64{start}, cdOff: second}
	w.window = &windowReader{r: w.r, buf: make([]byte, zipWindow)}
	if err := w.contiguous(context.Background(), start, []uint64{first, second}); err != nil {
		t.Fatalf("contiguous() = %v, want the second candidate to hold", err)
	}
	if w.skipped != 0 || w.stamped {
		t.Errorf("skipped %d records and stamped %t, want no trace of the refused candidate", w.skipped, w.stamped)
	}
}

// scaleWalkDeadline gives the walk of a test that builds a million entries the time
// the race detector and a loaded machine take: the deadline of the production is
// not what these tests measure.
func scaleWalkDeadline(t *testing.T) {
	t.Helper()
	prev := zipWalkDeadline
	zipWalkDeadline = slowdown * prev
	t.Cleanup(func() { zipWalkDeadline = prev })
}
