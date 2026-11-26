//go:build linux

package main

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/glimps-re/host-connector/pkg/plugins"
)

func writeRawZip(t *testing.T, z rawZip) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "forged.zip")
	if err := os.WriteFile(path, z.bytes(t), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

var plainMember = fileEntry("a.txt", "0123456789")

func isFolderAnomaly(err error) bool {
	return errors.Is(err, plugins.ErrArchiveAnomaly) && errors.Is(err, plugins.ErrEncryptionPossible)
}

func TestRealSevenZip_theHeadersOfAZipAreWalked(t *testing.T) {
	filler := bytes.Repeat([]byte("X"), 100_000)
	withData := func(e rawEntry) rawEntry {
		e.data, e.localComp, e.localUncomp = filler, 100_000, 100_000
		return e
	}
	record := rawZip{entries: []rawEntry{fileEntry("evil.exe", "MZ-hidden")}}.bytes(t)
	record = record[:bytes.LastIndex(record, []byte("PK\x01\x02"))]
	slack := func(e rawEntry) rawEntry { e.slack = record; return e }
	const unixDir = 0x41ED << 16
	tests := []struct {
		name string
		zip  rawZip
		// wantAnomaly says the archive is refused as an anomaly, the encryption possible.
		wantAnomaly bool
		// wantText is a fragment of the error, checked in extraction mode; it implies an anomaly.
		wantText string
	}{
		{name: "honest folders", zip: rawZip{entries: []rawEntry{folderEntry("d/"), plainMember}}},
		{name: "jar folders with a data descriptor", zip: rawZip{entries: []rawEntry{jarFolder("d/"), plainMember}}},
		{name: "a folder deflated on its own", zip: rawZip{entries: []rawEntry{{name: "d/", method: zipMethodDeflate, data: deflateEmptyData, localComp: 2, centralComp: 2}, plainMember}}},
		{name: "files only", zip: rawZip{entries: []rawEntry{plainMember, fileEntry("b.txt", "bb")}}},
		{name: "a name with a line feed, 100 KB behind", zip: rawZip{entries: []rawEntry{plainMember, {name: "n\nl/", data: filler, localComp: 100_000, localUncomp: 100_000}}}, wantAnomaly: true},
		{name: "a backslash folder of the FAT host with 100 KB", zip: rawZip{entries: []rawEntry{plainMember, withData(rawEntry{name: "dir\\", madeBy: zipHostFAT << 8})}}, wantAnomaly: true},
		{name: "a backslash folder of the NTFS host with 100 KB", zip: rawZip{entries: []rawEntry{plainMember, withData(rawEntry{name: "dir\\", madeBy: zipHostNTFS << 8})}}, wantAnomaly: true},
		{name: "an Amiga folder with 100 KB", zip: rawZip{entries: []rawEntry{plainMember, withData(rawEntry{name: "d", madeBy: zipHostAmiga << 8, attrs: 0o40755 << 16})}}, wantAnomaly: true},
		{name: "a Unix folder with 100 KB", zip: rawZip{entries: []rawEntry{plainMember, withData(rawEntry{name: "d", attrs: unixDir})}}, wantAnomaly: true},
		{name: "a deflate folder of 0/0 with a stream behind it", zip: rawZip{entries: []rawEntry{plainMember, {name: "d/", method: zipMethodDeflate, data: flated(t, "payload")}}}, wantAnomaly: true},
		{name: "a descriptor folder whose stream yields data", zip: rawZip{entries: []rawEntry{plainMember, {name: "d/", method: zipMethodDeflate, data: flated(t, "payload"), centralComp: 9, descriptor: 2}}}, wantAnomaly: true},
		{name: "a deflate stream that ends early, a record behind it", zip: rawZip{entries: []rawEntry{plainMember, func() rawEntry {
			d := append(flated(t, "hello"), []byte("PK\x03\x04junkjunkjunk")...)
			return rawEntry{name: "b.txt", method: zipMethodDeflate, data: d, localComp: uint64(len(d)), localUncomp: 5, centralComp: uint64(len(d)), centralUncomp: 5, crc: crc32.ChecksumIEEE([]byte("hello"))}
		}()}}, wantAnomaly: true},
		{name: "a bzip2 folder", zip: rawZip{entries: []rawEntry{plainMember, {name: "d/", method: 12, data: []byte("BZh9"), localComp: 4, centralComp: 4}}}, wantAnomaly: true},
		{name: "a record behind an empty folder", zip: rawZip{entries: []rawEntry{slack(folderEntry("d/")), plainMember}}, wantAnomaly: true},
		{name: "a record behind a file, in a zip with no folder", zip: rawZip{entries: []rawEntry{slack(plainMember), fileEntry("b.txt", "bb")}}, wantAnomaly: true},
		{name: "a record behind the last file", zip: rawZip{entries: []rawEntry{fileEntry("b.txt", "bb"), slack(plainMember)}}, wantAnomaly: true},
		{name: "a folder entry named /", zip: rawZip{entries: []rawEntry{folderEntry("/"), plainMember}}, wantText: "a folder entry has a name no file system takes"},
		{name: "a folder with a component of 300 bytes", zip: rawZip{entries: []rawEntry{folderEntry(strings.Repeat("a", 300) + "/"), plainMember}}, wantText: "a folder entry has a name no file system takes"},
		{name: "a record in the comment that ends the file", zip: rawZip{entries: []rawEntry{folderEntry("d/"), plainMember}, comment: string(eocd(nil, 7, 0, 0, ""))}, wantAnomaly: true},
		{name: "a gap of zeros between entries", zip: rawZip{entries: []rawEntry{func() rawEntry { f := plainMember; f.slack = make([]byte, 2994); return f }(), fileEntry("b.txt", "bb")}}},
		{name: "a gap with one byte that is not zero", zip: rawZip{entries: []rawEntry{func() rawEntry { f := plainMember; f.slack = append(make([]byte, 2994), 1); return f }(), fileEntry("b.txt", "bb")}}, wantAnomaly: true},
		{name: "zeros before a signed APK block", zip: rawZip{entries: []rawEntry{func() rawEntry { f := plainMember; f.slack = make([]byte, 11180); return f }()}, signingBlock: true}},
		{name: "a decoy directory in the comment, a copy of the real one", zip: rawZip{entries: []rawEntry{folderEntry("d/"), plainMember}, decoy: true}, wantAnomaly: true},
		{name: "a fat jar: a zip stored in a zip", zip: rawZip{entries: []rawEntry{fileEntry("inner.jar", string(rawZip{entries: []rawEntry{fileEntry("A.class", "CAFE")}}.bytes(t))), plainMember}}},
		{name: "local sizes that are not the ones of the directory", zip: rawZip{entries: []rawEntry{func() rawEntry { f := fileEntry("a.bin", "0123456789"); f.localComp, f.localUncomp = 0, 0; return f }()}}, wantAnomaly: true},
		{name: "a local name that is not the one of the directory", zip: rawZip{entries: []rawEntry{func() rawEntry { f := fileEntry("a.txt", "0123456789"); f.centralName = "b.txt"; return f }()}}, wantAnomaly: true},
		{name: "an unlisted zero record at offset 0", zip: rawZip{entries: []rawEntry{zeroRecord("", nil), plainMember}}},
		{name: "an unlisted zero record after the last entry", zip: rawZip{entries: []rawEntry{plainMember, zeroRecord("", make([]byte, 4))}}},
		{name: "an unlisted zero record at offset 0 and one between entries", zip: rawZip{entries: []rawEntry{zeroRecord("", nil), plainMember, zeroRecord("", nil), fileEntry("b.txt", "bb")}}},
		{name: "an unlisted zero record at offset 0 and two between entries", zip: rawZip{entries: []rawEntry{zeroRecord("", nil), plainMember, zeroRecord("", nil), zeroRecord("", nil), fileEntry("b.txt", "bb")}}},
		{name: "an unlisted zero record at offset 0 and one after the last entry", zip: rawZip{entries: []rawEntry{zeroRecord("", nil), plainMember, zeroRecord("", nil)}}},
		{name: "several unlisted zero records between entries and none first", zip: rawZip{entries: []rawEntry{plainMember, zeroRecord("", nil), zeroRecord("", nil), fileEntry("b.txt", "bb")}}},
		{name: "one source stamp", zip: rawZip{entries: []rawEntry{plainMember, stampRecord(32, stampName)}}},
		{name: "two source stamps", zip: rawZip{entries: []rawEntry{plainMember, stampRecord(32, stampName), stampRecord(32, stampName)}}, wantAnomaly: true},
		{name: "an unlisted record with a byte that is not zero", zip: rawZip{entries: []rawEntry{plainMember, zeroRecord("a", nil)}}, wantAnomaly: true},
		{name: "a decoy followed by a byte", zip: rawZip{entries: []rawEntry{folderEntry("d/"), plainMember}, decoy: true, trailing: []byte("X")}, wantAnomaly: true},
		{name: "a signed APK", zip: rawZip{entries: []rawEntry{plainMember, fileEntry("classes.dex", "dex")}, signingBlock: true}},
	}
	for _, tt := range tests {
		for mode, limits := range map[string]plugins.ExtractLimits{"extraction": extractionMode, "check only": checkOnlyMode} {
			t.Run(tt.name+"/"+mode, func(t *testing.T) {
				path := writeRawZip(t, tt.zip)
				_, err := realPlugin(t).ExtractFile(path, t.TempDir(), limits)
				refused := tt.wantAnomaly || tt.wantText != ""
				switch {
				case !refused && err != nil:
					t.Errorf("error = %v, want a plain archive", err)
				case refused && !isFolderAnomaly(err):
					t.Errorf("error = %v, want an anomaly with the encryption possible", err)
				case tt.wantText != "" && mode == "extraction" && !strings.Contains(fmt.Sprint(err), tt.wantText):
					t.Errorf("error = %v, want %q", err, tt.wantText)
				}
			})
		}
	}
}

func rawFromFixture(t *testing.T, fixtureName string) rawEntry {
	t.Helper()
	b := archiveFixture(t, fixtureName)
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	f := zr.File[0]
	raw, err := f.OpenRaw()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err = io.Copy(&buf, io.LimitReader(raw, 1<<20)); err != nil {
		t.Fatal(err)
	}
	data := buf.Bytes()
	return rawEntry{
		name: f.Name, method: f.Method, flags: f.Flags, data: data,
		localComp: uint64(len(data)), localUncomp: f.UncompressedSize64,
		centralComp: uint64(len(data)), centralUncomp: f.UncompressedSize64, crc: f.CRC32,
	}
}

// The folders are not part of the password retry: an anomaly found by the walk is
// still there once an encrypted member was opened with the default password.
func TestRealSevenZip_aForgedFolderBesideAMemberOfTheDefaultPasswordIsAnAnomaly(t *testing.T) {
	member := rawFromFixture(t, "known_password.zip")
	forged := rawEntry{name: "d/", data: bytes.Repeat([]byte("X"), 100_000), localComp: 100_000, localUncomp: 100_000}
	run := func(z rawZip) error {
		plugin := realPlugin(t)
		plugin.sze.config = extractorConfig{DefaultPasswords: []string{"infected"}}
		_, err := plugin.ExtractFile(writeRawZip(t, z), t.TempDir(), extractionMode)
		return err
	}
	if err := run(rawZip{entries: []rawEntry{member, {name: "d/"}}}); err != nil {
		t.Fatalf("an honest folder beside the member: error = %v, want a plain archive", err)
	}
	if err := run(rawZip{entries: []rawEntry{member, forged}}); !isFolderAnomaly(err) {
		t.Errorf("a forged folder beside the member: error = %v, want an anomaly with the encryption possible", err)
	}
}

// Folders beside an encrypted member change nothing: the archive is encrypted.
func TestRealSevenZip_honestFoldersBesideAnAESMemberAreStillAnEncryptedArchive(t *testing.T) {
	member := rawFromFixture(t, "enc_aes.zip")
	path := writeRawZip(t, rawZip{entries: []rawEntry{{name: "d/"}, member, jarFolder("e/")}})
	_, err := realPlugin(t).ExtractFile(path, t.TempDir(), extractionMode)
	if !errors.Is(err, plugins.ErrEncrypted) || isFolderAnomaly(err) {
		t.Errorf("error = %v, want ErrEncrypted and no anomaly", err)
	}
}

// Only a zip has a local header that can disagree with its directory: a tar with
// folders is not walked, whatever its number of folders.
func TestRealSevenZip_aTarWithManyFoldersIsNotWalked(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a tar of 300000 folders")
	}
	const n = 300_000
	path := filepath.Join(t.TempDir(), "folders.tar")
	f, err := os.Create(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	bw := bufio.NewWriter(f)
	tw := tar.NewWriter(bw)
	for i := range n {
		if err = tw.WriteHeader(&tar.Header{Name: fmt.Sprintf("d%06d/", i), Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
			t.Fatal(err)
		}
	}
	if err = errors.Join(tw.Close(), bw.Flush(), f.Close()); err != nil {
		t.Fatal(err)
	}
	limits := extractionMode
	limits.MaxFiles = 2 * n
	start := time.Now()
	_, err = realPlugin(t).ExtractFile(path, t.TempDir(), limits)
	t.Logf("a tar of %d folders: %v (error %v)", n, time.Since(start), err)
	if isFolderAnomaly(err) {
		t.Errorf("error = %v, want no anomaly for empty folders", err)
	}
}

// A folder entry of a zip that packs to anything but nothing or to the empty block
// of Deflate is an anomaly, in both modes; so is one in another method.
func TestRealSevenZip_aZipFolderThatPacksToSomethingIsAnAnomaly(t *testing.T) {
	tests := []struct {
		name   string
		folder rawEntry
	}{
		{"deflate, 3 bytes packed", rawEntry{name: "d/", method: zipMethodDeflate, data: bytes.Repeat([]byte{0xAA}, 3), localComp: 3, centralComp: 3}},
		{"deflate, 16 bytes packed", rawEntry{name: "d/", method: zipMethodDeflate, data: bytes.Repeat([]byte{0xAA}, 16), localComp: 16, centralComp: 16}},
		{"store, 2 bytes packed", rawEntry{name: "d/", data: []byte{1, 2}, localComp: 2, centralComp: 2}},
		{"deflate64, the empty block", rawEntry{name: "d/", method: 9, data: deflateEmptyData, localComp: 2, centralComp: 2}},
	}
	for _, tt := range tests {
		for mode, limits := range map[string]plugins.ExtractLimits{"extraction": extractionMode, "check only": checkOnlyMode} {
			t.Run(tt.name+"/"+mode, func(t *testing.T) {
				path := writeRawZip(t, rawZip{entries: []rawEntry{plainMember, tt.folder}})
				if _, err := realPlugin(t).ExtractFile(path, t.TempDir(), limits); err == nil {
					t.Error("error = nil, want a refusal")
				}
			})
		}
	}
}

func TestRealSevenZip_manyFolderEntriesAreOneWalk(t *testing.T) {
	entries := make([]rawEntry, 0, 2001)
	entries = append(entries, plainMember)
	for i := range 2000 {
		entries = append(entries, folderEntry(fmt.Sprintf("folder-%05d/", i)))
	}
	start := time.Now()
	res, err := realPlugin(t).ExtractFile(writeRawZip(t, rawZip{entries: entries}), t.TempDir(), extractionMode)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("2000 folder entries: %v", time.Since(start))
	if len(res.Files) != 1 {
		t.Errorf("files = %v, want the one plain member", res.Files)
	}
}
