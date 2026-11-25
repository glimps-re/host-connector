//go:build linux

package main

import (
	"archive/zip"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/glimps-re/host-connector/pkg/plugins"
)

var namesOnly = plugins.ExtractLimits{MaxFileSize: 1 << 20, MaxFiles: 100, MaxTotalSize: 1, NamesOnly: true}

func writeBytes(t *testing.T, content []byte) string {
	t.Helper()
	return writeNamed(t, "sample.zip", content)
}

func writeNamed(t *testing.T, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// zipcryptoWith is the encrypted zip of the fixtures, with plain entries after its
// own: the names are the ones of the listing when it is honest.
func zipcryptoWith(t *testing.T, plain ...string) []byte {
	t.Helper()
	enc := archiveFixture(t, "enc_zipcrypto.zip")
	zr, err := zip.NewReader(bytes.NewReader(enc), int64(len(enc)))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	if err = zw.Copy(zr.File[0]); err != nil {
		t.Fatal(err)
	}
	for _, name := range plain {
		w, cerr := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
		if cerr != nil {
			t.Fatal(cerr)
		}
		if _, err = w.Write([]byte("0123456789")); err != nil {
			t.Fatal(err)
		}
	}
	if err = zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func plainZipWith(t *testing.T, names ...string) []byte {
	t.Helper()
	entries := make([]rawEntry, len(names))
	for i, n := range names {
		entries[i] = fileEntry(n, "0123456789")
	}
	return rawZip{entries: entries}.bytes(t)
}

func TestRealSevenZip_namesOnlyGivesTheNamesOfTheFiles(t *testing.T) {
	over := namesOnly
	over.MaxFiles = 1
	plain := writeRawZip(t, rawZip{entries: []rawEntry{fileEntry("a.txt", "1"), fileEntry("docs/b.exe", "22"), folderEntry("docs/")}})
	empty := writeRawZip(t, rawZip{entries: []rawEntry{folderEntry("docs/")}})
	tests := []struct {
		name      string
		path      string
		limits    plugins.ExtractLimits
		wantNames []string
		wantNil   bool
	}{
		{"the files of the listing, not the folders", plain, namesOnly, []string{"a.txt", "docs/b.exe"}, false},
		{"an archive of folders only gives an empty list, not an unknown one", empty, namesOnly, []string{}, false},
		{"a listing over MaxFiles gives no name", plain, over, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := realPlugin(t).ExtractFile(tt.path, t.TempDir(), tt.limits)
			if err != nil {
				t.Fatalf("ExtractFile() error = %v", err)
			}
			if tt.wantNil != (got.Names == nil) {
				t.Fatalf("Names = %#v, want nil %t", got.Names, tt.wantNil)
			}
			names := slices.Clone(got.Names)
			slices.Sort(names)
			if !tt.wantNil && !slices.Equal(names, tt.wantNames) {
				t.Errorf("Names = %v, want %v", names, tt.wantNames)
			}
		})
	}
}

// Nothing is tested nor decompressed: the names of a zip that 7-Zip finds corrupt
// at the test are given, and an encrypted archive with readable headers gives them.
func TestRealSevenZip_namesOnlyDoesNotTestTheMembers(t *testing.T) {
	corrupt := rawZip{entries: []rawEntry{func() rawEntry { f := fileEntry("a.txt", "abc"); f.crc ^= 1; return f }()}}.bytes(t)
	got, err := realPlugin(t).ExtractFile(writeBytes(t, corrupt), t.TempDir(), namesOnly)
	if err != nil || !slices.Equal(got.Names, []string{"a.txt"}) {
		t.Errorf("a wrong checksum: names %v, error %v, want the name and no error", got.Names, err)
	}
	got, err = realPlugin(t).ExtractFile(writeBytes(t, zipcryptoWith(t, "ok.txt", "evil.exe")), t.TempDir(), namesOnly)
	if err != nil || got.Names == nil || !slices.Contains(got.Names, "ok.txt") || !slices.Contains(got.Names, "evil.exe") {
		t.Errorf("an encrypted member: names %v, error %v, want the names and no error", got.Names, err)
	}
}

// Whatever is wrong with the archive, the names are not given: nothing proves they
// are the names of everything a reader finds in it.
func TestRealSevenZip_namesOnlyGivesNothingOfAnArchiveThatIsNotPlain(t *testing.T) {
	tail := append(zipcryptoWith(t, "ok.txt"), plainZipWith(t, "evil.exe")...)
	stub := append([]byte("MZ-stub-in-front"), zipcryptoWith(t, "ok.txt")...)
	hidden := rawZip{entries: []rawEntry{func() rawEntry {
		f := fileEntry("a.txt", "1")
		f.slack = plainZipWith(t, "evil.exe")[:40]
		return f
	}()}}.bytes(t)
	tests := []struct {
		name string
		zip  []byte
	}{
		{"encrypted, with an archive appended", tail},
		{"encrypted, with a stub in front", stub},
		{"encrypted, with a name that has a control character", zipcryptoWith(t, "a\nb.txt")},
		{"encrypted, with a member 64 folders deep", zipcryptoWith(t, strings.Repeat("d/", 64)+"evil.exe")},
		{"a record behind a member, which the directory does not list", hidden},
		{"a plain archive with an archive appended", append(plainZipWith(t, "ok.txt"), plainZipWith(t, "evil.exe")...)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := realPlugin(t).ExtractFile(writeBytes(t, tt.zip), t.TempDir(), namesOnly)
			if got.Names != nil {
				t.Errorf("Names = %v (error %v), want none", got.Names, err)
			}
		})
	}
}

// A name with a control character that 7-Zip lists as it is (a carriage return in
// a 7z) is an anomaly of the listing: the names are not given. A line feed is listed
// as an underscore, which the plugin cannot tell from the name (a known limit, in the
// README).
func TestRealSevenZip_namesOnlyGivesNothingWhenTheListingHasAnAnomaly(t *testing.T) {
	got, err := realPlugin(t).ExtractFile(fixture(t, "cr.7z"), t.TempDir(), namesOnly)
	if got.Names != nil {
		t.Errorf("Names = %q (error %v), want none", got.Names, err)
	}
}

// Data in front of a 7z, which only the technical listing reports.
func TestRealSevenZip_namesOnlyGivesNothingOfA7zWithAStub(t *testing.T) {
	sevenZip := plainSevenZip(t)
	got, err := realPlugin(t).ExtractFile(writeNamed(t, "stub.7z", append([]byte("MZ-stub-in-front"), sevenZip...)), t.TempDir(), namesOnly)
	if got.Names != nil {
		t.Errorf("Names = %q (error %v), want none", got.Names, err)
	}
	plain, err := realPlugin(t).ExtractFile(writeNamed(t, "plain.7z", sevenZip), t.TempDir(), namesOnly)
	if err != nil || len(plain.Names) == 0 {
		t.Errorf("without the stub: names %q, error %v, want the names", plain.Names, err)
	}
}

func TestRealSevenZip_namesOnlyOfAnArchiveWithEncryptedHeaders(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enc_headers.7z")
	if err := os.WriteFile(path, archiveFixture(t, "enc_headers.7z"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := realPlugin(t).ExtractFile(path, t.TempDir(), namesOnly)
	if got.Names != nil || !errors.Is(err, plugins.ErrEncrypted) {
		t.Errorf("names %v, error %v, want an ErrEncrypted and no names: the headers need a password", got.Names, err)
	}
}

// CheckOnly no longer gives names: they come from NamesOnly.
func TestRealSevenZip_aCheckGivesNoNames(t *testing.T) {
	check := plugins.ExtractLimits{MaxFileSize: 1 << 20, MaxFiles: 100, MaxTotalSize: 1 << 30, CheckOnly: true}
	got, err := realPlugin(t).ExtractFile(writeRawZip(t, rawZip{entries: []rawEntry{fileEntry("a.txt", "1")}}), t.TempDir(), check)
	if err != nil || got.Names != nil {
		t.Errorf("names %v, error %v, want none", got.Names, err)
	}
}
