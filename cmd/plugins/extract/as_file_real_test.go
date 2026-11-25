//go:build linux

package main

import (
	"archive/zip"
	"bytes"
	le "encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/glimps-re/host-connector/pkg/plugins"
)

// storedZip is a zip of members stored without compression.
func storedZip(t *testing.T, members map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range members {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// clearLocalEncryptionBit clears bit 0 of the flags of every local header: the
// archive then says in its local headers that no member is encrypted.
func clearLocalEncryptionBit(t *testing.T, zipBytes []byte) []byte {
	t.Helper()
	out := bytes.Clone(zipBytes)
	cleared := 0
	for i := 0; i+8 <= len(out); i++ {
		if bytes.Equal(out[i:i+4], []byte("PK\x03\x04")) {
			flags := le.LittleEndian.Uint16(out[i+6:])
			le.LittleEndian.PutUint16(out[i+6:], flags&^1)
			cleared++
		}
	}
	if cleared == 0 {
		t.Fatal("no local header found")
	}
	return out
}

// plainSevenZip is a 7z of one plain member, made by the embedded 7-Zip.
func plainSevenZip(t *testing.T) []byte {
	t.Helper()
	plugin := realPlugin(t)
	dir := t.TempDir()
	src := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(src, []byte("plain member"), 0o600); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(dir, "plain.7z")
	if out, err := runCmd(t.Context(), plugin.sze.sevenZipPath, "a", "-t7z", archive, src); err != nil {
		t.Fatalf("cannot build the archive: %v %s", err, out)
	}
	b, err := os.ReadFile(filepath.Clean(archive))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// stubbedZip is a zip after a stub, with its offsets counted from the start of the
// file as an SFX archive has them.
func stubbedZip(t *testing.T) []byte {
	t.Helper()
	stub := append([]byte("MZ"), make([]byte, 500)...)
	z := storedZip(t, map[string]string{"a.txt": "plain member"})
	eocd := bytes.LastIndex(z, []byte("PK\x05\x06"))
	if eocd < 0 {
		t.Fatal("no end of central directory")
	}
	const stubLen = uint32(502)
	cdOffset := le.LittleEndian.Uint32(z[eocd+16:])
	cd := int(cdOffset)
	for i := cd; i+46 <= eocd; {
		if !bytes.Equal(z[i:i+4], []byte("PK\x01\x02")) {
			t.Fatalf("no central directory record at %d", i)
		}
		le.LittleEndian.PutUint32(z[i+42:], le.LittleEndian.Uint32(z[i+42:])+stubLen)
		i += 46 + int(le.LittleEndian.Uint16(z[i+28:])) + int(le.LittleEndian.Uint16(z[i+30:])) + int(le.LittleEndian.Uint16(z[i+32:]))
	}
	le.LittleEndian.PutUint32(z[eocd+16:], cdOffset+stubLen)
	return append(stub, z...)
}

// A zip behind a stub is listed by 7-Zip as plain, with the stub as an offset: the
// extractor does not see what the stub holds, so the encryption is possible. (An
// executable stub makes the file an executable for the connector before it reaches
// the extractor; the extractor answers for what reaches it.)
func TestExtractFile_aStubInFrontOfTheArchiveLeavesEncryptionPossible(t *testing.T) {
	tests := []struct {
		name    string
		content func(t *testing.T) []byte
	}{
		{name: "a zip after a stub of 502 bytes", content: stubbedZip},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "stub.zip")
			if err := os.WriteFile(path, tt.content(t), 0o600); err != nil {
				t.Fatal(err)
			}
			ex, err := realPlugin(t).ExtractFile(path, t.TempDir(), openLimits)
			if !errors.Is(err, plugins.ErrArchiveAnomaly) && len(ex.Files) == 0 {
				t.Fatalf("ExtractFile() = %+v, %v, want the archive opened", ex, err)
			}
			if err == nil {
				t.Fatal("ExtractFile() succeeded: 7-Zip says nothing of the stub, the archive must be flagged")
			}
			if !errors.Is(err, plugins.ErrEncryptionPossible) {
				t.Errorf("error = %v, want the encryption possible: an archive can hide in the stub", err)
			}
		})
	}
}
