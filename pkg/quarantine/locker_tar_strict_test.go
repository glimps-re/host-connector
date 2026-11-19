package quarantine

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"testing"
	"time"
)

type tarEntrySpec struct {
	name     string
	typeflag byte
	data     []byte
}

func buildTar(t *testing.T, entries []tarEntrySpec) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Typeflag: e.typeflag, Size: int64(len(e.data)), Mode: 0o600, ModTime: time.Unix(0, 0)}
		if e.typeflag == tar.TypeSymlink {
			hdr.Linkname = "/etc/passwd"
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(e.data); err != nil && hdr.Size != 0 {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestTarLocker_StrictLayout(t *testing.T) {
	var valid bytes.Buffer
	l := tarLocker{Password: "infected"}
	info := &fakeFileInfo{name: "x", size: 5, mode: 0o600, modTime: time.Now()}
	if err := l.LockFile("/tmp/x", bytes.NewReader([]byte("hello")), info, "malware: x", &valid); err != nil {
		t.Fatal(err)
	}
	if _, err := l.UnlockFile(bytes.NewReader(valid.Bytes()), int64(valid.Len()), io.Discard); err != nil {
		t.Fatalf("UnlockFile() on a valid container error = %v", err)
	}

	idx := []byte(`{"filepath":"/tmp/x","reason":"r"}`)
	payload := bytes.Repeat([]byte("x"), 64)
	tests := []struct {
		name    string
		entries []tarEntrySpec
		wantErr error
	}{
		{"duplicate index", []tarEntrySpec{{"index", tar.TypeReg, idx}, {"index", tar.TypeReg, idx}, {"file", tar.TypeReg, payload}}, errTarUnexpectedEntry},
		{"file before index", []tarEntrySpec{{"file", tar.TypeReg, payload}, {"index", tar.TypeReg, idx}}, errTarUnexpectedEntry},
		{"extra entry", []tarEntrySpec{{"index", tar.TypeReg, idx}, {"file", tar.TypeReg, payload}, {"other", tar.TypeReg, payload}}, errTarUnexpectedEntry},
		{"symlink as file", []tarEntrySpec{{"index", tar.TypeReg, idx}, {"file", tar.TypeSymlink, nil}}, errTarUnexpectedEntry},
		{"index only", []tarEntrySpec{{"index", tar.TypeReg, idx}}, errFileNotFound},
		{"empty", nil, errIndexNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := buildTar(t, tt.entries)
			if _, err := l.UnlockFile(bytes.NewReader(data), int64(len(data)), io.Discard); !errors.Is(err, tt.wantErr) {
				t.Errorf("UnlockFile() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}
