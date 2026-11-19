package quarantine

import (
	"bytes"
	"errors"
	"io"
	"os"
	"testing"
)

func TestLockerRouter_LockFile_AlwaysUsesWrite(t *testing.T) {
	writeCalled := false
	write := &lockerMock{LockFileMock: func(file string, in io.Reader, info os.FileInfo, reason string, out io.Writer) error {
		writeCalled = true
		return nil
	}}
	tarReader := &lockerMock{}
	zipReader := &lockerMock{}
	r := newLockerRouter(write, tarReader, zipReader)

	if err := r.LockFile("f", bytes.NewReader(nil), nil, "r", io.Discard); err != nil {
		t.Fatalf("LockFile() error = %s", err)
	}
	if !writeCalled {
		t.Errorf("LockFile() did not call the router's write locker")
	}
}

func TestLockerRouter_DispatchesByDetectedFormat(t *testing.T) {
	tarCalled, zipCalled := false, false
	tarReader := &lockerMock{
		GetHeaderMock: func(src io.ReaderAt, size int64) (LockEntry, error) {
			tarCalled = true
			return LockEntry{Filepath: "from-tar"}, nil
		},
	}
	zipReader := &lockerMock{
		GetHeaderMock: func(src io.ReaderAt, size int64) (LockEntry, error) {
			zipCalled = true
			return LockEntry{Filepath: "from-zip"}, nil
		},
	}
	r := newLockerRouter(&lockerMock{}, tarReader, zipReader)

	tarMagic := make([]byte, 512)
	copy(tarMagic[257:262], "ustar")
	entry, err := r.GetHeader(bytes.NewReader(tarMagic), int64(len(tarMagic)))
	if err != nil {
		t.Fatalf("GetHeader() on tar content error = %s", err)
	}
	if !tarCalled || zipCalled {
		t.Errorf("GetHeader() on tar content: tarCalled=%v zipCalled=%v, want tarCalled=true zipCalled=false", tarCalled, zipCalled)
	}
	if entry.Filepath != "from-tar" {
		t.Errorf("GetHeader() = %+v, want Filepath=from-tar", entry)
	}

	tarCalled, zipCalled = false, false
	zipMagic := []byte("PK\x03\x04 rest of a fake local file header")
	entry, err = r.GetHeader(bytes.NewReader(zipMagic), int64(len(zipMagic)))
	if err != nil {
		t.Fatalf("GetHeader() on zip content error = %s", err)
	}
	if tarCalled || !zipCalled {
		t.Errorf("GetHeader() on zip content: tarCalled=%v zipCalled=%v, want tarCalled=false zipCalled=true", tarCalled, zipCalled)
	}
	if entry.Filepath != "from-zip" {
		t.Errorf("GetHeader() = %+v, want Filepath=from-zip", entry)
	}
}

func TestLockerRouter_UnknownFormat_TypedError(t *testing.T) {
	r := newLockerRouter(&lockerMock{}, &lockerMock{}, &lockerMock{})
	garbage := bytes.Repeat([]byte{0x00}, 512)

	if _, err := r.GetHeader(bytes.NewReader(garbage), int64(len(garbage))); !errors.Is(err, errUnknownLockFormat) {
		t.Errorf("GetHeader() error = %v, want errUnknownLockFormat", err)
	}
	if _, err := r.UnlockFile(bytes.NewReader(garbage), int64(len(garbage)), io.Discard); !errors.Is(err, errUnknownLockFormat) {
		t.Errorf("UnlockFile() error = %v, want errUnknownLockFormat", err)
	}
}

func TestNewQuarantineLocker_WriteFormatAndReadBoth(t *testing.T) {
	info := &zipFakeFileInfo{size: 5, mode: 0o600}
	tests := []struct {
		name       string
		format     Format
		wantFormat containerFormat
	}{
		{name: "default is tar", format: "", wantFormat: formatTarContainer},
		{name: "tar", format: FormatTar, wantFormat: formatTarContainer},
		{name: "zip", format: FormatZip, wantFormat: formatZipContainer},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			locker, err := newQuarantineLocker("infected", tt.format)
			if err != nil {
				t.Fatalf("newQuarantineLocker() error = %v", err)
			}
			var buf bytes.Buffer
			if err := locker.LockFile("/tmp/x", bytes.NewReader([]byte("hello")), info, "malware: x", &buf); err != nil {
				t.Fatalf("LockFile() error = %s", err)
			}
			data := buf.Bytes()
			got, err := detectFormat(bytes.NewReader(data), int64(len(data)))
			if err != nil {
				t.Fatalf("detectFormat() error = %s", err)
			}
			if got != tt.wantFormat {
				t.Errorf("written format = %v, want %v", got, tt.wantFormat)
			}

			// Both formats stay readable whatever the write format.
			for name, l := range map[string]fileLocker{"tar": &tarLocker{Password: "infected"}, "zip": &zipLocker{Password: "infected"}} {
				var other bytes.Buffer
				if err := l.LockFile("/tmp/y", bytes.NewReader([]byte("world")), info, "malware: y", &other); err != nil {
					t.Fatalf("%s LockFile() error = %s", name, err)
				}
				var out bytes.Buffer
				if _, err := locker.UnlockFile(bytes.NewReader(other.Bytes()), int64(other.Len()), &out); err != nil {
					t.Fatalf("router UnlockFile() on %s container error = %s", name, err)
				}
				if out.String() != "world" {
					t.Errorf("router UnlockFile() on %s content = %q, want world", name, out.String())
				}
			}
		})
	}
}

func TestNewQuarantineLocker_UnknownFormat(t *testing.T) {
	if _, err := newQuarantineLocker("infected", "rar"); !errors.Is(err, ErrUnknownFormat) {
		t.Errorf("newQuarantineLocker() error = %v, want ErrUnknownFormat", err)
	}
}
