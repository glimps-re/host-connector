package quarantine

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"hash/crc32"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/glimps-re/host-connector/internal/zipcrypto"
)

// zipFakeFileInfo is a deterministic os.FileInfo, avoiding a dependency on
// real file ownership/mtime for reproducible test assertions.
type zipFakeFileInfo struct {
	size    int64
	mode    os.FileMode
	modTime time.Time
}

func (f *zipFakeFileInfo) Name() string       { return "ignored" }
func (f *zipFakeFileInfo) Size() int64        { return f.size }
func (f *zipFakeFileInfo) Mode() os.FileMode  { return f.mode }
func (f *zipFakeFileInfo) ModTime() time.Time { return f.modTime }
func (f *zipFakeFileInfo) IsDir() bool        { return false }
func (f *zipFakeFileInfo) Sys() any           { return nil }

func Test_zipLocker_LockFile_Structure(t *testing.T) {
	const (
		password = "infected"
		content  = "malicious payload content, long enough to be interesting"
		reason   = "malware: test.family"
		origPath = "/home/user/Downloads/evil sample.exe"
	)
	info := &zipFakeFileInfo{
		size:    int64(len(content)),
		mode:    0o644,
		modTime: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}

	locker := zipLocker{Password: password}
	var buf bytes.Buffer
	if err := locker.LockFile(origPath, bytes.NewReader([]byte(content)), info, reason, &buf); err != nil {
		t.Fatalf("LockFile() error = %s", err)
	}

	data := buf.Bytes()
	if !bytes.HasPrefix(data, []byte("PK\x03\x04")) {
		t.Errorf("produced file does not start with the ZIP local file header signature")
	}

	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("stdlib zip.NewReader() error = %s", err)
	}
	if len(zr.File) != 2 {
		t.Fatalf("entry count = %d, want 2", len(zr.File))
	}

	index := zr.File[0]
	if index.Name != "index.json" {
		t.Errorf("first entry name = %q, want %q (index must be first)", index.Name, "index.json")
	}
	if index.Flags&0x1 != 0 {
		t.Errorf("index.json Flags&1 = 1, want 0 (must not be encrypted)")
	}
	if index.Method != zip.Store {
		t.Errorf("index.json Method = %d, want %d (Store)", index.Method, zip.Store)
	}
	if index.ReaderVersion != 20 {
		t.Errorf("index.json ReaderVersion = %d, want 20", index.ReaderVersion)
	}

	payload := zr.File[1]
	if payload.Name != "evil sample.exe" {
		t.Errorf("payload entry name = %q, want %q", payload.Name, "evil sample.exe")
	}
	if payload.Flags&0x1 == 0 {
		t.Errorf("payload Flags&1 = 0, want 1 (must be encrypted)")
	}
	if payload.Flags&0x8 == 0 {
		t.Errorf("payload Flags&8 = 0, want 1 (stdlib zip.Writer always sets the data descriptor bit)")
	}
	if payload.Method != 0 {
		t.Errorf("payload Method = %d, want 0 (Store)", payload.Method)
	}
	if payload.CompressedSize64 != payload.UncompressedSize64+12 {
		t.Errorf("payload CompressedSize64 = %d, want UncompressedSize64(%d)+12", payload.CompressedSize64, payload.UncompressedSize64)
	}
	if payload.CRC32 == 0 {
		t.Errorf("payload CRC32 is zero, want the real plaintext checksum")
	}

	// The index must be readable without the password, via plain stdlib
	// zip - proving `quarantine list` needs no password.
	rc, err := index.Open()
	if err != nil {
		t.Fatalf("index.Open() error = %s", err)
	}
	defer func() { _ = rc.Close() }()
	var idx LockIndex
	if err := json.NewDecoder(rc).Decode(&idx); err != nil {
		t.Fatalf("decoding index.json failed: %s", err)
	}
	if idx.Filepath != origPath {
		t.Errorf("index.Filepath = %q, want %q", idx.Filepath, origPath)
	}
	if idx.Reason != reason {
		t.Errorf("index.Reason = %q, want %q", idx.Reason, reason)
	}
	if idx.Entry != "evil sample.exe" {
		t.Errorf("index.Entry = %q, want %q", idx.Entry, "evil sample.exe")
	}
}

func Test_zipLocker_RoundTrip(t *testing.T) {
	const (
		password = "infected"
		content  = "the quick brown fox jumps over the lazy dog, repeated for bulk: " +
			"the quick brown fox jumps over the lazy dog, repeated for bulk"
		reason   = "malware: trojan.test"
		origPath = "/tmp/sample.bin"
	)
	info := &zipFakeFileInfo{size: int64(len(content)), mode: 0o600, modTime: time.Now().Truncate(time.Second)}

	locker := zipLocker{Password: password}
	var buf bytes.Buffer
	if err := locker.LockFile(origPath, bytes.NewReader([]byte(content)), info, reason, &buf); err != nil {
		t.Fatalf("LockFile() error = %s", err)
	}
	data := buf.Bytes()

	entry, err := locker.GetHeader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("GetHeader() error = %s", err)
	}
	if entry.Filepath != origPath || entry.Reason != reason {
		t.Errorf("GetHeader() = %+v, want Filepath=%q Reason=%q", entry, origPath, reason)
	}

	var out bytes.Buffer
	locked, err := locker.UnlockFile(bytes.NewReader(data), int64(len(data)), &out)
	if err != nil {
		t.Fatalf("UnlockFile() error = %s", err)
	}
	if out.String() != content {
		t.Errorf("UnlockFile() content = %q, want %q", out.String(), content)
	}
	if locked.Filepath != origPath || locked.Reason != reason {
		t.Errorf("UnlockFile() LockEntry = %+v, want Filepath=%q Reason=%q", locked.LockEntry, origPath, reason)
	}
	if locked.Size != int64(len(content)) {
		t.Errorf("UnlockFile() Size = %d, want %d", locked.Size, len(content))
	}

	// Wrong password must be rejected before returning any content, via
	// the zipcrypto sentinel propagated unwrapped.
	wrongLocker := zipLocker{Password: "not-the-password"}
	if _, err := wrongLocker.UnlockFile(bytes.NewReader(data), int64(len(data)), io.Discard); !errors.Is(err, zipcrypto.ErrWrongPassword) {
		t.Errorf("UnlockFile() with wrong password error = %v, want zipcrypto.ErrWrongPassword", err)
	}
	// GetHeader never needs the password: the index is cleartext.
	if _, err := wrongLocker.GetHeader(bytes.NewReader(data), int64(len(data))); err != nil {
		t.Errorf("GetHeader() with wrong password unexpectedly failed: %s", err)
	}
}

// Test_SharedRoundTrip_TarAndZip runs the same table of scenarios against
// both lockers, proving format parity whichever container is used,
// LockFile -> UnlockFile/GetHeader recovers the same content and metadata
// (mode is compared via .Perm() since the containers store it differently;
// tar keeps full os.FileMode bits, zip's index only ever restores the
// permission bits).
func Test_SharedRoundTrip_TarAndZip(t *testing.T) {
	type scenario struct {
		name    string
		path    string
		reason  string
		content string
		mode    os.FileMode
	}
	scenarios := []scenario{
		{name: "empty file", path: "/tmp/empty.bin", reason: "malware: unknown", content: "", mode: 0o644},
		{name: "small file", path: "/home/user/a.exe", reason: "malware: trojan.a", content: "hi", mode: 0o600},
		{
			name: "larger file", path: "/var/tmp/big.bin", reason: "malware: worm.b",
			content: string(bytes.Repeat([]byte("0123456789"), 10000)), mode: 0o640,
		},
	}

	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			info := &zipFakeFileInfo{size: int64(len(sc.content)), mode: sc.mode, modTime: time.Now().Truncate(time.Second)}

			for _, locker := range []fileLocker{
				&tarLocker{Password: "infected"},
				&zipLocker{Password: "infected"},
			} {
				var buf bytes.Buffer
				if err := locker.LockFile(sc.path, bytes.NewReader([]byte(sc.content)), info, sc.reason, &buf); err != nil {
					t.Fatalf("%T LockFile() error = %s", locker, err)
				}
				data := buf.Bytes()

				header, err := locker.GetHeader(bytes.NewReader(data), int64(len(data)))
				if err != nil {
					t.Fatalf("%T GetHeader() error = %s", locker, err)
				}
				if header.Filepath != sc.path || header.Reason != sc.reason {
					t.Errorf("%T GetHeader() = %+v, want Filepath=%q Reason=%q", locker, header, sc.path, sc.reason)
				}

				var out bytes.Buffer
				locked, err := locker.UnlockFile(bytes.NewReader(data), int64(len(data)), &out)
				if err != nil {
					t.Fatalf("%T UnlockFile() error = %s", locker, err)
				}
				if out.String() != sc.content {
					t.Errorf("%T UnlockFile() content = %q, want %q", locker, out.String(), sc.content)
				}
				if locked.Mode.Perm() != sc.mode.Perm() {
					t.Errorf("%T UnlockFile() Mode = %v, want %v", locker, locked.Mode.Perm(), sc.mode.Perm())
				}
			}
		})
	}
}

// --- Defensive parsing / rejection tests -----------------------------------

// buildZip is a small test helper assembling an in-memory ZIP file from raw
// entries, bypassing zipLocker.LockFile entirely, so tests can construct
// deliberately malformed containers.
type zipEntrySpec struct {
	name       string
	data       []byte
	method     uint16
	encrypted  bool
	compressed []byte // if set, used verbatim as the raw (already "compressed"/encrypted) bytes instead of data
}

func buildZip(t testing.TB, entries []zipEntrySpec) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		raw := e.data
		if e.compressed != nil {
			raw = e.compressed
		}
		fh := &zip.FileHeader{
			Name:               e.name,
			Method:             e.method,
			Modified:           time.Now(),
			CRC32:              crc32.ChecksumIEEE(e.data),
			CompressedSize64:   uint64(len(raw)),
			UncompressedSize64: uint64(len(e.data)),
			CreatorVersion:     20,
			ReaderVersion:      20,
		}
		if e.encrypted {
			fh.Flags |= 0x1
		}
		w, err := zw.CreateRaw(fh)
		if err != nil {
			t.Fatalf("CreateRaw(%q): %s", e.name, err)
		}
		if _, err := w.Write(raw); err != nil {
			t.Fatalf("Write(%q): %s", e.name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip Close(): %s", err)
	}
	return buf.Bytes()
}

func validIndexBytes(t testing.TB, entryName string) []byte {
	t.Helper()
	b, err := json.Marshal(LockIndex{Version: 1, Filepath: "/tmp/x", Reason: "malware: x", Entry: entryName})
	if err != nil {
		t.Fatalf("marshal index: %s", err)
	}
	return b
}

func TestZipLocker_EncryptedIndex_Rejected(t *testing.T) {
	idx := validIndexBytes(t, "payload.bin")
	data := buildZip(t, []zipEntrySpec{
		{name: "index.json", data: idx, method: zip.Store, encrypted: true},
		{name: "payload.bin", data: []byte("x"), method: zip.Store, encrypted: true},
	})
	l := zipLocker{Password: "infected"}
	if _, err := l.GetHeader(bytes.NewReader(data), int64(len(data))); !errors.Is(err, errZipIndexEncrypted) {
		t.Errorf("GetHeader() error = %v, want errZipIndexEncrypted", err)
	}
}

func TestZipLocker_PayloadMethod99_Rejected(t *testing.T) {
	idx := validIndexBytes(t, "payload.bin")
	// A "payload" that at least has 12 bytes so the CompressedSize64>=12
	// check passes and we actually reach the zipcrypto method check.
	payload := make([]byte, 20)
	data := buildZip(t, []zipEntrySpec{
		{name: "index.json", data: idx, method: zip.Store, encrypted: false},
		{name: "payload.bin", data: payload, method: 99, encrypted: true},
	})
	l := zipLocker{Password: "infected"}
	if _, err := l.UnlockFile(bytes.NewReader(data), int64(len(data)), io.Discard); !errors.Is(err, errZipMethod) {
		t.Errorf("UnlockFile() error = %v, want errZipMethod", err)
	}
}

func TestZipLocker_Layout_Rejected(t *testing.T) {
	idx := validIndexBytes(t, "payload.bin")
	index := zipEntrySpec{name: "index.json", data: idx, method: zip.Store}
	payload := zipEntrySpec{name: "payload.bin", data: bytes.Repeat([]byte("x"), 20), method: zip.Store, encrypted: true}
	extra := zipEntrySpec{name: "extra", data: []byte("x"), method: zip.Store}
	tests := []struct {
		name    string
		entries []zipEntrySpec
		wantErr error
	}{
		{name: "index only", entries: []zipEntrySpec{index}, wantErr: errZipLayout},
		{name: "extra entry", entries: []zipEntrySpec{index, payload, extra}, wantErr: errZipLayout},
		{name: "payload before index", entries: []zipEntrySpec{payload, index}, wantErr: errZipIndexNotFound},
		{name: "deflate index", entries: []zipEntrySpec{{name: "index.json", data: idx, method: zip.Deflate}, payload}, wantErr: errZipMethod},
	}
	l := zipLocker{Password: "infected"}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := buildZip(t, tt.entries)
			if _, err := l.GetHeader(bytes.NewReader(data), int64(len(data))); !errors.Is(err, tt.wantErr) {
				t.Errorf("GetHeader() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestZipLocker_DeflatePayload_Rejected(t *testing.T) {
	data := buildZip(t, []zipEntrySpec{
		{name: "index.json", data: validIndexBytes(t, "payload.bin"), method: zip.Store},
		{name: "payload.bin", data: bytes.Repeat([]byte("x"), 20), method: zip.Deflate, encrypted: true},
	})
	l := zipLocker{Password: "infected"}
	if _, err := l.UnlockFile(bytes.NewReader(data), int64(len(data)), io.Discard); !errors.Is(err, errZipMethod) {
		t.Errorf("UnlockFile() error = %v, want errZipMethod", err)
	}
}

func TestZipLocker_IndexTooLarge_Rejected(t *testing.T) {
	// Pad the index well past the cap inside a string field, so it stays
	// syntactically valid JSON while its declared UncompressedSize64
	// exceeds maxZipIndexSize.
	idx, err := json.Marshal(LockIndex{
		Version:  1,
		Filepath: "/tmp/x",
		Reason:   string(bytes.Repeat([]byte("r"), maxZipIndexSize+1)),
		Entry:    "payload.bin",
	})
	if err != nil {
		t.Fatalf("marshal: %s", err)
	}
	data := buildZip(t, []zipEntrySpec{
		{name: "index.json", data: idx, method: zip.Store},
		{name: "payload.bin", data: []byte("x"), method: zip.Store},
	})
	l := zipLocker{Password: "infected"}
	if _, err := l.GetHeader(bytes.NewReader(data), int64(len(data))); !errors.Is(err, errZipIndexTooLarge) {
		t.Errorf("GetHeader() error = %v, want errZipIndexTooLarge", err)
	}
}

func TestZipLocker_PayloadTooSmall_Rejected(t *testing.T) {
	idx := validIndexBytes(t, "payload.bin")
	data := buildZip(t, []zipEntrySpec{
		{name: "index.json", data: idx, method: zip.Store},
		{name: "payload.bin", data: []byte("short"), method: zip.Store, encrypted: true}, // < 12 bytes
	})
	l := zipLocker{Password: "infected"}
	if _, err := l.UnlockFile(bytes.NewReader(data), int64(len(data)), io.Discard); !errors.Is(err, errZipPayloadTooSmall) {
		t.Errorf("UnlockFile() error = %v, want errZipPayloadTooSmall", err)
	}
}

func TestZipLocker_PayloadNotFound_Rejected(t *testing.T) {
	idx := validIndexBytes(t, "does-not-exist.bin")
	data := buildZip(t, []zipEntrySpec{
		{name: "index.json", data: idx, method: zip.Store},
		{name: "other.bin", data: bytes.Repeat([]byte("x"), 20), method: zip.Store, encrypted: true},
	})
	l := zipLocker{Password: "infected"}
	if _, err := l.UnlockFile(bytes.NewReader(data), int64(len(data)), io.Discard); !errors.Is(err, errZipPayloadNotFound) {
		t.Errorf("UnlockFile() error = %v, want errZipPayloadNotFound", err)
	}
}

func TestZipLocker_PayloadNotMarkedEncrypted_Rejected(t *testing.T) {
	idx := validIndexBytes(t, "payload.bin")
	data := buildZip(t, []zipEntrySpec{
		{name: "index.json", data: idx, method: zip.Store},
		{name: "payload.bin", data: bytes.Repeat([]byte("x"), 20), method: zip.Store, encrypted: false},
	})
	l := zipLocker{Password: "infected"}
	if _, err := l.UnlockFile(bytes.NewReader(data), int64(len(data)), io.Discard); !errors.Is(err, errZipPayloadNotLocked) {
		t.Errorf("UnlockFile() error = %v, want errZipPayloadNotLocked", err)
	}
}

func TestZipLocker_IndexNotFound_Rejected(t *testing.T) {
	data := buildZip(t, []zipEntrySpec{
		{name: "something-else.json", data: []byte("{}"), method: zip.Store},
		{name: "payload.bin", data: []byte("x"), method: zip.Store},
	})
	l := zipLocker{Password: "infected"}
	if _, err := l.GetHeader(bytes.NewReader(data), int64(len(data))); !errors.Is(err, errZipIndexNotFound) {
		t.Errorf("GetHeader() error = %v, want errZipIndexNotFound", err)
	}
}

func TestZipLocker_UnknownIndexVersion_Rejected(t *testing.T) {
	idx, err := json.Marshal(LockIndex{Version: 999, Filepath: "/tmp/x", Reason: "r", Entry: "payload.bin"})
	if err != nil {
		t.Fatalf("marshal: %s", err)
	}
	data := buildZip(t, []zipEntrySpec{
		{name: "index.json", data: idx, method: zip.Store},
		{name: "payload.bin", data: []byte("x"), method: zip.Store},
	})
	l := zipLocker{Password: "infected"}
	if _, err := l.GetHeader(bytes.NewReader(data), int64(len(data))); !errors.Is(err, errZipUnknownVersion) {
		t.Errorf("GetHeader() error = %v, want errZipUnknownVersion", err)
	}
}

func TestZipLocker_WrongPassword_TamperedByte_DoNotCorrupt(t *testing.T) {
	l := zipLocker{Password: "infected"}
	var buf bytes.Buffer
	content := "some payload content long enough to matter for a checksum test"
	info := &zipFakeFileInfo{size: int64(len(content)), mode: 0o600, modTime: time.Now()}
	if err := l.LockFile("/tmp/x.bin", bytes.NewReader([]byte(content)), info, "malware: x", &buf); err != nil {
		t.Fatalf("LockFile: %s", err)
	}
	data := buf.Bytes()

	// Flip a byte deep inside the payload's ciphertext (well after the ZIP
	// local file headers): this must not panic and must not silently
	// succeed with wrong content.
	tampered := append([]byte(nil), data...)
	tampered[len(tampered)-5] ^= 0xFF

	var out bytes.Buffer
	_, err := l.UnlockFile(bytes.NewReader(tampered), int64(len(tampered)), &out)
	if err == nil {
		t.Fatalf("UnlockFile() on tampered ciphertext unexpectedly succeeded")
	}
	if errors.Is(err, io.EOF) {
		t.Errorf("UnlockFile() returned io.EOF-flavoured error %v, want a non-EOF error", err)
	}
}

func TestZipLocker_InvalidIndex_Rejected(t *testing.T) {
	payload := zipEntrySpec{name: "payload.bin", data: bytes.Repeat([]byte("x"), 20), method: zip.Store, encrypted: true}
	tests := []struct {
		name    string
		index   LockIndex
		wantErr error
	}{
		{name: "version 0", index: LockIndex{Version: 0, Filepath: "/tmp/x", Entry: "payload.bin"}, wantErr: errZipUnknownVersion},
		{name: "negative version", index: LockIndex{Version: -1, Filepath: "/tmp/x", Entry: "payload.bin"}, wantErr: errZipUnknownVersion},
		{name: "negative size", index: LockIndex{Version: 1, Filepath: "/tmp/x", Entry: "payload.bin", Size: -1}, wantErr: errZipInvalidIndex},
		{name: "empty path", index: LockIndex{Version: 1, Entry: "payload.bin"}, wantErr: errZipInvalidIndex},
		{name: "empty entry", index: LockIndex{Version: 1, Filepath: "/tmp/x"}, wantErr: errZipInvalidIndex},
	}
	l := zipLocker{Password: "infected"}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idx, err := json.Marshal(tt.index)
			if err != nil {
				t.Fatal(err)
			}
			data := buildZip(t, []zipEntrySpec{{name: "index.json", data: idx, method: zip.Store}, payload})
			if _, err := l.GetHeader(bytes.NewReader(data), int64(len(data))); !errors.Is(err, tt.wantErr) {
				t.Errorf("GetHeader() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestZipLocker_ForgedEOCD_Rejected(t *testing.T) {
	var good bytes.Buffer
	l := zipLocker{Password: "infected"}
	info := &zipFakeFileInfo{size: 5, mode: 0o600, modTime: time.Now()}
	if err := l.LockFile("/tmp/x", bytes.NewReader([]byte("hello")), info, "malware: x", &good); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(b []byte) []byte
	}{
		{"65535 entries announced", func(b []byte) []byte {
			binary.LittleEndian.PutUint16(b[len(b)-12:], 0xffff)
			binary.LittleEndian.PutUint16(b[len(b)-14:], 0xffff)
			return b
		}},
		{"three entries announced", func(b []byte) []byte {
			binary.LittleEndian.PutUint16(b[len(b)-12:], 3)
			binary.LittleEndian.PutUint16(b[len(b)-14:], 3)
			return b
		}},
		{"trailing comment", func(b []byte) []byte { return append(b, []byte("comment")...) }},
		{"too short", func(b []byte) []byte { return b[:10] }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := tt.mutate(bytes.Clone(good.Bytes()))
			if _, err := l.GetHeader(bytes.NewReader(data), int64(len(data))); !errors.Is(err, errZipLayout) {
				t.Errorf("GetHeader() error = %v, want errZipLayout", err)
			}
		})
	}
}

func TestZipLocker_PayloadEntryChecks_Rejected(t *testing.T) {
	idx := validIndexBytes(t, "payload.bin")
	index := zipEntrySpec{name: "index.json", data: idx, method: zip.Store}
	l := zipLocker{Password: "infected"}
	// buildZip writes sizes as raw data length for both compressed and
	// uncompressed, and no data descriptor.
	data := buildZip(t, []zipEntrySpec{index, {name: "payload.bin", data: bytes.Repeat([]byte("x"), 20), method: zip.Store, encrypted: true}})
	if _, err := l.GetHeader(bytes.NewReader(data), int64(len(data))); err == nil {
		t.Error("GetHeader() accepted a payload without data descriptor and with inconsistent sizes")
	}
}

func TestZipLocker_LongReason_Truncated(t *testing.T) {
	l := zipLocker{Password: "infected"}
	info := &zipFakeFileInfo{size: 5, mode: 0o600, modTime: time.Now()}
	var buf bytes.Buffer
	if err := l.LockFile("/tmp/x", bytes.NewReader([]byte("hello")), info, strings.Repeat("r", 3*maxZipIndexSize), &buf); err != nil {
		t.Fatalf("LockFile() error = %v", err)
	}
	if _, err := l.GetHeader(bytes.NewReader(buf.Bytes()), int64(buf.Len())); err != nil {
		t.Errorf("GetHeader() on a long-reason container error = %v", err)
	}
}

func TestZipLocker_NoSpecialModeBitsInEntry(t *testing.T) {
	l := zipLocker{Password: "infected"}
	info := &zipFakeFileInfo{size: 5, mode: 0o755 | os.ModeSetuid | os.ModeSetgid, modTime: time.Now()}
	var buf bytes.Buffer
	if err := l.LockFile("/tmp/x", bytes.NewReader([]byte("hello")), info, "malware: x", &buf); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	if mode := zr.File[1].Mode(); mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		t.Errorf("payload entry mode = %v, must not carry setuid/setgid/sticky", mode)
	}
}

func TestZipLocker_Zip64Record(t *testing.T) {
	var good bytes.Buffer
	l := zipLocker{Password: "infected"}
	info := &zipFakeFileInfo{size: 5, mode: 0o600, modTime: time.Now()}
	if err := l.LockFile("/tmp/x", bytes.NewReader([]byte("hello")), info, "malware: x", &good); err != nil {
		t.Fatal(err)
	}
	// zip64 rewrites the container the way archive/zip does past 4 GiB: the
	// EOCD carries the markers and a ZIP64 record holds the real values.
	zip64 := func(entries uint64, locatorSig uint32) []byte {
		b := good.Bytes()
		eocd := bytes.Clone(b[len(b)-22:])
		body := bytes.Clone(b[:len(b)-22])
		recOffset := uint64(len(body))
		rec := make([]byte, 56)
		binary.LittleEndian.PutUint32(rec[0:4], 0x06064b50)
		binary.LittleEndian.PutUint64(rec[4:12], 44)
		binary.LittleEndian.PutUint64(rec[24:32], entries)
		binary.LittleEndian.PutUint64(rec[32:40], entries)
		binary.LittleEndian.PutUint64(rec[40:48], uint64(binary.LittleEndian.Uint32(eocd[12:16])))
		binary.LittleEndian.PutUint64(rec[48:56], uint64(binary.LittleEndian.Uint32(eocd[16:20])))
		locator := make([]byte, 20)
		binary.LittleEndian.PutUint32(locator[0:4], locatorSig)
		binary.LittleEndian.PutUint64(locator[8:16], recOffset)
		binary.LittleEndian.PutUint32(locator[16:20], 1)
		binary.LittleEndian.PutUint32(eocd[12:16], 0xffffffff)
		binary.LittleEndian.PutUint32(eocd[16:20], 0xffffffff)
		return append(append(append(body, rec...), locator...), eocd...)
	}
	tests := []struct {
		name    string
		data    []byte
		wantErr error
	}{
		{"valid zip64 record with two entries", zip64(2, 0x07064b50), nil},
		{"65535 entries in the zip64 record", zip64(0xffff, 0x07064b50), errZipLayout},
		{"three entries in the zip64 record", zip64(3, 0x07064b50), errZipLayout},
		{"bad locator signature", zip64(2, 0), errZipLayout},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := l.GetHeader(bytes.NewReader(tt.data), int64(len(tt.data)))
			if tt.wantErr == nil && err != nil {
				t.Errorf("GetHeader() error = %v, want nil", err)
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("GetHeader() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}
