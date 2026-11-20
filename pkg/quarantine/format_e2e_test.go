package quarantine

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newE2EHandler(t *testing.T, format Format) (*QuarantineHandler, string) {
	t.Helper()
	dir := t.TempDir()
	q, err := NewQuarantineHandler(t.Context(), Config{Location: dir, LockPassword: "infected", Format: format})
	if err != nil {
		t.Fatalf("NewQuarantineHandler() error = %v", err)
	}
	t.Cleanup(func() {
		if err := q.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
	return q, dir
}

func writeSample(t *testing.T, name string, content []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestQuarantineRestore_WrittenFormat(t *testing.T) {
	longName := strings.Repeat("a", 251) + ".exe"
	tests := []struct {
		name      string
		format    Format
		file      string
		content   []byte
		wantMagic string
	}{
		{"zip", FormatZip, "sample.bin", []byte("zip payload"), "PK"},
		{"tar explicit", FormatTar, "sample.bin", []byte("tar payload"), ""},
		{"default is tar", "", "sample.bin", []byte("default payload"), ""},
		{"zip empty file", FormatZip, "empty.bin", nil, "PK"},
		{"zip 255 byte file name", FormatZip, longName, []byte("long"), "PK"},
		{"tar 255 byte file name", FormatTar, longName, []byte("long"), ""},
		{"zip binary content", FormatZip, "b.bin", bytes.Repeat([]byte{0, 0xff, 'P', 'K', 3, 4}, 5000), "PK"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q, dir := newE2EHandler(t, tt.format)
			src := writeSample(t, tt.file, tt.content)
			location, id, err := quarantinePath(t.Context(), t, q, src, sha256Hex(tt.content), []string{"m"})
			if err != nil {
				t.Fatalf("Quarantine() error = %v", err)
			}
			head, err := os.ReadFile(filepath.Clean(location))
			if err != nil {
				t.Fatal(err)
			}
			if tt.wantMagic != "" && !bytes.HasPrefix(head, []byte(tt.wantMagic)) {
				t.Errorf("container does not start with %q", tt.wantMagic)
			}
			if tt.wantMagic == "" && bytes.HasPrefix(head, []byte("PK\x03\x04")) {
				t.Error("tar format must not produce a zip container")
			}
			if _, err := os.Stat(src); err == nil {
				if err := os.Remove(src); err != nil {
					t.Fatal(err)
				}
			}
			if err := q.Restore(t.Context(), id); err != nil {
				t.Fatalf("Restore() error = %v", err)
			}
			got, err := os.ReadFile(filepath.Clean(src))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, tt.content) {
				t.Errorf("restored content differs (%d bytes, want %d)", len(got), len(tt.content))
			}
			entries, err := os.ReadDir(filepath.Dir(src))
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range entries {
				if strings.HasPrefix(e.Name(), TempPrefix) {
					t.Errorf("temporary file %q left behind", e.Name())
				}
			}
			if _, err := os.Stat(filepath.Join(dir, id+".lock")); err == nil {
				t.Error(".lock must be removed after a successful restore")
			}
		})
	}
}

func TestReconfigure_FormatChangeKeepsOldLocksRestorable(t *testing.T) {
	q, dir := newE2EHandler(t, FormatTar)
	oldSrc := writeSample(t, "old.bin", []byte("old tar content"))
	_, oldID, err := quarantinePath(t.Context(), t, q, oldSrc, sha256Hex([]byte("old tar content")), []string{"m"})
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Reconfigure(t.Context(), Config{Location: dir, LockPassword: "infected", Format: FormatZip}); err != nil {
		t.Fatalf("Reconfigure() error = %v", err)
	}
	newSrc := writeSample(t, "new.bin", []byte("new zip content"))
	newLoc, newID, err := quarantinePath(t.Context(), t, q, newSrc, sha256Hex([]byte("new zip content")), []string{"m"})
	if err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Clean(newLoc)); err != nil || !bytes.HasPrefix(b, []byte("PK")) {
		t.Errorf("new container after Reconfigure(zip) is not a zip (err=%v)", err)
	}
	for id, want := range map[string]struct {
		path, content string
	}{oldID: {oldSrc, "old tar content"}, newID: {newSrc, "new zip content"}} {
		if err := q.Restore(t.Context(), id); err != nil {
			t.Fatalf("Restore(%s) error = %v", id, err)
		}
		got, err := os.ReadFile(filepath.Clean(want.path))
		if err != nil || string(got) != want.content {
			t.Errorf("restored %s = %q (err=%v), want %q", id, got, err, want.content)
		}
	}
}

func TestReconfigure_UnknownFormatKeepsState(t *testing.T) {
	q, dir := newE2EHandler(t, FormatTar)
	err := q.Reconfigure(t.Context(), Config{Location: dir, LockPassword: "infected", Format: "rar"})
	if err == nil {
		t.Fatal("Reconfigure() error = nil, want ErrUnknownFormat")
	}
	src := writeSample(t, "s.bin", []byte("still tar"))
	loc, _, err := quarantinePath(t.Context(), t, q, src, sha256Hex([]byte("still tar")), nil)
	if err != nil {
		t.Fatalf("Quarantine() after refused Reconfigure error = %v", err)
	}
	if b, err := os.ReadFile(filepath.Clean(loc)); err != nil || bytes.HasPrefix(b, []byte("PK")) {
		t.Errorf("format changed despite the refused Reconfigure (err=%v)", err)
	}
}

func TestNewQuarantineHandler_UnknownFormat(t *testing.T) {
	_, err := NewQuarantineHandler(t.Context(), Config{Location: t.TempDir(), LockPassword: "x", Format: "rar"})
	if err == nil {
		t.Fatal("NewQuarantineHandler() error = nil, want ErrUnknownFormat")
	}
}

func TestRestore_hostileIDs(t *testing.T) {
	q, _ := newE2EHandler(t, FormatTar)
	valid := strings.Repeat("a", 64)
	for name, id := range map[string]string{
		"empty":            "",
		"63 hex":           valid[:63],
		"65 hex":           valid + "a",
		"traversal prefix": "../" + valid[:61],
		"traversal inside": valid[:30] + "/../" + valid[:30],
		"slash":            valid[:63] + "/",
		"nul":              valid[:63] + "\x00",
		"non hex":          valid[:63] + "g",
		"absolute":         "/etc/passwd",
		"newline":          valid + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			if err := q.Restore(t.Context(), id); !errors.Is(err, errInvalidQuarantineID) {
				t.Errorf("Restore(%q) error = %v, want errInvalidQuarantineID", id, err)
			}
		})
	}
}

func TestQuarantine_wrongSHA256Refused(t *testing.T) {
	for _, format := range []Format{FormatTar, FormatZip} {
		t.Run(string(format), func(t *testing.T) {
			q, dir := newE2EHandler(t, format)
			src := writeSample(t, "s.bin", []byte("actual content"))
			wrong := sha256Hex([]byte("another content"))
			_, id, err := quarantinePath(t.Context(), t, q, src, wrong, []string{"m"})
			if !errors.Is(err, ErrQuarantineSHA256Mismatch) {
				t.Fatalf("Quarantine() error = %v, want ErrQuarantineSHA256Mismatch", err)
			}
			if entries, err := filepath.Glob(filepath.Join(dir, "*.lock")); err != nil || len(entries) != 0 {
				t.Errorf("no .lock must be kept, got %v (err %v)", entries, err)
			}
			if got, err := q.IsRestored(t.Context(), src, wrong); err != nil || got {
				t.Errorf("IsRestored() = %t (err %v) for a refused quarantine %q", got, err, id)
			}
			if _, err := os.Stat(src); err != nil {
				t.Errorf("source must be left untouched: %v", err)
			}
		})
	}
}
