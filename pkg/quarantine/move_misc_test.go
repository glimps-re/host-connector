package quarantine

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCopyAndDelete(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.bin")
	if err := os.WriteFile(src, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "dst.bin")
	if err := copyAndDelete(src, dst); err != nil {
		t.Fatalf("copyAndDelete() error = %v", err)
	}
	got, err := os.ReadFile(filepath.Clean(dst))
	if err != nil || string(got) != "payload" {
		t.Errorf("dst = %q (err %v), want payload", got, err)
	}
	if info, err := os.Stat(dst); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("dst mode = %v (err %v), want 0600", info, err)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Errorf("src must be removed, stat err = %v", err)
	}
}

func TestCopyAndDelete_Errors(t *testing.T) {
	dir := t.TempDir()
	if err := copyAndDelete(filepath.Join(dir, "missing"), filepath.Join(dir, "dst")); err == nil {
		t.Error("missing source: error = nil")
	}
	src := filepath.Join(dir, "src")
	if err := os.WriteFile(src, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copyAndDelete(src, filepath.Join(dir, "no-such-dir", "dst")); err == nil {
		t.Error("unwritable destination: error = nil")
	}
	if _, err := os.Stat(src); err != nil {
		t.Errorf("source must be kept on failure: %v", err)
	}
}

func TestMoveFile_MissingSource(t *testing.T) {
	dir := t.TempDir()
	if err := MoveFile(filepath.Join(dir, "missing"), filepath.Join(dir, "dst")); err == nil {
		t.Error("MoveFile() error = nil, want error")
	}
}

func TestNewQuarantineHandler_LocationIsAFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	q, err := NewQuarantineHandler(t.Context(), Config{Location: filepath.Join(f, "sub"), LockPassword: "x"})
	if err == nil {
		if e := q.Close(); e != nil {
			t.Error(e)
		}
		t.Fatal("NewQuarantineHandler() error = nil, want error")
	}
}

func TestIsTempFile(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{TempPrefix + "a.bin-0123", true},
		{filepath.Join("/dir", TempPrefix+"a.bin-0123"), true},
		{"a.bin", false},
		{filepath.Join("/dir"+TempPrefix, "a.bin"), false},
		{"x" + TempPrefix + "a", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := IsTempFile(tt.path); got != tt.want {
			t.Errorf("IsTempFile(%q) = %t, want %t", tt.path, got, tt.want)
		}
	}
}
