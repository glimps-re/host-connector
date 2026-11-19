package quarantine

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	mrand "math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Metadata of testdata/legacy_v1.5.3.lock, see testdata/README.md for
// provenance and how to regenerate it.
const (
	legacyFixturePassword = "infected"
	legacyFixtureFilepath = "/home/user/malware/legacy_sample.exe"
	legacyFixtureReason   = "malware: trojan.legacy.v1"
	legacyFixtureContent  = "This is a synthetic payload standing in for a v1.5.3 quarantined sample.\n"
)

func Test_cipherFile(t *testing.T) {
	type args struct {
		password string
		input    string
	}
	tests := []struct {
		name    string
		seed    int64
		args    args
		wantOut string
		wantErr bool
	}{
		{
			name: "cipher1",
			seed: 1234,
			args: args{
				password: "RandomPassword",
				input:    "azerty",
			},
			wantErr: false,
			wantOut: "c00e5d67c2755389aded7d8b151cbd5bcdf7ed275ad5e028b664880fc7581c77547deaf77620043495b358675999c4b7fe3dd3c32845",
		},
		{
			name: "cipher2",
			seed: 1235,
			args: args{
				password: "RandomPassword",
				input:    "azerty",
			},
			wantErr: false,
			wantOut: "967b822188d90d8080f226a31a9306b5e5c07fdca452cfa8a3853ce6c00dd7478caea4dbbace351154777b09ce954e206d77cfc840fd",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The salt and IV come from rand.Reader: pin them to a seeded,
			// non-cryptographic source so the expected output is reproducible.
			origReader := rand.Reader
			t.Cleanup(func() { rand.Reader = origReader })
			rand.Reader = mrand.New(mrand.NewSource(tt.seed)) //nolint:gosec // deterministic salt and IV for golden outputs, never used outside tests
			out := &bytes.Buffer{}
			if err := cipherFile(tt.args.password, strings.NewReader(tt.args.input), out); (err != nil) != tt.wantErr {
				t.Errorf("cipherFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			gotOut := hex.EncodeToString(out.Bytes())
			if gotOut != tt.wantOut {
				t.Errorf("cipherFile() = %v, want %v", gotOut, tt.wantOut)
			}
		})
	}
}

func Test_decipherFile(t *testing.T) {
	type args struct {
		password string
		input    string
	}
	tests := []struct {
		name    string
		seed    int64
		args    args
		wantOut string
		wantErr bool
	}{
		{
			name: "cipher1",
			seed: 1234,
			args: args{
				password: "RandomPassword",
				input:    "c00e5d67c2755389aded7d8b151cbd5bcdf7ed275ad5e028b664880fc7581c77547deaf77620043495b358675999c4b7fe3dd3c32845",
			},
			wantErr: false,
			wantOut: "azerty",
		},
		{
			name: "cipher2",
			seed: 1235,
			args: args{
				password: "RandomPassword",
				input:    "967b822188d90d8080f226a31a9306b5e5c07fdca452cfa8a3853ce6c00dd7478caea4dbbace351154777b09ce954e206d77cfc840fd",
			},
			wantErr: false,
			wantOut: "azerty",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The salt and IV come from rand.Reader: pin them to a seeded,
			// non-cryptographic source so the expected output is reproducible.
			origReader := rand.Reader
			t.Cleanup(func() { rand.Reader = origReader })
			rand.Reader = mrand.New(mrand.NewSource(tt.seed)) //nolint:gosec // deterministic salt and IV for golden outputs, never used outside tests

			in := hex.NewDecoder(strings.NewReader(tt.args.input))
			out := &bytes.Buffer{}
			if err := decipherFile(tt.args.password, in, out); (err != nil) != tt.wantErr {
				t.Errorf("decipherFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			gotOut := out.String()
			if gotOut != tt.wantOut {
				t.Errorf("decipherFile() = %v, want %v", gotOut, tt.wantOut)
			}
		})
	}
}

func Test_LockFile(t *testing.T) {
	tests := []struct {
		name string
		test func(t *testing.T)
	}{
		{
			name: "test 1",
			test: func(t *testing.T) {
				t.Helper()
				file, err := os.CreateTemp(t.TempDir(), "test_lock_*")
				if err != nil {
					t.Errorf("could not create temp file, error: %s", err)
					return
				}
				defer func() {
					err := file.Close()
					if err != nil {
						t.Fatalf("TestLockFile cannot close file : %s", err)
					}
				}()
				_, err = file.WriteString("my funny test content, long enough to require several blocks")
				if err != nil {
					t.Fatalf("TestLockFile cannot write string : %s", err)
				}
				err = file.Sync()
				if err != nil {
					t.Fatalf("TestLockFile cannot sync file : %s", err)
				}
				buffer := &bytes.Buffer{}

				locker := tarLocker{Password: "tst_password"}

				_, err = file.Seek(0, io.SeekStart)
				if err != nil {
					t.Fatalf("TestLockFile cannot seek file : %s", err)
				}
				stat, err := os.Stat(file.Name())
				if err != nil {
					t.Errorf("could not stat test file, error: %s", err)
					return
				}
				err = locker.LockFile(file.Name(), file, stat, "malicious test", buffer)
				if err != nil {
					t.Errorf("could not lock test file, error: %s", err)
					return
				}

				// check get header
				lockedBytes := buffer.Bytes()
				entry, err := locker.GetHeader(bytes.NewReader(lockedBytes), int64(len(lockedBytes)))
				if err != nil {
					t.Errorf("could not get header of locked test file, error: %s", err)
					return
				}
				if entry.Filepath != file.Name() {
					t.Errorf("invalid filepath from lock entry header, got: %v", entry.Filepath)
				}

				if entry.Reason != "malicious test" {
					t.Errorf("invalid reason from lock entry header, got: %v", entry.Reason)
				}

				buffer2 := &bytes.Buffer{}

				locked, err := locker.UnlockFile(bytes.NewReader(lockedBytes), int64(len(lockedBytes)), buffer2)
				if err != nil {
					t.Errorf("could not unlock test file, error: %s", err)
					return
				}
				if locked.Filepath != file.Name() {
					t.Errorf("invalid file path, got: %v, want: %v", locked.Filepath, file.Name())
				}
				if locked.Size != stat.Size() {
					t.Errorf("invalid stat size, got: %v, want: %v", locked.Size, stat.Size())
				}
				if locked.Reason != "malicious test" {
					t.Errorf("invalid reason, got: %v, want: %v", locked.Reason, "malicious test")
				}
				if buffer2.String() != "my funny test content, long enough to require several blocks" {
					t.Errorf("invalid content, got: %v", buffer2.String())
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, tt.test)
	}
}

// Test_UnlockFile_LegacyFixture exercises S1: a tar `.lock` produced by
// GMHost <= v1.5.3 (testdata/legacy_v1.5.3.lock, generated with the
// unchanged wire format and a pinned rand source, see testdata/README.md)
// must still restore bit-for-bit with the refactored tarLocker.
func Test_UnlockFile_LegacyFixture(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "legacy_v1.5.3.lock"))
	if err != nil {
		t.Fatalf("could not read legacy fixture: %s", err)
	}

	locker := tarLocker{Password: legacyFixturePassword}

	entry, err := locker.GetHeader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("GetHeader() on legacy fixture failed: %s", err)
	}
	if entry.Filepath != legacyFixtureFilepath {
		t.Errorf("GetHeader() filepath = %q, want %q", entry.Filepath, legacyFixtureFilepath)
	}
	if entry.Reason != legacyFixtureReason {
		t.Errorf("GetHeader() reason = %q, want %q", entry.Reason, legacyFixtureReason)
	}

	var out bytes.Buffer
	locked, err := locker.UnlockFile(bytes.NewReader(data), int64(len(data)), &out)
	if err != nil {
		t.Fatalf("UnlockFile() on legacy fixture failed: %s", err)
	}
	if out.String() != legacyFixtureContent {
		t.Errorf("UnlockFile() content = %q, want %q", out.String(), legacyFixtureContent)
	}
	if locked.Filepath != legacyFixtureFilepath {
		t.Errorf("UnlockFile() filepath = %q, want %q", locked.Filepath, legacyFixtureFilepath)
	}
	if locked.Size != int64(len(legacyFixtureContent)) {
		t.Errorf("UnlockFile() size = %d, want %d", locked.Size, len(legacyFixtureContent))
	}

	// The tar format's "index" entry is cleartext (unchanged from the
	// original format): GetHeader never touches the password, so it
	// succeeds identically regardless of it.
	badLocker := tarLocker{Password: "not-the-right-password"}
	if _, err := badLocker.GetHeader(bytes.NewReader(data), int64(len(data))); err != nil {
		t.Errorf("GetHeader() must not depend on the password, got error: %s", err)
	}

	// The payload is AES-CTR, which is unauthenticated: decrypting
	// with the wrong password never errors, it silently produces garbage
	// plaintext. The only requirement is that it must not panic and
	// must not accidentally reproduce the real content.
	var garbage bytes.Buffer
	if _, err := badLocker.UnlockFile(bytes.NewReader(data), int64(len(data)), &garbage); err != nil {
		t.Errorf("UnlockFile() with wrong password unexpectedly errored: %s", err)
	}
	if garbage.String() == legacyFixtureContent {
		t.Errorf("UnlockFile() with wrong password unexpectedly recovered the real content")
	}
}
