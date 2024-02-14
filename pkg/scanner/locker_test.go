package scanner

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	mrand "math/rand"
	"os"
	"strings"
	"testing"
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
			// ensure always the same random
			rand.Reader = mrand.New(mrand.NewSource(tt.seed))

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
			// ensure always the same random
			rand.Reader = mrand.New(mrand.NewSource(tt.seed))

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
				file, err := os.CreateTemp(os.TempDir(), "test_lock_*")
				if err != nil {
					t.Errorf("could not create temp file, error: %s", err)
					return
				}
				defer file.Close()
				defer os.Remove(file.Name())
				file.WriteString("my funny test content, long enough to require several blocks")
				file.Sync()
				buffer := &bytes.Buffer{}

				locker := Lock{Password: "tst_password"}

				file.Seek(0, io.SeekStart)
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

				entry, err := locker.GetHeader(bytes.NewReader(buffer.Bytes()))
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

				fileOut, infoOut, reason, err := locker.UnlockFile(bytes.NewReader(buffer.Bytes()), buffer2)
				if err != nil {
					t.Errorf("could not unlock test file, error: %s", err)
					return
				}
				if fileOut != file.Name() {
					t.Errorf("invalid file path, got: %v, want: %v", fileOut, file.Name())
				}
				if infoOut.Size() != stat.Size() {
					t.Errorf("invalid stat size, got: %v, want: %v", infoOut.Size(), stat.Size())
				}
				if reason != "malicious test" {
					t.Errorf("invalid reason, got: %v, want: %v", reason, "malicious test")
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
