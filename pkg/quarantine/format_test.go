package quarantine

import (
	"bytes"
	"errors"
	"testing"
)

func TestParseFormat(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    Format
		wantErr bool
	}{
		{name: "empty defaults to tar", in: "", want: FormatTar},
		{name: "tar", in: "tar", want: FormatTar},
		{name: "zip", in: "zip", want: FormatZip},
		{name: "unknown", in: "7z", wantErr: true},
		{name: "case sensitive", in: "TAR", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseFormat(tt.in)
			if tt.wantErr {
				if !errors.Is(err, ErrUnknownFormat) {
					t.Errorf("ParseFormat(%q) error = %v, want ErrUnknownFormat", tt.in, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseFormat(%q) unexpected error = %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("ParseFormat(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestDetectFormat(t *testing.T) {
	pad := func(prefix []byte, total int) []byte {
		b := make([]byte, total)
		copy(b, prefix)
		return b
	}

	tarWithMagicAt257 := func() []byte {
		b := make([]byte, 512)
		copy(b[257:262], "ustar")
		return b
	}()

	tests := []struct {
		name    string
		data    []byte
		want    containerFormat
		wantErr error
	}{
		{
			name: "empty file",
			data: nil,
			want: formatUnknown, wantErr: errUnknownLockFormat,
		},
		{
			name: "zip local file header signature",
			data: pad([]byte("PK\x03\x04rest of the local file header..."), 600),
			want: formatZipContainer,
		},
		{
			name: "zip signature at minimum length (4 bytes)",
			data: []byte("PK\x03\x04"),
			want: formatZipContainer,
		},
		{
			name: "zip empty-archive marker (PK\\x05\\x06) is unknown",
			data: pad([]byte("PK\x05\x06"), 600),
			want: formatUnknown, wantErr: errUnknownLockFormat,
		},
		{
			name: "zip spanning marker (PK\\x07\\x08) is unknown",
			data: pad([]byte("PK\x07\x08"), 600),
			want: formatUnknown, wantErr: errUnknownLockFormat,
		},
		{
			name: "tar ustar magic at offset 257",
			data: tarWithMagicAt257,
			want: formatTarContainer,
		},
		{
			name: "tar magic just short of offset 257+5",
			data: tarWithMagicAt257[:261], // one byte short of the full magic
			want: formatUnknown, wantErr: errUnknownLockFormat,
		},
		{
			name: "garbage",
			data: bytes.Repeat([]byte{0x00}, 512),
			want: formatUnknown, wantErr: errUnknownLockFormat,
		},
		{
			name: "3 bytes (shorter than any signature)",
			data: []byte{'P', 'K', 0x03},
			want: formatUnknown, wantErr: errUnknownLockFormat,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := detectFormat(bytes.NewReader(tt.data), int64(len(tt.data)))
			if got != tt.want {
				t.Errorf("detectFormat() format = %v, want %v", got, tt.want)
			}
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("detectFormat() error = %v, want %v", err, tt.wantErr)
				}
			} else if err != nil {
				t.Errorf("detectFormat() unexpected error = %v", err)
			}
		})
	}
}

// FuzzDetectFormat proves detectFormat never panics, hangs, or allocates
// without bound on arbitrary (including adversarially truncated) input.
func FuzzDetectFormat(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("PK\x03\x04"))
	f.Add([]byte("PK\x05\x06"))
	f.Add([]byte("PK\x07\x08"))
	tar512 := make([]byte, 512)
	copy(tar512[257:262], "ustar")
	f.Add(tar512)
	f.Add([]byte{'P', 'K'})
	f.Add(bytes.Repeat([]byte{0xff}, 4096))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = detectFormat(bytes.NewReader(data), int64(len(data)))
	})
}
