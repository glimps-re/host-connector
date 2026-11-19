package quarantine

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestSanitizeEntryName(t *testing.T) {
	tests := []struct {
		name     string
		original string
		want     string
	}{
		{name: "plain unix path", original: "/home/user/malware/evil.exe", want: "evil.exe"},
		{name: "plain windows path", original: `C:\Users\bob\malware.exe`, want: "malware.exe"},
		{name: "mixed separators", original: `/mnt/share\evil.exe`, want: "evil.exe"},
		{name: "already just a basename", original: "evil.exe", want: "evil.exe"},
		{name: "drive letter with forward slashes", original: "D:/data/evil.exe", want: "evil.exe"},
		{name: "empty", original: "", want: "payload.bin"},
		{name: "dot", original: ".", want: "payload.bin"},
		{name: "dotdot", original: "..", want: "payload.bin"},
		{name: "trailing dot", original: "evil.exe.", want: "evil.exe"},
		{name: "trailing spaces", original: "evil.exe   ", want: "evil.exe"},
		{name: "trailing dots and spaces mixed", original: "evil.exe . . ", want: "evil.exe"},
		{
			name:     "C0 control characters stripped",
			original: "evil\x00\x01\x1f.exe",
			want:     "evil.exe",
		},
		{
			name:     "DEL stripped",
			original: "evil\x7f.exe",
			want:     "evil.exe",
		},
		{
			name:     "C1 control characters stripped",
			original: "evil\u0080\u009f.exe",
			want:     "evil.exe",
		},
		{
			name:     "RLO bidi override stripped (spoofing attempt)",
			original: "evil\u202eexe.txt",
			want:     "evilexe.txt",
		},
		{
			name:     "zero width and line separators stripped",
			original: "inv\u200b\u200c\u200d\ufeff\u2028\u2029oice.exe",
			want:     "invoice.exe",
		},
		{
			name:     "LRM/RLM stripped",
			original: "evil\u200e\u200f.exe",
			want:     "evil.exe",
		},
		{name: "windows reserved name bare", original: "CON", want: "_CON"},
		{name: "windows reserved name lowercase", original: "con", want: "_con"},
		{name: "windows reserved name with extension", original: "NUL.txt", want: "_NUL.txt"},
		{name: "windows reserved name COM port", original: "COM1.exe", want: "_COM1.exe"},
		{name: "windows reserved name LPT port", original: "lpt9", want: "_lpt9"},
		{name: "name resembling but not a reserved name", original: "CONSOLE.exe", want: "CONSOLE.exe"},
		{name: "collides with index.json literally", original: "index.json", want: "payload.bin"},
		{
			name:     "collides with index.json case-insensitively (Explorer extracts onto NTFS)",
			original: "INDEX.JSON",
			want:     "payload.bin",
		},
		{
			name:     "valid UTF-8 with non-ASCII characters is preserved",
			original: "/tmp/факел.exe",
			want:     "факел.exe",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeEntryName(tt.original)
			if got != tt.want {
				t.Errorf("sanitizeEntryName(%q) = %q, want %q", tt.original, got, tt.want)
			}
		})
	}
}

func TestSanitizeEntryName_InvalidUTF8(t *testing.T) {
	original := "evil\xff\xfeexe.exe"
	got := sanitizeEntryName(original)
	if !utf8.ValidString(got) {
		t.Errorf("sanitizeEntryName(%q) = %q is not valid UTF-8", original, got)
	}
}

func TestSanitizeEntryName_LengthCap(t *testing.T) {
	original := strings.Repeat("a", 500) + ".exe"
	got := sanitizeEntryName(original)
	if len(got) > maxEntryNameBytes {
		t.Errorf("sanitizeEntryName() length = %d, want <= %d", len(got), maxEntryNameBytes)
	}
	if got == "" {
		t.Errorf("sanitizeEntryName() unexpectedly empty after truncation")
	}
}
