package scanner

import (
	"errors"
	"math"
	"testing"
)

func TestHumanSize(t *testing.T) {
	const mib = 1 << 20
	tests := []struct {
		in   int64
		want string
	}{
		{0, "0 B"},
		{1023, "1023 B"},
		{1024, "1 KiB"},
		{1025, "1 KiB"},
		{1126, "1 KiB"},
		{1127, "1.1 KiB"},
		{1536, "1.5 KiB"},
		{mib - 1, "1023.9 KiB"},
		{mib, "1 MiB"},
		{mib + 1, "1 MiB"},
		{1<<30 - 1, "1023.9 MiB"},
		{1 << 30, "1 GiB"},
		{100 * mib, "100 MiB"},
		{150*mib + 1, "150 MiB"},
		{2 << 30, "2 GiB"},
		{math.MaxInt64, "7.9 EiB"},
		{1 << 40, "1 TiB"},
		{1 << 50, "1 PiB"},
		{1 << 60, "1 EiB"},
		{-5, "-5 B"},
		{math.MinInt64, "-9223372036854775808 B"},
	}
	for _, tt := range tests {
		if got := humanSize(tt.in); got != tt.want {
			t.Errorf("humanSize(%d) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestTooBigError(t *testing.T) {
	const mib = 1 << 20
	tests := []struct {
		name        string
		size, limit int64
		want        string
	}{
		{"units", 150*mib + 1, 100 * mib, "file is too big to be analyzed: size 150 MiB exceeds max_file_size 100 MiB"},
		{"same rounded value", 1025, 1024, "file is too big to be analyzed: size 1025 B exceeds max_file_size 1024 B"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tooBigError(tt.size, tt.limit)
			if err.Error() != tt.want {
				t.Errorf("tooBigError = %q, want %q", err, tt.want)
			}
			if !errors.Is(err, errFileTooBig) {
				t.Errorf("tooBigError = %v, want errors.Is errFileTooBig", err)
			}
		})
	}
}
