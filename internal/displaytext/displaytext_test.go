package displaytext

import (
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestIsHidden(t *testing.T) {
	tests := []struct {
		name string
		r    rune
		want bool
	}{
		{"NUL", 0x00, true},
		{"line feed", 0x0A, true},
		{"carriage return", 0x0D, true},
		{"escape", 0x1B, true},
		{"DEL", 0x7F, true},
		{"C1 start", 0x80, true},
		{"C1 end", 0x9F, true},
		{"soft hyphen", 0x00AD, true},
		{"combining grapheme joiner", 0x034F, true},
		{"arabic letter mark", 0x061C, true},
		{"hangul choseong filler", 0x115F, true},
		{"hangul jungseong filler", 0x1160, true},
		{"khmer inherent vowel", 0x17B4, true},
		{"mongolian free variation selector", 0x180B, true},
		{"mongolian vowel separator", 0x180E, true},
		{"zero width space", 0x200B, true},
		{"zero width non-joiner", 0x200C, true},
		{"zero width joiner", 0x200D, true},
		{"left-to-right mark", 0x200E, true},
		{"right-to-left mark", 0x200F, true},
		{"line separator", 0x2028, true},
		{"paragraph separator", 0x2029, true},
		{"left-to-right embedding", 0x202A, true},
		{"right-to-left override", 0x202E, true},
		{"word joiner", 0x2060, true},
		{"invisible times", 0x2062, true},
		{"unassigned default ignorable", 0x2065, true},
		{"first isolate", 0x2066, true},
		{"pop directional isolate", 0x2069, true},
		{"braille blank", 0x2800, true},
		{"ideographic hangul filler", 0x3164, true},
		{"variation selector 15", 0xFE0E, true},
		{"variation selector 16", 0xFE0F, true},
		{"BOM", 0xFEFF, true},
		{"halfwidth hangul filler", 0xFFA0, true},
		{"unassigned default ignorable FFF0", 0xFFF0, true},
		{"interlinear annotation", 0xFFF9, true},
		{"tag begin", 0xE0001, true},
		{"tag letter", 0xE0041, true},
		{"tag cancel", 0xE007F, true},
		{"unassigned default ignorable E0080", 0xE0080, true},
		{"variation selector supplement", 0xE0100, true},
		{"space", ' ', false},
		{"letter", 'a', false},
		{"digit", '0', false},
		{"dot", '.', false},
		{"slash", '/', false},
		{"backslash", '\\', false},
		{"no-break space", 0x00A0, false},
		{"em space", 0x2003, false},
		{"ideographic space", 0x3000, false},
		{"latin accent", 'é', false},
		{"cyrillic", 'я', false},
		{"arabic letter", 0x0627, false},
		{"persian letter", 0x067E, false},
		{"hebrew letter", 0x05D0, false},
		{"han", '日', false},
		{"combining acute", 0x0301, false},
		{"emoji", 0x1F600, false},
		{"replacement character", 0xFFFD, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsHidden(tt.r); got != tt.want {
				t.Errorf("IsHidden(U+%04X) = %t, want %t", tt.r, got, tt.want)
			}
		})
	}
}

func TestSanitize(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"plain", "report.pdf", "report.pdf"},
		{"bidi override", "invoice\u202Eexe.pdf", "invoice\uFFFDexe.pdf"},
		{"zero width", "a.exe\u200B", "a.exe\uFFFD"},
		{"newline forging a line", "x\n\u202Ey.exe", "x\uFFFD\uFFFDy.exe"},
		{"soft hyphen and BOM", "a\u00AD\uFEFFb", "a\uFFFD\uFFFDb"},
		{"fillers", "a\u3164b\uFFA0c\u2800d", "a\uFFFDb\uFFFDc\uFFFDd"},
		{"variation selector", "a\uFE0Fb", "a\uFFFDb"},
		{"tag characters", "a\U000E0041b", "a\uFFFDb"},
		{"invalid UTF-8", "a\xffb\xc0\xafc", "a\uFFFDb\uFFFD\uFFFDc"},
		{"truncated sequence", "a\xe2\x82", "a\uFFFD\uFFFD"},
		{"literal replacement character", "a\uFFFDb", "a\uFFFDb"},
		{"nbsp and ideographic space", "a\u00A0b\u3000c", "a\u00A0b\u3000c"},
		{"letters, emoji, arabic, combining accent", "é日😀مرحباe\u0301", "é日😀مرحباe\u0301"},
		{"persian joiner", "می\u200Cخواهم", "می\uFFFDخواهم"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Sanitize(tt.in); got != tt.want {
				t.Errorf("Sanitize(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestReplace(t *testing.T) {
	tests := []struct {
		name string
		in   string
		repl rune
		want string
	}{
		{"underscore", "a\u202Eb\nc", '_', "a_b_c"},
		{"drop", "a\u202Eb\nc", -1, "abc"},
		{"drop keeps a literal replacement character", "a\uFFFDb\u200B", -1, "a\uFFFDb"},
		{"invalid UTF-8 is replaced even when dropping", "a\xffb", -1, "a\uFFFDb"},
		{"nothing to replace", "plain", '_', "plain"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Replace(tt.in, tt.repl); got != tt.want {
				t.Errorf("Replace(%q, %q) = %q, want %q", tt.in, tt.repl, got, tt.want)
			}
		})
	}
}

func TestSanitize_largeInput(t *testing.T) {
	in := strings.Repeat("ab\u202E\xff", 1<<18)
	got := Sanitize(in)
	if want := strings.Repeat("ab\uFFFD\uFFFD", 1<<18); got != want {
		t.Errorf("Sanitize of %d bytes differs from the expected text", len(in))
	}
}

func FuzzSanitize(f *testing.F) {
	for _, seed := range []string{"", "plain", "a\u202Eb", "a\xffb", "\u200B\uFE0F\U000E0041", "\uFFFD", "x\ny"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := Sanitize(s)
		if !utf8.ValidString(got) {
			t.Fatalf("Sanitize(%q) = %q is not valid UTF-8", s, got)
		}
		for _, r := range got {
			if IsHidden(r) {
				t.Fatalf("Sanitize(%q) = %q keeps U+%04X", s, got, r)
			}
		}
		if again := Sanitize(got); again != got {
			t.Fatalf("Sanitize is not idempotent: %q then %q", got, again)
		}
	})
}

func ExampleSanitize() {
	fmt.Printf("%q\n", Sanitize("invoice\u202Eexe.pdf"))
	// Output: "invoice�exe.pdf"
}

func ExampleIsHidden() {
	fmt.Println(IsHidden('\u200B'), IsHidden('a'))
	// Output: true false
}

func BenchmarkSanitize(b *testing.B) {
	plain := strings.Repeat("report-2026.pdf", 274)[:4096]
	hidden := plain[:4095] + "\u202E"
	b.Run("plain 4 KiB", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			Sanitize(plain)
		}
	})
	b.Run("hidden 4 KiB", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			Sanitize(hidden)
		}
	})
}
