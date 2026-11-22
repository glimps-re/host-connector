// Package displaytext tells which runes of an untrusted text must not be displayed as they are.
package displaytext

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// IsHidden reports whether r must not reach a display as it is: the Unicode
// default-ignorable code points (format characters, variation selectors, fillers
// that draw as blanks), control characters, U+2028, U+2029 and U+2800.
func IsHidden(r rune) bool {
	if r < utf8.RuneSelf {
		return r < 0x20 || r == 0x7f
	}
	return unicode.IsControl(r) ||
		unicode.Is(unicode.Cf, r) ||
		unicode.Is(unicode.Variation_Selector, r) ||
		unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r) ||
		r == 0x2028 || r == 0x2029 || r == 0x2800
}

// Replace returns s with each hidden rune replaced by repl, or dropped when repl
// is negative. Each byte of invalid UTF-8 becomes U+FFFD. It allocates only when
// s changes.
func Replace(s string, repl rune) string {
	return strings.Map(func(r rune) rune {
		if IsHidden(r) {
			return repl
		}
		return r
	}, s)
}

// Sanitize returns s with each hidden rune, and each byte of invalid UTF-8, replaced by U+FFFD.
func Sanitize(s string) string {
	return Replace(s, utf8.RuneError)
}
