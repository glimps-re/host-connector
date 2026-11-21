package handler

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// What a log line, a console line or an event tells of names that someone else
// writes (the keys of a configuration, the entries of a plugins file) is bounded
// after it is quoted: a byte that is not printable takes up to six bytes once it
// is escaped, so a bound on the raw text bounds nothing.
const (
	maxReportedKeys    = 50
	maxReportedKeyLen  = 256
	maxReportedNameLen = 100
	maxReportedFileLen = 130
)

// truncationMark tells that a quoted text was cut.
const truncationMark = "..."

// quoteBounded quotes s as %q does, rune by rune, and stops, with a mark, before
// the quoted text goes over budget bytes. What it returns is valid UTF-8 and
// holds no raw control, invisible or bidirectional character; a byte that is not
// valid UTF-8 is written as \xNN.
func quoteBounded(s string, budget int) string {
	escapes := make([]string, 0, min(len(s), budget))
	total := 2 // the quotes
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		var escaped string
		if r == utf8.RuneError && size == 1 {
			escaped = fmt.Sprintf(`\x%02x`, s[i])
		} else {
			quoted := strconv.Quote(string(r))
			escaped = quoted[1 : len(quoted)-1]
		}
		escapes = append(escapes, escaped)
		total += len(escaped)
		i += size
		if total > budget {
			break // what follows is cut, and the text is known not to fit
		}
	}
	var b strings.Builder
	b.WriteByte('"')
	if total <= budget {
		for _, e := range escapes {
			b.WriteString(e)
		}
	} else {
		used := 2 + len(truncationMark) // the quotes and the mark
		for _, e := range escapes {
			if used+len(e) > budget {
				break
			}
			b.WriteString(e)
			used += len(e)
		}
		b.WriteString(truncationMark)
	}
	b.WriteByte('"')
	return b.String()
}

// boundedList joins at most maxReportedKeys items and says how many more there are.
func boundedList(items []string) string {
	if len(items) <= maxReportedKeys {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:maxReportedKeys], ", ") + fmt.Sprintf(", ... and %d more", len(items)-maxReportedKeys)
}

// quoteKeys quotes each key, within maxReportedKeyLen bytes.
func quoteKeys(keys []string) []string {
	out := make([]string, len(keys))
	for i, k := range keys {
		out[i] = quoteBounded(k, maxReportedKeyLen)
	}
	return out
}
