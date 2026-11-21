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
// the quoted text goes over budget bytes (at least the quotes and the mark, which
// is what a smaller budget gets). What it returns is valid UTF-8 and
// holds no raw control, invisible or bidirectional character; a byte that is not
// valid UTF-8 is written as \xNN.
func quoteBounded(s string, budget int) string {
	budget = max(budget, 2+len(truncationMark)) // the quotes and the mark: nothing shorter says anything
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
	return joinCounted(items[:min(len(items), maxReportedKeys)], len(items))
}

// boundedKeys quotes, within maxReportedKeyLen bytes each, the first
// maxReportedKeys keys only, and says how many more there are: the keys come from
// the network, and a document of many of them must cost no more than its first 50.
func boundedKeys(keys []string) string {
	shown := make([]string, min(len(keys), maxReportedKeys))
	for i := range shown {
		shown[i] = quoteBounded(keys[i], maxReportedKeyLen)
	}
	return joinCounted(shown, len(keys))
}

// joinCounted joins the items shown, of total, and says how many were left out.
func joinCounted(shown []string, total int) string {
	list := strings.Join(shown, ", ")
	if total > len(shown) {
		list += fmt.Sprintf(", ... and %d more", total-len(shown))
	}
	return list
}
