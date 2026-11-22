package quarantine

import (
	"strings"
	"unicode/utf8"

	"github.com/glimps-re/host-connector/internal/displaytext"
)

// maxEntryNameBytes caps a sanitised ZIP payload entry name.
const maxEntryNameBytes = 200

// windowsReservedNames are the device names Windows treats specially
// regardless of extension (CON, CON.txt, con.tar.gz, ... are all reserved).
var windowsReservedNames = map[string]bool{
	"CON": true, "PRN": true, "AUX": true, "NUL": true,
	"COM1": true, "COM2": true, "COM3": true, "COM4": true, "COM5": true,
	"COM6": true, "COM7": true, "COM8": true, "COM9": true,
	"LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true, "LPT5": true,
	"LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true,
}

// isASCIILetter reports whether b is an ASCII letter, used only to detect a
// Windows-style drive letter prefix ("C:").
func isASCIILetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// sanitizeEntryName derives a safe ZIP payload entry name from original,
// the untrusted (possibly attacker-chosen) original file path: basename only; no path separators, drive
// letters, or "." / ".." traversal tokens; no C0/C1 control or
// bidirectional-override characters; Windows reserved device names
// rewritten (with or without an extension); no trailing dots or spaces;
// capped length; guaranteed valid UTF-8; never "index.json" (the sibling
// cleartext entry) and never empty.
//
// This is display/compatibility sanitisation only: the authoritative
// original path is always the cleartext index (LockIndex.Filepath), never
// this entry name, and restore matches the payload by the index's Entry
// field rather than by re-deriving it from the (possibly renamed) name on
// disk.
func sanitizeEntryName(original string) string {
	name := original
	if idx := strings.LastIndexAny(name, `/\`); idx >= 0 {
		name = name[idx+1:]
	}
	if len(name) >= 2 && name[1] == ':' && isASCIILetter(name[0]) {
		name = name[2:]
	}

	var b strings.Builder
	b.Grow(len(name))
	for _, r := range name {
		switch {
		case r == utf8.RuneError:
			b.WriteRune('_')
		case displaytext.IsHidden(r):
		default:
			b.WriteRune(r)
		}
	}
	name = strings.TrimRight(b.String(), ". ")

	if name == "" || name == "." || name == ".." {
		return "payload.bin"
	}

	name = rewriteIfWindowsReserved(name)

	if len(name) > maxEntryNameBytes {
		name = truncateUTF8(name, maxEntryNameBytes)
		name = strings.TrimRight(name, ". ")
		if name == "" {
			return "payload.bin"
		}
	}

	// Case-insensitive: Windows Explorer/7-Zip extract onto case-insensitive
	// (though case-preserving) filesystems, so "INDEX.JSON" would otherwise
	// collide with the cleartext index entry once extracted, defeating the
	// no-password-needed listing/inspection workflow this format exists for.
	if strings.EqualFold(name, "index.json") {
		return "payload.bin"
	}
	return name
}

// rewriteIfWindowsReserved prefixes name with "_" if its extension-free
// component (case-insensitively) is a Windows reserved device name.
func rewriteIfWindowsReserved(name string) string {
	base := name
	if i := strings.IndexByte(base, '.'); i >= 0 {
		base = base[:i]
	}
	if windowsReservedNames[strings.ToUpper(base)] {
		return "_" + name
	}
	return name
}

// truncateUTF8 truncates s to at most maxBytes bytes without splitting a
// multi-byte UTF-8 sequence.
func truncateUTF8(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	for maxBytes > 0 && !utf8.RuneStart(s[maxBytes]) {
		maxBytes--
	}
	return s[:maxBytes]
}
