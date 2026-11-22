//go:build linux && e2e

package test

import (
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
)

// consoleLinesOf returns the lines of the process output that describe a file.
func (in *instance) consoleLinesOf(marker string) (lines []string) {
	for line := range strings.SplitSeq(in.stderr.String(), "\n") {
		if strings.HasPrefix(line, "time: ") && strings.Contains(line, marker) {
			lines = append(lines, line)
		}
	}
	return lines
}

// T66: a name with a bidirectional override is submitted with "_" in its place,
// printed with U+FFFD, and kept raw in the JSON report.
func TestE2E_aBidiOverrideInANameIsMaskedForTheServiceAndTheConsoleOnly(t *testing.T) {
	gm := newGMalware(t, false)
	in := startInstance(t, gm, options{})
	content := []byte("a malware whose name reverses the extension on display")
	gm.MarkMalicious(content)
	in.expect.flag(content)
	path := in.drop(t, "invoice\u202eexe.pdf", content)
	in.quarantinedFile(t, path, content)
	in.waitFor(t, "the session report", func() bool { return in.reportCount() > 0 })

	names := in.namesOf(t, content)
	if len(names) == 0 || !strings.HasSuffix(names[0], "/invoice_exe.pdf") || strings.ContainsRune(names[0], '\u202e') {
		t.Errorf("submitted names = %q, want one ending in /invoice_exe.pdf with no U+202E", names)
	}
	in.waitFor(t, "the console line of the file", func() bool { return len(in.consoleLinesOf("sha256: "+sha256Hex(content))) > 0 })
	for _, line := range in.consoleLinesOf("sha256: " + sha256Hex(content)) {
		if strings.ContainsRune(line, '\u202e') {
			t.Errorf("the console line holds the raw override: %q", line)
		}
		if !strings.Contains(line, "invoice�exe.pdf") {
			t.Errorf("the console line does not show U+FFFD in place of the override: %q", line)
		}
	}
	if !in.reportHas(t, content, func(e datamodel.Report) bool { return e.Filename == path && strings.ContainsRune(e.Filename, '\u202e') }) {
		t.Errorf("the JSON report does not keep the raw name %q: %+v", path, in.reportsOf(t, content))
	}
}

// T66: a newline hides in a name as well: one console line per file.
func TestE2E_aNewlineAndAnOverrideInANameMakeOneConsoleLine(t *testing.T) {
	gm := newGMalware(t, false)
	in := startInstance(t, gm, options{})
	content := []byte("a malware whose name tries to forge a second console line")
	gm.MarkMalicious(content)
	in.expect.flag(content)
	path := in.drop(t, "x\ntime: forged\u202ey.exe", content)
	in.quarantinedFile(t, path, content)
	in.waitFor(t, "the console line of the file", func() bool { return len(in.consoleLinesOf("sha256: "+sha256Hex(content))) > 0 })
	if got := in.consoleLinesOf("sha256: " + sha256Hex(content)); len(got) != 1 || !strings.Contains(got[0], "x�time: forged�y.exe") {
		t.Errorf("console lines = %q, want one with both runes shown as U+FFFD", got)
	}
	if strings.Contains(in.stderr.String(), "\ntime: forged") {
		t.Error("the name forged a console line of its own")
	}
}

// T66: a member whose name ends with a zero-width space does not escape
// `\.exe$`: the archive is refused and the member is named in the report.
func TestE2E_aZeroWidthSpaceAfterTheExtensionDoesNotEscapeAForbiddenPath(t *testing.T) {
	gm := newGMalware(t, false)
	in := startInstance(t, gm, options{extract: true, config: pathFilter([]string{`\.exe$`}, nil)})
	member := []byte(strings.Repeat("an executable that hides its extension ", 40))
	other := []byte(strings.Repeat("a harmless member ", 40))
	archive := zipOf(t, map[string]string{"a.exe\u200b": string(member), "b.txt": string(other)})
	in.expect.flag(member)
	in.expect.archive(archive, member, other)
	path := in.drop(t, "a.zip", archive)
	in.quarantinedFile(t, path, archive)
	in.waitFor(t, "the session report", func() bool { return in.reportCount() > 0 })
	if !in.reportHas(t, archive, func(e datamodel.Report) bool {
		return slices.ContainsFunc(e.MaliciousExtractedFiles, func(m datamodel.ExtractedFile) bool {
			return strings.Contains(m.FileName, "a.exe") && m.MalwareReason == datamodel.FilteredFilePath
		})
	}) {
		t.Errorf("the member a.exe+U+200B is not named with the reason %s: %+v", datamodel.FilteredFilePath, in.reportsOf(t, archive))
	}
}

// T66: the folded form of a name (hidden runes removed) can only add a
// refusal, never widen a skip. `/tom/a\.log$` matches a.log, and the folded form
// of a<U+200B>.log, but not its raw or sanitized form: the file is analyzed.
// The unanchored `\.log$` matches every form: that file is skipped.
func TestE2E_theFoldedNameDoesNotWidenASkipRule(t *testing.T) {
	gm := newGMalware(t, false)
	in := startInstance(t, gm, options{config: pathFilter(nil, []string{`/tom/a\.log$`, `/tom/skipped/.*\.log$`})})
	in.expect.allow(datamodel.NotAnalyzedPolicySkipped)
	hidden := []byte("a file whose hidden rune must not make it match the skip rule")
	plain := []byte("a file the skip rule matches in every form")
	in.drop(t, "a\u200b.log", hidden)
	in.drop(t, "skipped/b\u200b.log", plain)
	in.waitFor(t, "both files to be delivered", func() bool { return in.inOutput("a\u200b.log") && in.inOutput("skipped/b\u200b.log") })
	in.waitFor(t, "the session report", func() bool { return in.reportCount() > 0 })
	if _, ok := gm.Given(sha256Hex(hidden)); !ok {
		t.Error("the file whose raw name escapes the skip rule was not analyzed")
	}
	if in.reportHas(t, hidden, func(e datamodel.Report) bool { return e.NotAnalyzedReason == datamodel.NotAnalyzedPolicySkipped }) {
		t.Error("the folded form widened the skip rule")
	}
	if _, ok := gm.Given(sha256Hex(plain)); ok {
		t.Error("a file matched by the skip rule in every form was analyzed")
	}
	if !in.reportHas(t, plain, func(e datamodel.Report) bool { return e.NotAnalyzedReason == datamodel.NotAnalyzedPolicySkipped }) {
		t.Error("the file matched in every form is not reported as skipped")
	}
}

// T66: a skip needs every form of the name to match. The folded form drops the
// invalid byte of "trusted\xff", so `trusted[_\x{FFFD}]` no longer matches it: the
// file is analyzed, not skipped.
func TestE2E_aSkipRuleThatOnlyMatchesTheMangledFolderNoLongerSkips(t *testing.T) {
	gm := newGMalware(t, false)
	in := startInstance(t, gm, options{config: pathFilter(nil, []string{"/tom/trusted[_\\x{FFFD}]/"})})
	in.expect.allow(datamodel.NotAnalyzedPolicySkipped)
	content := []byte("a file in a folder whose name is not valid UTF-8")
	in.drop(t, "trusted\xff/x.txt", content)
	in.waitFor(t, "the file to be delivered", func() bool { return in.inOutput("trusted\xff/x.txt") })
	in.waitFor(t, "the session report", func() bool { return in.reportCount() > 0 })
	if _, ok := gm.Given(sha256Hex(content)); !ok {
		t.Error("the file was not analyzed")
	}
	if in.reportHas(t, content, func(e datamodel.Report) bool { return e.NotAnalyzedReason == datamodel.NotAnalyzedPolicySkipped }) {
		t.Error("the file was skipped by a rule that its folded name alone matches")
	}
}

// T66: the file name is quoted on the console line: a name that looks like the
// next fields stays inside the quotes, a quote in it is escaped.
func TestE2E_aNameThatImitatesTheNextFieldsStaysInsideTheQuotes(t *testing.T) {
	gm := newGMalware(t, false)
	in := startInstance(t, gm, options{})
	for rel, content := range map[string][]byte{
		"x, flagged: false":              []byte("a malware named like a console field"),
		"y\", sha256: 0, flagged: false": []byte("a malware named like a console field, with a quote"),
	} {
		gm.MarkMalicious(content)
		in.expect.flag(content)
		path := in.drop(t, rel, content)
		in.quarantinedFile(t, path, content)
		marker := "sha256: " + sha256Hex(content)
		in.waitFor(t, "the console line of "+rel, func() bool { return len(in.consoleLinesOf(marker)) > 0 })
		lines := in.consoleLinesOf(marker)
		if len(lines) != 1 {
			t.Fatalf("console lines of %q = %q, want one", rel, lines)
		}
		quoted := strconv.Quote(path)
		prefix := "file: " + quoted + ", sha256: " + sha256Hex(content) + ", flagged: true, "
		if !strings.Contains(lines[0], prefix) {
			t.Errorf("the console line does not hold the quoted name followed by the real fields (%q): %q", prefix, lines[0])
		}
	}
}

// T66: a variation selector after the extension does not escape `\.exe$`.
func TestE2E_aVariationSelectorAfterTheExtensionDoesNotEscapeAForbiddenPath(t *testing.T) {
	gm := newGMalware(t, false)
	in := startInstance(t, gm, options{extract: true, config: pathFilter([]string{`\.exe$`}, nil)})
	member := []byte(strings.Repeat("an executable followed by a variation selector ", 40))
	other := []byte(strings.Repeat("a harmless member next to it ", 40))
	archive := zipOf(t, map[string]string{"a.exe️": string(member), "b.txt": string(other)})
	in.expect.flag(member)
	in.expect.archive(archive, member, other)
	path := in.drop(t, "v.zip", archive)
	in.quarantinedFile(t, path, archive)
	in.waitFor(t, "the session report", func() bool { return in.reportCount() > 0 })
	if !in.reportHas(t, archive, func(e datamodel.Report) bool {
		return slices.ContainsFunc(e.MaliciousExtractedFiles, func(m datamodel.ExtractedFile) bool {
			return strings.Contains(m.FileName, "a.exe") && m.MalwareReason == datamodel.FilteredFilePath
		})
	}) {
		t.Errorf("the member a.exe+U+FE0F is not named with the reason %s: %+v", datamodel.FilteredFilePath, in.reportsOf(t, archive))
	}
}
