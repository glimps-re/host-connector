//go:build linux && (e2e || e2e_core)

package core

import (
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/test/internal/fakes/gmalware"
	"github.com/glimps-re/host-connector/test/internal/harness"
)

// consoleLinesOf returns the lines of the process output that describe a file.
func consoleLinesOf(in *harness.Instance, marker string) (lines []string) {
	for line := range strings.SplitSeq(in.Stderr.String(), "\n") {
		if strings.HasPrefix(line, "time: ") && strings.Contains(line, marker) {
			lines = append(lines, line)
		}
	}
	return lines
}

// p3/T66: a name with a bidirectional override is submitted with "_" in its place,
// printed with U+FFFD, and kept raw in the JSON report.
func TestE2E_aBidiOverrideInANameIsMaskedForTheServiceAndTheConsoleOnly(t *testing.T) {
	content := []byte("a malware whose name reverses the extension on display")
	in := harness.Run(t, harness.Scenario{
		Files: []harness.File{{Path: "invoice\u202eexe.pdf", Content: content, Verdict: harness.Malicious}},
		Want: map[string]harness.Outcome{
			"invoice\u202eexe.pdf": {In: harness.Quarantine, Malware: datamodel.MalwareDetected, SubmittedAs: []string{"invoice_exe.pdf"}},
		},
	})
	marker := "sha256: " + gmalware.SHA256Hex(content)
	in.WaitFor(t, "the console line of the file", func() bool { return len(consoleLinesOf(in, marker)) > 0 })
	for _, line := range consoleLinesOf(in, marker) {
		if strings.ContainsRune(line, '\u202e') {
			t.Errorf("the console line holds the raw override: %q", line)
		}
		if !strings.Contains(line, "invoice�exe.pdf") {
			t.Errorf("the console line does not show U+FFFD in place of the override: %q", line)
		}
	}
}

// p3/T66: a newline hides in a name as well: one console line per file.
func TestE2E_aNewlineAndAnOverrideInANameMakeOneConsoleLine(t *testing.T) {
	content := []byte("a malware whose name tries to forge a second console line")
	in := harness.Run(t, harness.Scenario{
		Files: []harness.File{{Path: "x\ntime: forged\u202ey.exe", Content: content, Verdict: harness.Malicious}},
		Want: map[string]harness.Outcome{
			"x\ntime: forged\u202ey.exe": {In: harness.Quarantine, Malware: datamodel.MalwareDetected},
		},
	})
	marker := "sha256: " + gmalware.SHA256Hex(content)
	in.WaitFor(t, "the console line of the file", func() bool { return len(consoleLinesOf(in, marker)) > 0 })
	if got := consoleLinesOf(in, marker); len(got) != 1 || !strings.Contains(got[0], "x�time: forged�y.exe") {
		t.Errorf("console lines = %q, want one with both runes shown as U+FFFD", got)
	}
	if strings.Contains(in.Stderr.String(), "\ntime: forged") {
		t.Error("the name forged a console line of its own")
	}
}

// p3/T66: the file name is quoted on the console line: a name that looks like the
// next fields stays inside the quotes, a quote in it is escaped.
func TestE2E_aNameThatImitatesTheNextFieldsStaysInsideTheQuotes(t *testing.T) {
	files := []harness.File{
		{Path: "x, flagged: false", Content: []byte("a malware named like a console field"), Verdict: harness.Malicious},
		{Path: "y\", sha256: 0, flagged: false", Content: []byte("a malware named like a console field, with a quote"), Verdict: harness.Malicious},
	}
	in := harness.Run(t, harness.Scenario{
		Files: files,
		Want: map[string]harness.Outcome{
			"x, flagged: false":              {In: harness.Quarantine, Malware: datamodel.MalwareDetected},
			"y\", sha256: 0, flagged: false": {In: harness.Quarantine, Malware: datamodel.MalwareDetected},
		},
	})
	for _, f := range files {
		marker := "sha256: " + gmalware.SHA256Hex(f.Content)
		in.WaitFor(t, "the console line of "+f.Path, func() bool { return len(consoleLinesOf(in, marker)) > 0 })
		lines := consoleLinesOf(in, marker)
		if len(lines) != 1 {
			t.Fatalf("console lines of %q = %q, want one", f.Path, lines)
		}
		quoted := strconv.Quote(filepath.Join(in.Input, "tom", f.Path))
		prefix := "file: " + quoted + ", sha256: " + gmalware.SHA256Hex(f.Content) + ", flagged: true, "
		if !strings.Contains(lines[0], prefix) {
			t.Errorf("the console line does not hold the quoted name followed by the real fields (%q): %q", prefix, lines[0])
		}
	}
}
