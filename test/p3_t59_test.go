//go:build linux && e2e

package test

import (
	"slices"
	"strings"
	"testing"
	"unicode/utf8"
)

// namesOf waits until the fake service has been sent the content, and returns
// the names it was sent under.
func (in *instance) namesOf(t *testing.T, content []byte) []string {
	t.Helper()
	in.waitFor(t, "the content to be submitted to the service", func() bool { return len(in.gm.SubmittedNames(content)) > 0 })
	return in.gm.SubmittedNames(content)
}

// T59: a member is submitted to GLIMPS Malware Detect under the host path of
// its archive followed by its path inside it, nested archives included, and
// never under a path of the work folder. A plain file keeps its host path.
func TestE2E_anArchiveMemberIsSubmittedUnderItsArchivePath(t *testing.T) {
	gm := newGMalware(t, false)
	in := startInstance(t, gm, options{extract: true})
	evil := []byte(strings.Repeat("an unknown member of an archive ", 40))
	deep := []byte(strings.Repeat("a member of an archive in an archive ", 40))
	plain := []byte(strings.Repeat("an ordinary deposit ", 40))
	archive := zipOf(t, map[string]string{"d/evil.bin": string(evil)})
	inner := zipOf(t, map[string]string{"sub/x.bin": string(deep)})
	outer := zipOf(t, map[string]string{"inner.zip": string(inner)})
	in.expect.archive(archive, evil)
	in.expect.archive(inner, deep)
	in.expect.archive(outer, deep)
	archivePath := in.drop(t, "a.zip", archive)
	outerPath := in.drop(t, "o/outer.zip", outer)
	plainPath := in.drop(t, "plain.txt", plain)

	want := map[string]struct {
		content []byte
		name    string
	}{
		"member":        {evil, archivePath + "/d/evil.bin"},
		"nested member": {deep, outerPath + "/inner.zip/sub/x.bin"},
		"plain file":    {plain, plainPath},
	}
	for what, w := range want {
		names := in.namesOf(t, w.content)
		if !slices.Equal(names, []string{w.name}) {
			t.Errorf("%s was submitted as %q, want [%q]", what, names, w.name)
		}
		for _, n := range names {
			if strings.Contains(n, in.work) {
				t.Errorf("%s: the label %q holds the work folder %q", what, n, in.work)
			}
			if strings.Contains(n, "..") {
				t.Errorf("%s: the label %q holds a parent reference", what, n)
			}
		}
	}
	in.waitFor(t, "the archives to be delivered", func() bool { return in.inOutput("a.zip") && in.inOutput("o/outer.zip") && in.inOutput("plain.txt") })
	in.waitFor(t, "the session report", func() bool { return in.reportCount() > 0 })
}

// T59 (F6): a label over 4096 bytes is cut to 4096 at most, keeps its tail
// after a leading "…", and stays valid UTF-8.
func TestE2E_aLongLabelIsCappedKeepingTheTail(t *testing.T) {
	gm := newGMalware(t, false)
	in := startInstance(t, gm, options{extract: true})
	evil := []byte(strings.Repeat("a member with a very long path ", 40))
	memberDir := strings.TrimSuffix(strings.Repeat(strings.Repeat("m", 199)+"/", 6), "/")
	member := memberDir + "/last.bin"
	archive := zipOf(t, map[string]string{member: string(evil)})
	in.expect.archive(archive, evil)
	hostDir := strings.TrimSuffix(strings.Repeat(strings.Repeat("h", 199)+"/", 15), "/")
	archivePath := in.drop(t, hostDir+"/a.zip", archive)
	full := archivePath + "/" + member
	if len(full) <= 4096 {
		t.Fatalf("the label is only %d bytes: the cap is not exercised", len(full))
	}
	names := in.namesOf(t, evil)
	if len(names) != 1 {
		t.Fatalf("names = %d, want 1", len(names))
	}
	label := names[0]
	if len(label) > 4096 {
		t.Errorf("label of %d bytes, want at most 4096", len(label))
	}
	if len(label) < 4096-8 {
		t.Errorf("label of %d bytes: cut much more than needed", len(label))
	}
	if !strings.HasPrefix(label, "…") {
		t.Errorf("label starts with %.20q, want the ellipsis", label)
	}
	if !utf8.ValidString(label) {
		t.Error("label is not valid UTF-8")
	}
	if tail := strings.TrimPrefix(label, "…"); !strings.HasSuffix(full, tail) || !strings.HasSuffix(label, "/last.bin") {
		t.Errorf("label does not keep the tail of the path: ends with %q", label[max(0, len(label)-40):])
	}
}
