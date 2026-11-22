package scanner

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	gdetectMock "github.com/glimps-re/go-gdetect/pkg/gdetect/mock"
	quarantineMock "github.com/glimps-re/host-connector/pkg/quarantine/mock"
)

// The name sent with a submission carries no control character, which the service
// refuses in a header, and is otherwise the path of the file.
func TestAnalyze_theSubmittedNameHasNoControlCharacter(t *testing.T) {
	tests := []struct {
		name string
		file string
		want string
	}{
		{"a normal name", "plain.txt", "plain.txt"},
		{"a control character", "a\x01b.txt", "a_b.txt"},
		{"a line feed", "a\nb.txt", "a_b.txt"},
		{"DEL", "a\x7fb.txt", "a_b.txt"},
		{"a C1 control (NEL)", "a\u0085b.txt", "a_b.txt"},
		{"a line separator", "a\u2028b.txt", "a_b.txt"},
		{"a paragraph separator", "a\u2029b.txt", "a_b.txt"},
		{"invalid UTF-8", "a\xffb.txt", "a\ufffdb.txt"},
		{"a quote and a backslash", "a\"b\\c.txt", "a\"b\\c.txt"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			noOpenInputs(t)
			in := t.TempDir()
			file := filepath.Join(in, tt.file)
			if err := os.WriteFile(file, []byte("content to analyze"), 0o600); err != nil {
				t.Fatal(err)
			}
			var mu sync.Mutex
			var sent []string
			submitter := readerTrio(&gdetectMock.MockGDetectSubmitter{
				ExtractExpertViewURLMock: func(*gdetect.Result) (string, error) { return "", nil },
				WaitForReaderMock: func(_ context.Context, _ io.Reader, opts gdetect.WaitForOptions) (gdetect.Result, error) {
					mu.Lock()
					defer mu.Unlock()
					sent = append(sent, opts.Filename)
					return gdetect.Result{}, nil
				},
			})
			quarantiner := &quarantineMock.QuarantineMock{
				IsRestoredMock: func(context.Context, string, string) (bool, error) { return false, nil },
			}
			c, err := NewConnector(Config{Roots: []string{in}, WorkDir: t.TempDir(), Workers: 1}, quarantiner, submitter)
			if err != nil {
				t.Fatal(err)
			}
			got := &outcomes{}
			c.config.OnFileDone = got.add
			if err = c.Start(); err != nil {
				t.Fatal(err)
			}
			if err = c.ScanFile(t.Context(), file); err != nil {
				t.Fatal(err)
			}
			waitUntil(t, "the file to end", func() bool { return len(got.get()) == 1 })
			c.Close(t.Context())
			mu.Lock()
			defer mu.Unlock()
			if len(sent) != 1 || sent[0] != filepath.Join(in, tt.want) {
				t.Errorf("names sent = %q, want %q", sent, filepath.Join(in, tt.want))
			}
		})
	}
}

// The submission of a file that no descriptor holds (a member of an archive) goes
// by WaitForFile: its name is cleaned as well.
func TestAnalyze_theNameOfAFileSubmittedByPathHasNoControlCharacter(t *testing.T) {
	file := filepath.Join(t.TempDir(), "a\x01b\u2028c.txt")
	if err := os.WriteFile(file, []byte("content to analyze"), 0o600); err != nil {
		t.Fatal(err)
	}
	var sent []string
	submitter := &gdetectMock.MockGDetectSubmitter{
		ExtractExpertViewURLMock: func(*gdetect.Result) (string, error) { return "", nil },
		WaitForFileMock: func(_ context.Context, _ string, opts gdetect.WaitForOptions) (gdetect.Result, error) {
			sent = append(sent, opts.Filename)
			return gdetect.Result{SHA256: "sha"}, nil
		},
	}
	c, err := NewConnector(Config{Roots: []string{filepath.Dir(file)}, WorkDir: t.TempDir(), Workers: 1}, &quarantineMock.QuarantineMock{}, submitter)
	if err != nil {
		t.Fatal(err)
	}
	size := int64(len("content to analyze"))
	res := c.analyze(fileToAnalyze{filename: "m", location: file, sha256: "sha", size: size}, nil)
	want := filepath.Join(filepath.Dir(file), "a_b_c.txt")
	if res.Error != nil || len(sent) != 1 || sent[0] != want {
		t.Errorf("error %v, names sent %q, want one, %q", res.Error, sent, want)
	}
}

func TestSubmissionLabel_isCappedKeepingTheTail(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{"ascii", strings.Repeat("d/", 2500) + "evil.exe"},
		{"2-byte runes on the cut", strings.Repeat("é", 3000) + "/evil.exe"},
		{"2-byte runes, shifted by one", "p" + strings.Repeat("é", 3000) + "/evil.exe"},
		{"3-byte runes on the cut", strings.Repeat("€", 2000) + "/evil.exe"},
		{"3-byte runes, shifted by one", "p" + strings.Repeat("€", 2000) + "/evil.exe"},
		{"3-byte runes, shifted by two", "pp" + strings.Repeat("€", 2000) + "/evil.exe"},
		{"4-byte runes on the cut", strings.Repeat("\U0001F600", 2000) + "/evil.exe"},
		{"4-byte runes, shifted by one", "p" + strings.Repeat("\U0001F600", 2000) + "/evil.exe"},
		{"4-byte runes, shifted by two", "pp" + strings.Repeat("\U0001F600", 2000) + "/evil.exe"},
		{"4-byte runes, shifted by three", "ppp" + strings.Repeat("\U0001F600", 2000) + "/evil.exe"},
		{"exactly the bound", strings.Repeat("a", maxSubmissionLabel)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := submissionLabel(tt.in)
			if len(got) > maxSubmissionLabel {
				t.Errorf("len = %d, want <= %d", len(got), maxSubmissionLabel)
			}
			if !utf8.ValidString(got) {
				t.Errorf("label is not valid UTF-8")
			}
			if len(tt.in) <= maxSubmissionLabel {
				if got != tt.in {
					t.Errorf("a label within the bound must be unchanged")
				}
				return
			}
			if !strings.HasPrefix(got, "…") || !strings.HasSuffix(got, "/evil.exe") {
				t.Errorf("label = %.20q…%.20q, want an ellipsis, then the tail", got, got[len(got)-20:])
			}
		})
	}
}

func TestSubmissionLabel_aMemberIsLabeledWithItsPathInTheArchive(t *testing.T) {
	const workDir = "/work/x-1234"
	archive := fileToAnalyze{location: "/in/a.zip", logicalPath: "/in/a.zip", archiveID: "id"}
	member := func(parent fileToAnalyze, rel string) fileToAnalyze {
		logical := memberLogicalPath(parent.logical(), rel, true, workDir+"/"+rel)
		f := fileToAnalyze{location: workDir + "/" + rel, archiveID: "id", logicalPath: logical}
		if raw := memberRawPath(parent.rawLogical(), rel, true, f.location); raw != logical {
			f.rawPath = raw
		}
		return f
	}
	nested := member(archive, "sub.zip")
	tests := []struct {
		name string
		in   fileToAnalyze
		want string
	}{
		{"a plain file keeps its host path", fileToAnalyze{location: "/in/alice/plain.exe"}, "/in/alice/plain.exe"},
		{"a member", member(archive, "d/m.exe"), "/in/a.zip/d/m.exe"},
		{"a member of a nested archive", member(nested, "x.exe"), "/in/a.zip/sub.zip/x.exe"},
		{"a newline in a member name", member(archive, "d/a\nb.exe"), "/in/a.zip/d/a_b.exe"},
		{"invalid UTF-8 in a member name", member(archive, "d/a\xffb.exe"), "/in/a.zip/d/a\ufffdb.exe"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := submissionLabel(tt.in.rawLogical())
			if got != tt.want {
				t.Errorf("label = %q, want %q", got, tt.want)
			}
			if strings.Contains(got, workDir) {
				t.Errorf("label %q holds the work folder", got)
			}
		})
	}
}

func TestAnalyze_theSubmittedNameOfAMemberHoldsNoWorkFolder(t *testing.T) {
	work := t.TempDir()
	file := filepath.Join(work, "x-1", "d", "evil.bin")
	if err := os.MkdirAll(filepath.Dir(file), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("content to analyze"), 0o600); err != nil {
		t.Fatal(err)
	}
	var sent []string
	submitter := &gdetectMock.MockGDetectSubmitter{
		ExtractExpertViewURLMock: func(*gdetect.Result) (string, error) { return "", nil },
		WaitForFileMock: func(_ context.Context, _ string, opts gdetect.WaitForOptions) (gdetect.Result, error) {
			sent = append(sent, opts.Filename)
			return gdetect.Result{SHA256: "sha"}, nil
		},
	}
	c, err := NewConnector(Config{Roots: []string{"/in"}, WorkDir: work, Workers: 1}, &quarantineMock.QuarantineMock{}, submitter)
	if err != nil {
		t.Fatal(err)
	}
	member := fileToAnalyze{
		filename: "d/evil.bin", location: file, sha256: "sha", size: int64(len("content to analyze")),
		archiveID: "id", logicalPath: "/in/a.zip/d/evil.bin", archiveLocation: "/in/a.zip", archiveTopLocation: "/in/a.zip",
	}
	res := c.analyze(member, nil)
	if res.Error != nil || len(sent) != 1 || sent[0] != "/in/a.zip/d/evil.bin" {
		t.Errorf("error %v, names sent %q, want one, /in/a.zip/d/evil.bin", res.Error, sent)
	}
}

func TestSubmissionLabel_hiddenRunes(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"right-to-left override", "invoice\u202Eexe.pdf", "invoice_exe.pdf"},
		{"isolate", "a\u2066b\u2069c", "a_b_c"},
		{"zero width space", "a.exe\u200B", "a.exe_"},
		{"soft hyphen", "a\u00ADb", "a_b"},
		{"filler", "a\u3164b", "a_b"},
		{"variation selector", "a\uFE0Fb", "a_b"},
		{"tag character", "a\U000E0041b", "a_b"},
		{"line separator", "a\u2028b", "a_b"},
		{"bidi in a folder name", "/in/dir\u202Egpj/file.txt", "/in/dir_gpj/file.txt"},
		{"invalid UTF-8", "a\xffb", "a\uFFFDb"},
		{"nbsp and emoji kept", "a\u00A0b\U0001F600", "a\u00A0b\U0001F600"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := submissionLabel(tt.in); got != tt.want {
				t.Errorf("submissionLabel(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestSubmissionLabel_hiddenRunesAreCappedKeepingTheTail(t *testing.T) {
	in := strings.Repeat("\u202E/", 3000) + "evil.exe"
	got := submissionLabel(in)
	if len(got) > maxSubmissionLabel || !strings.HasSuffix(got, "evil.exe") || strings.Contains(got, "\u202E") {
		t.Errorf("label of %d bytes, tail kept %v, bidi left %v", len(got), strings.HasSuffix(got, "evil.exe"), strings.Contains(got, "\u202E"))
	}
}
