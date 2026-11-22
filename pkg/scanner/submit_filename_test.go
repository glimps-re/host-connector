package scanner

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"

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
