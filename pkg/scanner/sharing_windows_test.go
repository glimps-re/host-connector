//go:build windows

package scanner

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	gdetectMock "github.com/glimps-re/go-gdetect/pkg/gdetect/mock"
	"github.com/glimps-re/host-connector/pkg/quarantine"
)

const windowsMalware = "MALWARE: quarantined then deleted"

// TestPipeline_filesAreMovedQuarantinedAndDeletedWithoutSharingErrors checks
// that the descriptor of a file is closed before the actions: a file opened
// without delete sharing can be neither renamed nor removed on Windows.
func TestPipeline_filesAreMovedQuarantinedAndDeletedWithoutSharingErrors(t *testing.T) {
	tests := []struct {
		name         string
		clean, bad   string
		cleanContent string
	}{
		{name: "a clean file moved and a malware quarantined then deleted", clean: "clean.txt", bad: "bad.exe", cleanContent: "harmless"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			in, out, qdir := filepath.Join(root, "in"), filepath.Join(root, "out"), filepath.Join(root, "quarantine")
			for _, d := range []string{in, out, qdir} {
				if err := os.MkdirAll(d, 0o750); err != nil {
					t.Fatal(err)
				}
			}
			clean := filepath.Join(in, tt.clean)
			bad := filepath.Join(in, tt.bad)
			if err := os.WriteFile(clean, []byte(tt.cleanContent), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(bad, []byte(windowsMalware), 0o600); err != nil {
				t.Fatal(err)
			}
			verdict := func(content string) (gdetect.Result, error) {
				return gdetect.Result{Malware: strings.HasPrefix(content, "MALWARE")}, nil
			}
			submitter := &gdetectMock.MockGDetectSubmitter{
				ExtractExpertViewURLMock: func(*gdetect.Result) (string, error) { return "", nil },
				WaitForFileMock: func(_ context.Context, path string, _ gdetect.WaitForOptions) (gdetect.Result, error) {
					b, err := os.ReadFile(filepath.Clean(path))
					if err != nil {
						return gdetect.Result{}, err
					}
					return verdict(string(b))
				},
				WaitForReaderMock: func(_ context.Context, r io.Reader, _ gdetect.WaitForOptions) (gdetect.Result, error) {
					b, err := io.ReadAll(r)
					if err != nil {
						return gdetect.Result{}, err
					}
					return verdict(string(b))
				},
			}
			// The core submits through GetResultBySHA256, SubmitReader and
			// GetResultByUUIDWithWait: readerTrio plays them from WaitForReaderMock.
			readerTrio(submitter)
			quarantiner, err := quarantine.NewQuarantineHandler(t.Context(), quarantine.Config{Location: qdir, LockPassword: "infected"})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if e := quarantiner.Close(); e != nil {
					t.Errorf("Close() error = %v", e)
				}
			})
			c, err := NewConnector(Config{
				Roots:    []string{in},
				WorkDir:  t.TempDir(),
				Workers:  1,
				Actions:  Actions{Move: true, Quarantine: true, Deleted: true},
				MoveFrom: in,
				MoveTo:   out,
			}, quarantiner, submitter)
			if err != nil {
				t.Fatal(err)
			}
			if err = c.Start(); err != nil {
				t.Fatal(err)
			}
			for _, p := range []string{clean, bad} {
				if err = c.ScanFile(t.Context(), p); err != nil {
					t.Fatalf("ScanFile(%s) error = %v", p, err)
				}
			}
			c.Close(t.Context())

			if b, rerr := os.ReadFile(filepath.Clean(filepath.Join(out, tt.clean))); rerr != nil || string(b) != tt.cleanContent {
				t.Errorf("the clean file must be moved: %q, %v", b, rerr)
			}
			if _, serr := os.Stat(clean); !os.IsNotExist(serr) {
				t.Errorf("the clean file must be gone from INPUT: %v", serr)
			}
			if _, serr := os.Stat(bad); !os.IsNotExist(serr) {
				t.Errorf("the malicious file must be removed from INPUT (sharing error?): %v", serr)
			}
			if _, serr := os.Stat(filepath.Join(out, tt.bad)); !os.IsNotExist(serr) {
				t.Errorf("the malicious file must never reach OUTPUT: %v", serr)
			}
			locks, gerr := filepath.Glob(filepath.Join(qdir, "*.lock"))
			if gerr != nil || len(locks) != 1 {
				t.Errorf("quarantine holds %v (err %v), want one container for the malicious file", locks, gerr)
			}
		})
	}
}
