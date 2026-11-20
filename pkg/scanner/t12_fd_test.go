//go:build linux

package scanner

import (
	"os"
	"path/filepath"
	"testing"

	gdetectMock "github.com/glimps-re/go-gdetect/pkg/gdetect/mock"
)

// Every path out of the pipeline releases the verified descriptor: the counter of
// the sources and the descriptors of the process are back to what they were once
// the files are handled, whatever the outcome.
func TestT12_noDescriptorIsHeldAfterTheActionsWhateverTheOutcome(t *testing.T) {
	outcomes := map[string]func(f **swapFixture) *gdetectMock.MockGDetectSubmitter{
		"clean file moved": func(f **swapFixture) *gdetectMock.MockGDetectSubmitter { return echoReader(serviceSubmitter(f, nil)) },
		"malware removed":  func(f **swapFixture) *gdetectMock.MockGDetectSubmitter { return echoReader(serviceSubmitter(f, nil)) },
		"file rewritten during the analysis": func(f **swapFixture) *gdetectMock.MockGDetectSubmitter {
			return echoReader(serviceSubmitter(f, func() {
				if err := os.WriteFile(filepath.Clean((*f).file), []byte("rewritten while it was analyzed"), 0o600); err != nil {
					t.Error(err)
				}
			}))
		},
	}
	for name, mk := range outcomes {
		t.Run(name, func(t *testing.T) {
			skipWithoutProc(t)
			baseSources := openSourceFiles.Load()
			baseFDs := openDescriptors(t)
			var f *swapFixture
			f = newSwapFixture(t, mk(&f))
			out := t.TempDir()
			move, err := NewMoveAction(out, filepath.Dir(filepath.Dir(f.file)))
			if err != nil {
				t.Fatal(err)
			}
			f.c.action = NewMultiAction(&ReportAction{}, move, &RemoveFileAction{})
			f.run(t)
			moved, err := os.ReadDir(out)
			if err != nil {
				t.Fatal(err)
			}
			_, statErr := os.Stat(f.file)
			switch name {
			case "clean file moved":
				if len(moved) == 0 {
					t.Error("the clean file was not moved: the test proves nothing")
				}
			case "malware removed":
				if !os.IsNotExist(statErr) {
					t.Errorf("the malicious file was not removed (%v): the test proves nothing", statErr)
				}
			}
			if got := openSourceFiles.Load(); got != baseSources {
				t.Errorf("%d verified source(s) still open after %s, was %d", got, name, baseSources)
			}
			if got := openDescriptors(t); got > baseFDs {
				t.Errorf("%d descriptors open after %s, was %d", got, name, baseFDs)
			}
		})
	}
}
