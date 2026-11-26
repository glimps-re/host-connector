package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	gdetectMock "github.com/glimps-re/go-gdetect/pkg/gdetect/mock"
)

// idOf returns the identity of the file at path, as the monitor observes it.
func idOf(t *testing.T, path string) FileIdentity {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return IdentityOf(info)
}

func TestFileIdentity_changesWithEveryWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f.bin")
	if err := os.WriteFile(path, []byte("aaaa"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := idOf(t, path)
	if !base.Equal(idOf(t, path)) {
		t.Fatal("two reads of an untouched file must give the same identity")
	}
	mtime := base.ModTime
	tests := []struct {
		name   string
		change func(t *testing.T)
	}{
		{"size", func(t *testing.T) {
			if err := os.WriteFile(path, []byte("aaaaa"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chtimes(path, time.Time{}, mtime); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte("aaaa"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chtimes(path, time.Time{}, mtime); err != nil {
				t.Fatal(err)
			}
			before := idOf(t, path)
			tt.change(t)
			if before.Equal(idOf(t, path)) {
				t.Error("the identity must change")
			}
		})
	}
}

// echoReader makes a submitter that answers like its WaitForFile for a file
// given by path or through the trio the connector uses for a deposited file
// (see readerTrio), and that reports the SHA256 of what it read when the answer
// has none.
func echoReader(m *gdetectMock.MockGDetectSubmitter) *gdetectMock.MockGDetectSubmitter {
	file := m.WaitForFileMock
	m.WaitForFileMock = func(ctx context.Context, path string, opts gdetect.WaitForOptions) (gdetect.Result, error) {
		res, err := file(ctx, path, opts)
		if err == nil && res.SHA256 == "" {
			res.SHA256, _ = getFileSHA256(path)
		}
		return res, err
	}
	m.WaitForReaderMock = func(ctx context.Context, r io.Reader, opts gdetect.WaitForOptions) (gdetect.Result, error) {
		h := sha256.New()
		if _, err := io.Copy(h, r); err != nil {
			return gdetect.Result{}, err
		}
		res, err := file(ctx, opts.Filename, opts)
		if res.SHA256 == "" {
			res.SHA256 = hex.EncodeToString(h.Sum(nil))
		}
		return res, err
	}
	return readerTrio(m)
}

// readerTrio plays, for a mock that has a WaitForReaderMock, the three calls the
// connector makes for a deposited file read through its descriptor: a cache
// lookup that misses, the submission of the content, and the wait for the
// result, which is what WaitForReaderMock answers.
func readerTrio(m *gdetectMock.MockGDetectSubmitter) *gdetectMock.MockGDetectSubmitter {
	type submitted struct {
		r    io.Reader
		opts gdetect.SubmitOptions
	}
	var mu sync.Mutex
	subs := map[string]submitted{}
	var n int
	if m.GetResultBySHA256Mock == nil {
		m.GetResultBySHA256Mock = func(context.Context, string) (gdetect.Result, error) {
			return gdetect.Result{}, gdetect.HTTPError{Code: http.StatusNotFound}
		}
	}
	m.SubmitReaderMock = func(_ context.Context, r io.Reader, opts gdetect.SubmitOptions) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		n++
		id := fmt.Sprintf("uuid-%d", n)
		subs[id] = submitted{r: r, opts: opts}
		return id, nil
	}
	m.GetResultByUUIDWithWaitMock = func(ctx context.Context, id string, _ int) (gdetect.Result, error) {
		mu.Lock()
		s := subs[id]
		mu.Unlock()
		res, err := m.WaitForReaderMock(ctx, s.r, gdetect.WaitForOptions{SubmitOptions: s.opts})
		res.Done = true
		return res, err
	}
	return m
}
