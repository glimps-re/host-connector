//go:build linux

package errlog

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"syscall"
	"testing"
	"testing/iotest"
)

type failingWriter struct {
	header http.Header
	err    error
}

func (w *failingWriter) Header() http.Header       { return w.header }
func (w *failingWriter) WriteHeader(int)           {}
func (w *failingWriter) Write([]byte) (int, error) { return 0, w.err }

// A fake that cannot answer says so, except when the connector closed the
// connection, which is only noted.
func TestErrLog(t *testing.T) {
	req := func(ctx context.Context, body io.Reader) *http.Request {
		return httptest.NewRequestWithContext(ctx, http.MethodPost, "/api/lite/v2/submit", body)
	}
	t.Run("a closed connection is a note", func(t *testing.T) {
		var l Log
		r := req(t.Context(), nil)
		l.JSON(&failingWriter{header: http.Header{}, err: syscall.EPIPE}, r, map[string]any{})
		l.Text(&failingWriter{header: http.Header{}, err: syscall.ECONNRESET}, r, "x")
		if got := l.Errors(); len(got) != 0 {
			t.Errorf("errors = %v, want none for a closed connection", got)
		}
		if got := l.AbortedUploads(); got != 0 {
			t.Errorf("aborted = %d, want 0: a failed answer is not an aborted upload", got)
		}
	})
	t.Run("another write failure is an error naming the endpoint", func(t *testing.T) {
		var l Log
		l.Text(&failingWriter{header: http.Header{}, err: io.ErrShortWrite}, req(t.Context(), nil), "x")
		got := l.Errors()
		if len(got) != 1 || !strings.Contains(got[0], "POST /api/lite/v2/submit") {
			t.Errorf("errors = %v, want one naming the endpoint", got)
		}
	})
	t.Run("a cut body that nobody announced is an error", func(t *testing.T) {
		var l Log
		l.Drain(req(t.Context(), iotest.ErrReader(io.ErrUnexpectedEOF)), 10)
		if got := l.Errors(); len(got) != 1 {
			t.Errorf("errors = %v, want one", got)
		}
	})
	t.Run("an announced abort that never happens is unconsumed", func(t *testing.T) {
		var l Log
		l.ExpectAbortedUploads(2)
		l.Drain(req(t.Context(), iotest.ErrReader(io.ErrUnexpectedEOF)), 10)
		if got := l.Unconsumed(); got != 1 {
			t.Errorf("unconsumed = %d, want 1", got)
		}
	})
	t.Run("a cut body that was announced is a note, once", func(t *testing.T) {
		var l Log
		l.ExpectAbortedUploads(1)
		l.Drain(req(t.Context(), iotest.ErrReader(io.ErrUnexpectedEOF)), 10)
		if got := l.Errors(); len(got) != 0 {
			t.Fatalf("errors = %v, want none for an announced abort", got)
		}
		if got := l.AbortedUploads(); got != 1 {
			t.Errorf("aborted = %d, want 1", got)
		}
		l.Drain(req(t.Context(), iotest.ErrReader(io.ErrUnexpectedEOF)), 10)
		if got := l.Errors(); len(got) != 1 {
			t.Errorf("errors = %v, want the second, unannounced abort to be an error", got)
		}
	})
	t.Run("a cancelled request does not excuse a cut body", func(t *testing.T) {
		var l Log
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		l.Drain(req(ctx, iotest.ErrReader(io.ErrUnexpectedEOF)), 10)
		if got := l.Errors(); len(got) != 1 {
			t.Errorf("errors = %v, want one", got)
		}
	})
	t.Run("a connection reset while reading is a note and an aborted upload", func(t *testing.T) {
		var l Log
		l.Drain(req(t.Context(), iotest.ErrReader(syscall.ECONNRESET)), 10)
		if got := l.Errors(); len(got) != 0 {
			t.Errorf("errors = %v, want none", got)
		}
		if got := l.AbortedUploads(); got != 1 {
			t.Errorf("aborted = %d, want 1", got)
		}
	})
}
