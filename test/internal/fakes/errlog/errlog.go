// Package errlog records what the fakes of the e2e suite failed to read or
// write while answering.
package errlog

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"syscall"
	"testing"
)

// Log records what a fake failed to read or write while answering. A
// connection that the connector closed or reset (it does at shutdown) is only a
// note; anything else is an error the run asserts at its end. A body cut short
// (io.ErrUnexpectedEOF) is an error: a connector must not cut its uploads.
type Log struct {
	mu      sync.Mutex
	errs    []string
	notes   []string
	aborted int
}

// closedConnection tells the errors of a peer that went away.
func closedConnection(err error) bool {
	return errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) || errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled)
}

// Record keeps the failure of an operation and tells whether it succeeded.
func (l *Log) Record(what string, err error) (ok bool) {
	if err == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	line := what + ": " + err.Error()
	if closedConnection(err) {
		l.notes = append(l.notes, line)
		return false
	}
	l.errs = append(l.errs, line)
	return false
}

// Note keeps a failure that is expected, such as a client that went away.
func (l *Log) Note(what string, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.notes = append(l.notes, what+": "+err.Error())
}

// Fail keeps a failure of the protocol, which is always an error.
func (l *Log) Fail(msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.errs = append(l.errs, msg)
}

// AbortedUploads counts the uploads whose connection the connector closed
// while their body was read.
func (l *Log) AbortedUploads() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.aborted
}

// Errors returns the failures recorded so far.
func (l *Log) Errors() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.errs...)
}

// Notes returns the expected failures recorded so far, for the log of a test.
func (l *Log) Notes() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.notes...)
}

func endpoint(r *http.Request) string { return r.Method + " " + r.URL.Path }

// Deliver writes an answer, flushes it, and tells whether it reached the
// client as far as the server can see: no write or flush error, and the request
// not cancelled once the answer is flushed. The writes of net/http go to a
// buffer and succeed even when the client has gone: only the context of the
// request tells. What the server cannot see is a client that receives the bytes
// and then drops them.
func (l *Log) Deliver(w http.ResponseWriter, r *http.Request, write func() error) bool {
	if !l.Record("writing the answer to "+endpoint(r), write()) {
		return false
	}
	if !l.Record("flushing the answer to "+endpoint(r), http.NewResponseController(w).Flush()) {
		return false
	}
	if err := r.Context().Err(); err != nil {
		l.Note("the client of "+endpoint(r)+" gave up before the answer", err)
		return false
	}
	return true
}

// JSON answers with v as JSON and tells whether the answer was delivered.
func (l *Log) JSON(w http.ResponseWriter, r *http.Request, v any) bool {
	return l.Deliver(w, r, func() error { return json.NewEncoder(w).Encode(v) })
}

// Text answers with s and tells whether the answer was delivered.
func (l *Log) Text(w http.ResponseWriter, r *http.Request, s string) bool {
	return l.Deliver(w, r, func() error {
		_, err := io.WriteString(w, s)
		return err
	})
}

// Drain reads and drops the body of the request, up to limit bytes. A closed
// connection counts as an aborted upload.
func (l *Log) Drain(r *http.Request, limit int64) {
	_, err := io.Copy(io.Discard, io.LimitReader(r.Body, limit))
	if err == nil {
		return
	}
	if closedConnection(err) {
		l.mu.Lock()
		l.aborted++
		l.mu.Unlock()
	}
	l.Record("reading the body of "+endpoint(r), err)
}

func (l *Log) Check(t *testing.T, name string) {
	for _, e := range l.Errors() {
		t.Errorf("%s: %s", name, e)
	}
	if n := l.AbortedUploads(); n != 0 {
		t.Errorf("%s: %d aborted uploads", name, n)
	}
	for _, n := range l.Notes() {
		t.Logf("%s (expected): %s", name, n)
	}
}
