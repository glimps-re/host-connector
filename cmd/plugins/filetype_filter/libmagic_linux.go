//go:build linux

package main

/*
#cgo LDFLAGS: -lmagic
#include <magic.h>
#include <stdlib.h>

static int set_bytes_max(magic_t c, size_t n) { return magic_setparam(c, MAGIC_PARAM_BYTES_MAX, &n); }

static size_t get_bytes_max(magic_t c) {
	size_t n = 0;
	magic_getparam(c, MAGIC_PARAM_BYTES_MAX, &n);
	return n;
}
*/
import "C"

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

// typeTimeout bounds one typing, the wait for a free cookie included: a call that
// goes over it is an error, the file being refused when types are forbidden.
// libmagic cannot be interrupted, so a call that is late is left to end by itself,
// and its cookie is not reused until it does.
var typeTimeout = 5 * time.Second

// poolSize is the most cookies there are, so typings that can run at once: libmagic
// cookies are not safe for concurrent use, one per call, and they are created as
// concurrent calls need them, so that an idle site keeps one. It bounds what stuck
// calls can take: the others keep typing.
var poolSize = 8

// cookie is a libmagic handle: it follows links (MAGIC_SYMLINK), which go-magic
// does not and which typing a descriptor by its /proc name needs, and it reports
// an error as an error (MAGIC_ERROR). A cookie is used by one goroutine at a time.
type cookie struct {
	c     C.magic_t
	slots chan struct{} // the slot this cookie holds while it is in use
}

func newCookie(databases []string) (*cookie, error) {
	c := C.magic_open(C.MAGIC_ERROR | C.MAGIC_MIME_TYPE | C.MAGIC_SYMLINK)
	if c == nil {
		return nil, errors.New("libmagic could not be opened")
	}
	var list *C.char
	if len(databases) > 0 {
		list = C.CString(strings.Join(databases, ":"))
		defer C.free(unsafe.Pointer(list))
	}
	if C.magic_load(c, list) != 0 {
		msg := C.GoString(C.magic_error(c))
		C.magic_close(c)
		return nil, fmt.Errorf("libmagic could not load its database: %s", msg)
	}
	if C.set_bytes_max(c, C.size_t(bytesMax)) != 0 {
		msg := C.GoString(C.magic_error(c))
		C.magic_close(c)
		return nil, fmt.Errorf("libmagic bytes_max could not be set: %s", msg)
	}
	openCookies.Add(1)
	return &cookie{c: c}, nil
}

// bytesMaxSet is the bytes_max the cookie works with.
func (k *cookie) bytesMaxSet() uint64 {
	return uint64(C.get_bytes_max(k.c))
}

// file gives the MIME type libmagic finds for the file at path.
func (k *cookie) file(path string) (string, error) {
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))
	out := C.magic_file(k.c, cpath)
	if out == nil {
		msg := C.GoString(C.magic_error(k.c))
		if msg == "" {
			msg = "libmagic gave no answer"
		}
		return "", errors.New(msg)
	}
	return C.GoString(out), nil
}

func (k *cookie) close() {
	C.magic_close(k.c)
	openCookies.Add(-1)
}

// openCookies counts the libmagic handles that are open.
var openCookies atomic.Int64

// cookies are the cookies not in use, and the slots that bound how many are in use
// at once. They are kept, not pooled by sync.Pool, which would drop them without
// closing them. Nothing slow is done under mu: no read of the database, no libmagic
// call.
var cookies struct {
	mu     sync.Mutex
	free   []*cookie
	slots  chan struct{}
	closed int // incremented by closeCookies: a cookie in use then is closed on release
}

// databaseList is the list of the libmagic databases, kept once it was read: a
// failure is not kept, the next typing reads the list again.
var databaseList struct {
	mu    sync.Mutex
	files []string
	known bool
}

// listDatabases reads the list of the databases; a variable so that tests can make
// it fail.
var listDatabases = databaseFiles

// cachedDatabases lists the libmagic databases, once it succeeds.
func cachedDatabases() ([]string, error) {
	databaseList.mu.Lock()
	defer databaseList.mu.Unlock()
	if databaseList.known {
		return databaseList.files, nil
	}
	files, err := listDatabases()
	if err != nil {
		return nil, err
	}
	databaseList.files, databaseList.known = files, true
	return files, nil
}

// loadDatabases lists the libmagic databases; a variable so that tests can make it
// slow.
var loadDatabases = cachedDatabases

// minTypeBudget is the least time left for a typing to start one: libmagic cannot
// be interrupted, so a call that has no time left is not started.
const minTypeBudget = 50 * time.Millisecond

// errTypingTimeout is the error of a typing that took, or would take, longer than
// the bound.
func errTypingTimeout(d time.Duration) error {
	return fmt.Errorf("typing took more than %s", d)
}

// acquireSlot takes a slot, waiting at most wait: the calls that are stuck keep
// theirs. It gives back the channel of the slot, to be received from to free it.
func acquireSlot(wait time.Duration) (chan struct{}, error) {
	cookies.mu.Lock()
	if cookies.slots == nil {
		cookies.slots = make(chan struct{}, poolSize)
	}
	slots := cookies.slots
	cookies.mu.Unlock()
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case slots <- struct{}{}:
		return slots, nil
	case <-timer.C:
		return nil, fmt.Errorf("no libmagic handle was free within %s", wait)
	}
}

// takeCookie gives a cookie to the call that holds slots: a free one, or a new one,
// opened without the lock. A failure frees the slot.
func takeCookie(slots chan struct{}) (*cookie, int, error) {
	cookies.mu.Lock()
	generation := cookies.closed
	if n := len(cookies.free); n > 0 {
		k := cookies.free[n-1]
		cookies.free = cookies.free[:n-1]
		k.slots = slots
		cookies.mu.Unlock()
		return k, generation, nil
	}
	cookies.mu.Unlock()
	databases, err := loadDatabases()
	if err != nil {
		<-slots
		return nil, 0, err
	}
	k, err := newCookie(databases)
	if err != nil {
		<-slots
		return nil, 0, err
	}
	k.slots = slots
	return k, generation, nil
}

// acquireCookie takes a slot and a cookie.
func acquireCookie(wait time.Duration) (*cookie, int, error) {
	slots, err := acquireSlot(wait)
	if err != nil {
		return nil, 0, err
	}
	return takeCookie(slots)
}

// releaseCookie gives a cookie and its slot back, when the C call it was used for
// has ended.
func releaseCookie(k *cookie, generation int) {
	cookies.mu.Lock()
	slots := k.slots // read before the cookie is handed to another call, which sets it
	if generation != cookies.closed {
		k.close()
	} else {
		cookies.free = append(cookies.free, k)
	}
	cookies.mu.Unlock()
	<-slots
}

// closeCookies frees the cookies not in use; the ones in use are freed when they
// come back, and the next typing opens new ones.
func closeCookies() {
	cookies.mu.Lock()
	defer cookies.mu.Unlock()
	for _, k := range cookies.free {
		k.close()
	}
	cookies.free, cookies.slots = nil, nil
	cookies.closed++
	databaseList.mu.Lock()
	databaseList.files, databaseList.known = nil, false
	databaseList.mu.Unlock()
}

// cookieFile types a file with a cookie; a variable so that tests can make a typing
// last.
var cookieFile = (*cookie).file

// libmagicType types the file at path, within typeTimeout, which counts the wait
// for a slot, the opening of a cookie and the typing. release is called once, when
// the C call has ended or none was started: the caller hands over to it the
// descriptor path names, which must stay open until libmagic has opened it, however
// late that is.
func libmagicType(path string, release func()) (string, error) {
	start := time.Now()
	slots, err := acquireSlot(typeTimeout)
	if err != nil {
		release()
		return "", err
	}
	remaining := typeTimeout - time.Since(start)
	if remaining < minTypeBudget {
		<-slots
		release()
		return "", errTypingTimeout(typeTimeout)
	}
	return within(remaining, func() (string, error) {
		defer release()
		k, generation, err := takeCookie(slots)
		if err != nil {
			return "", err
		}
		defer releaseCookie(k, generation)
		return cookieFile(k, path)
	})
}

// within runs typing and gives its answer, or an error when it takes longer than
// d: typing is then left to end by itself, since libmagic cannot be interrupted.
func within(d time.Duration, typing func() (string, error)) (string, error) {
	type answer struct {
		mime string
		err  error
	}
	done := make(chan answer, 1)
	go func() {
		mime, err := typing()
		done <- answer{mime, err}
	}()
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case a := <-done:
		return a.mime, a.err
	case <-timer.C:
		return "", errTypingTimeout(d)
	}
}
