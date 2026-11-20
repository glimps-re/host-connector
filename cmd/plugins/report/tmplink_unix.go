//go:build !windows

package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	tmpLinkPrefix = "gmhc-"
	// maxLinkBase is the longest folder a link is made in. Chrome puts a socket
	// under the link, and the socket path must fit the smallest limit of the
	// systems we run on (103 bytes on macOS, 107 on Linux; the macOS figure was
	// not checked with a real browser):
	// 38 + "/gmhc-" and 12 hex digits (18) + "/org.chromium.Chromium.XXXXXX/SingletonSocket"
	// (45) = 101.
	maxLinkBase = 38
	// purgeBatch bounds the entries of the temporary folder held in memory at a
	// time: it may hold millions of files.
	purgeBatch = 256
	// linkNameTries is plenty: a name has 48 random bits.
	linkNameTries = 10
)

// Replaced in tests, which must never reach the real temporary folder.
var (
	systemTempDir    = os.TempDir
	fallbackLinkBase = "/tmp"
	newLinkName      = drawLinkName
)

func drawLinkName() (string, error) {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("cannot draw the name of the temporary link: %w", err)
	}
	return tmpLinkPrefix + hex.EncodeToString(b[:]), nil
}

// safeLinkBase tells whether links may be made in dir: an absolute folder, short
// enough, owned by root or by this account, in which no other account can rename
// or replace entries (not writable by its group or by others, or with the sticky
// bit). Otherwise one of them could swap our link for his own between its
// creation and the launch of the browser. Only dir itself is checked, not the
// folders above it.
func safeLinkBase(dir string) bool {
	if !filepath.IsAbs(dir) || len(dir) > maxLinkBase {
		return false
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return false
	}
	if st, ok := info.Sys().(*syscall.Stat_t); !ok || (st.Uid != 0 && int(st.Uid) != os.Geteuid()) {
		return false
	}
	mode := info.Mode()
	return mode.Perm()&0o022 == 0 || mode&fs.ModeSticky != 0
}

// pickLinkBase returns the first of the candidates that is safe.
func pickLinkBase(candidates ...string) (string, error) {
	for _, dir := range candidates {
		if safeLinkBase(dir) {
			return dir, nil
		}
	}
	return "", fmt.Errorf("no safe folder for the temporary link of the browser (tried %s): it must be an absolute path of at most %d bytes, not writable by other accounts or with the sticky bit", strings.Join(candidates, ", "), maxLinkBase)
}

// linkBase is the folder the short links are made in: the temporary folder of
// the system when it is safe, else /tmp.
func linkBase() (string, error) {
	return pickLinkBase(systemTempDir(), fallbackLinkBase)
}

// linkTemp makes a short link to the temporary folder of a rendering and returns
// its path. The browser is given the link as its TMPDIR: it puts its socket
// there, and the files it creates are in the folder of the rendering. A name
// already taken is never replaced.
func linkTemp(target string) (string, error) {
	base, err := linkBase()
	if err != nil {
		return "", err
	}
	for range linkNameTries {
		name, err := newLinkName()
		if err != nil {
			return "", err
		}
		link := filepath.Join(base, name)
		err = os.Symlink(target, link)
		if err == nil {
			return link, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return "", fmt.Errorf("cannot make the temporary link of the browser in %s: %w", base, err)
		}
	}
	return "", fmt.Errorf("no free name for the temporary link of the browser in %s", base)
}

// unlink removes a name without ever removing a folder: os.Remove would fall
// back to rmdir if the entry had been replaced by an empty one. A name already
// gone is not an error.
func unlink(path string) error {
	if err := syscall.Unlink(path); err != nil && !errors.Is(err, syscall.ENOENT) {
		return &fs.PathError{Op: "unlink", Path: path, Err: err}
	}
	return nil
}

func removeTempLink(link string) error {
	return unlink(link)
}

// purgeTempLinks removes the links of a connector that did not stop cleanly:
// entries of the temporary folder that are symbolic links, named like ours,
// owned by this account, and dangling (the folder of their rendering is gone).
// Nothing else is touched. It returns how many it removed.
//
// Two connectors of the same account that share the temporary folder but not
// their work directories (containers) would judge each other's links dangling,
// and so would a connector whose work directory is missing at that moment (its
// links are made again by the next rendering). A folder whose read position is
// unstable (network or FUSE file systems) may make the purge miss entries: a
// link is left, never a wrong one removed.
func purgeTempLinks() (removed int, err error) {
	base, err := linkBase()
	if err != nil {
		return 0, err
	}
	dir, err := os.Open(filepath.Clean(base))
	if err != nil {
		return 0, err
	}
	defer func() {
		if cerr := dir.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	uid := os.Geteuid()
	var errs []error
	for {
		entries, rerr := dir.ReadDir(purgeBatch)
		for _, e := range entries {
			if !strings.HasPrefix(e.Name(), tmpLinkPrefix) || e.Type()&fs.ModeSymlink == 0 {
				continue
			}
			path := filepath.Join(base, e.Name())
			if !isOurDanglingLink(path, uid) {
				continue
			}
			if uerr := unlink(path); uerr != nil {
				errs = append(errs, uerr)
				continue
			}
			removed++
		}
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			errs = append(errs, rerr)
			break
		}
	}
	return removed, errors.Join(errs...)
}

// isOurDanglingLink tells whether path is a symbolic link owned by uid whose
// target does not exist. It never follows the link except to test the target.
func isOurDanglingLink(path string, uid int) bool {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&fs.ModeSymlink == 0 {
		return false
	}
	if st, ok := info.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != uid {
		return false
	}
	_, err = os.Stat(path)
	return errors.Is(err, fs.ErrNotExist)
}
