package scanner

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/glimps-re/host-connector/internal/pathutil"
	"github.com/glimps-re/host-connector/internal/safepath"
	"github.com/glimps-re/host-connector/pkg/quarantine"
)

// ErrSourceChanged is returned when a source is no longer the file the
// pipeline verified: it was replaced or modified since. It is the error of the
// quarantine package: a single errors.Is serves every layer.
var ErrSourceChanged = quarantine.ErrSourceChanged

// errSourceLink is returned by the actions that destroy or move a source
// reached through a symbolic link (follow_symlinks): the content is elsewhere,
// and what would be removed or moved is the link, not the file that was
// analyzed. It is permanent: retrying cannot change the link.
var errSourceLink = fmt.Errorf("%w: the source is a symbolic link", errPermanentAction)

// errNoHandle is returned when a source without the verified handle reaches an
// action that removes or moves it, on a system that gives one: acting by name
// would act on whatever the name designates when it is used. It is a fault of
// the caller, not worth a retry.
var errNoHandle = fmt.Errorf("%w: %w", errPermanentAction, quarantine.ErrNoVerifiedSource)

// errNoIdentity is returned when a source without a verified identity reaches
// an action that deletes or moves it: there is nothing to compare the file
// with.
var errNoIdentity = fmt.Errorf("%w: the source has no verified identity", errPermanentAction)

// errNoSHA256 is returned when a source without the SHA256 the pipeline
// computed reaches an action that deletes, moves or quarantines it: what is
// destroyed or published must be what was hashed.
var errNoSHA256 = fmt.Errorf("%w: the source has no verified SHA256", errPermanentAction)

// holdsHandle tells whether the pipeline keeps the verified descriptor open
// during the actions. Elsewhere it is closed before them (a file that is open
// cannot be moved or deleted on Windows) and the actions work by name, the
// window between the check and the action being a documented limit.
const holdsHandle = runtime.GOOS == "linux"

// openSourceFiles counts the descriptors handed out by Source.Open and not yet
// released, to check that none leaks.
var openSourceFiles atomic.Int64

// Source is the verified file an action applies to.
type Source struct {
	// Path is the deposit path: what names, logs, the registry and the
	// destination of an action are made from.
	Path string
	// Root is the monitored root containing Path; "" if there is none.
	Root string
	// Identity is the identity the pipeline verified.
	Identity FileIdentity
	// SHA256 is the hash of the content the pipeline read and analyzed, computed
	// by the pipeline itself (a plugin can replace the one of the result). The
	// actions that delete, move or quarantine the source refuse one without it.
	SHA256 string
	// TooBig is true when the pipeline did not analyze the content because the
	// file is larger than max_file_size (too_big policy, or an encrypted archive
	// over the limit). Set by the pipeline from its own decision, never from the
	// result or from the size alone: a large archive that was extracted and
	// analyzed is not too big.
	TooBig bool

	// handle is the file the pipeline opened without following any link, set
	// where the platform allows it.
	handle *safepath.File
	// viaLink is set when the file was reached through a symbolic link that the
	// configuration told to follow.
	viaLink bool
	// fd is the verified descriptor of a file reached through a link, where the
	// pipeline keeps it open: there is no handle to give then (a handle is
	// opened without following links), but the content is still read from it.
	fd *os.File
}

// Open returns the verified file, ready to be read from its start, and a
// function that releases it. It is another descriptor on the file the pipeline
// verified, or, without one, the file at Path opened again (without following a
// link below Root unless the configuration says to follow them). It fails with
// ErrSourceChanged if what it opened is no longer Identity.
func (s Source) Open() (f *os.File, release func(), err error) {
	switch {
	case s.handle != nil:
		f, err = safepath.Reopen(s.handle.OS())
	case s.fd != nil:
		f, err = safepath.Reopen(s.fd)
	default:
		f, err = s.openPath()
	}
	if err != nil {
		return nil, nil, err
	}
	if err = s.matches(f, FileIdentity.Equal); err != nil {
		if closeErr := f.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
		return nil, nil, err
	}
	openSourceFiles.Add(1)
	var once sync.Once
	return f, func() {
		once.Do(func() {
			openSourceFiles.Add(-1)
			if closeErr := f.Close(); closeErr != nil {
				logger.Warn("could not close a source file", slog.String("file", s.Path), slog.String(logErrorKey, closeErr.Error()))
			}
		})
	}, nil
}

// openPath opens Path again: as it is, for a file reached through a link the
// configuration told to follow; below Root without following any link
// otherwise; by name, never blocking on a pipe, when the file has no root.
func (s Source) openPath() (*os.File, error) {
	if s.viaLink {
		return openRegular(s.Path, true)
	}
	if s.Root != "" && pathutil.Under(s.Root, s.Path) {
		rel, err := filepath.Rel(s.Root, s.Path)
		if err != nil {
			return nil, err
		}
		h, err := safepath.Open(s.Root, rel)
		if err != nil {
			return nil, err
		}
		// The file stays usable once the handle is dropped: only the parent
		// directory handle is released.
		f, err := safepath.Reopen(h.OS())
		if closeErr := h.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
		return f, err
	}
	return openRegular(s.Path, false)
}

// matches compares what f says now with the verified identity, with same.
func (s Source) matches(f *os.File, same func(a, b FileIdentity) bool) error {
	info, err := f.Stat()
	if err != nil {
		return err
	}
	return s.compare(info, same)
}

func (s Source) compare(info os.FileInfo, same func(a, b FileIdentity) bool) error {
	if !same(IdentityOf(info), s.Identity) {
		return fmt.Errorf("%w: %s", ErrSourceChanged, s.Path)
	}
	return nil
}

// actionable is what every action that deletes, moves or quarantines the
// source asks first: it is not a link, and the pipeline verified it.
func (s Source) actionable() error {
	if s.viaLink {
		return errSourceLink
	}
	return s.verified()
}

// verified refuses a source the pipeline gave no identity or no SHA256.
func (s Source) verified() error {
	if s.Identity.zero() {
		return fmt.Errorf("%w: %s", errNoIdentity, s.Path)
	}
	if s.SHA256 == "" {
		return fmt.Errorf("%w: %s", errNoSHA256, s.Path)
	}
	return nil
}

// checkNow compares the file as it is now with the verified identity, with
// same: through the handle where there is one, by name elsewhere.
func (s Source) checkNow(same func(a, b FileIdentity) bool) error {
	if s.handle != nil {
		return s.matches(s.handle.OS(), same)
	}
	info, err := lstat(s.Path)
	if err != nil {
		return err
	}
	return s.compare(info, same)
}

// ready is the check a move makes right before moving: the source is
// actionable and still is the verified file.
func (s Source) ready() error {
	if err := s.actionable(); err != nil {
		return err
	}
	return s.checkNow(FileIdentity.Equal)
}

// Remove deletes the source file if it still is Identity. With the handle of the
// pipeline it removes the name the file was opened under, in the folder it was
// opened in, and only if that name still is the opened inode. A source reached
// through a link is never removed, and on a system that gives a handle a source
// without one is refused. Elsewhere, after checking the file at Path.
func (s Source) Remove() error {
	if err := s.actionable(); err != nil {
		return err
	}
	switch {
	case s.handle != nil:
		if err := s.checkNow(FileIdentity.Equal); err != nil {
			return err
		}
		return s.removeHandle()
	case holdsHandle:
		return fmt.Errorf("%w: %s", errNoHandle, s.Path)
	}
	if err := s.checkNow(FileIdentity.Equal); err != nil {
		return err
	}
	return os.Remove(s.Path)
}

// removeHandle removes the name the file was opened under; a name that holds
// another file is reported as ErrSourceChanged (and safepath.ErrChanged).
func (s Source) removeHandle() error {
	err := s.handle.Remove()
	if errors.Is(err, safepath.ErrChanged) {
		return fmt.Errorf("%w: %s: %w", ErrSourceChanged, s.Path, err)
	}
	return err
}

// removeLinked removes the source once the connector linked its inode to the
// destination: the link changed the change time of the inode, so only the
// device, inode, size and modification time are compared with what was
// verified.
func (s Source) removeLinked() error {
	if s.handle == nil {
		return s.Remove()
	}
	if err := s.actionable(); err != nil {
		return err
	}
	if err := s.checkNow(FileIdentity.sameFileContent); err != nil {
		return err
	}
	return s.removeHandle()
}

// moveSource is the source as a move takes it.
func (s Source) moveSource() quarantine.MoveSource {
	ms := quarantine.MoveSource{Path: s.Path, SHA256: s.SHA256, Remove: s.removeLinked}
	if s.handle != nil {
		ms.File = s.handle.OS()
	}
	return ms
}

// zero reports whether the identity is the zero value: a Source built by hand,
// without verification.
func (a FileIdentity) zero() bool {
	return a.Dev == 0 && a.Ino == 0 && a.Size == 0 && a.ModTime.IsZero() && a.ChangeTime.IsZero()
}
