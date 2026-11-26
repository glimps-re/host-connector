package quarantine

import (
	"context"
	"errors"
	"os"
	"time"
)

// ErrNoVerifiedSource is returned by a move whose source has no verified
// descriptor on a system that needs one: moving by name would act on whatever
// the name designates when it is used, not on the file that was verified.
var ErrNoVerifiedSource = errors.New("the source of the move has no verified descriptor")

// MoveSource is the file a move applies to.
type MoveSource struct {
	// Path is the deposit path: the name the file was found under. Where a
	// verified descriptor is given it only serves for messages.
	Path string
	// File is the descriptor of the verified file, where the system gives one
	// (Linux): the move publishes that very inode, whatever the name holds by
	// then.
	File *os.File
	// SHA256 is the hash the file was analyzed with. A copy made by the move (a
	// file system that refuses links, or another device) is verified against it
	// before it is published, and refused with ErrNoExpectedHash when it is
	// missing.
	SHA256 string
	// Remove removes the source through the verified handle: only the name the
	// file was opened under, and only if it still is that file.
	Remove func() error
}

// MoveResolvingConflicts moves the source to dst, or when dst exists to a
// ConflictName next to it, up to maxConflicts names (see
// MoveFileResolvingConflicts). On Linux the verified descriptor is published
// (hard link made from it, or a verified copy read from it when the file system
// refuses links) and the source is then removed through the verified handle; a
// source without descriptor is refused. Elsewhere the move goes by name. A
// copy is interrupted by ctx.
func MoveResolvingConflicts(ctx context.Context, src MoveSource, dst, stagingDir string, now func() time.Time, maxConflicts int) (string, error) {
	return moveSource(ctx, src, dst, stagingDir, conflictNames(dst, now, maxConflicts))
}
