//go:build !linux

package quarantine

import "context"

// moveSource moves by name: these systems have no way to publish a descriptor,
// and the file is closed before the action. The window between the check and
// the move is a documented limit. A copy made when the file is on another
// device is verified against the SHA256 of the source, which must be given.
func moveSource(ctx context.Context, src MoveSource, dst, stagingDir string, next func(attempt int) (string, bool)) (string, error) {
	return runPublication(&pathMove{src: src.Path, cur: src.Path, stagingDir: stagingDir, ctx: ctx, sha256: src.SHA256, verified: true}, dst, next)
}
