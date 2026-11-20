//go:build !linux

package quarantine

// moveSource moves by name: these systems have no way to publish a descriptor,
// and the file is closed before the action. The window between the check and
// the move is a documented limit.
func moveSource(src MoveSource, dst, stagingDir string, next func(attempt int) (string, bool)) (string, error) {
	return moveFile(src.Path, dst, stagingDir, next)
}
