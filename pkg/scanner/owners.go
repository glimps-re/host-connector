package scanner

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/glimps-re/host-connector/internal/pathutil"
)

// OwnerRule declares how the files below Root are grouped into owners for the
// fair sharing of the monitoring table: one owner per directory at Depth below
// Root.
type OwnerRule struct {
	Root  string
	Depth int
}

// ErrInvalidOwnerRule is returned for a declaration the monitor cannot use.
var ErrInvalidOwnerRule = errors.New("invalid tracking owners declaration")

// DeclareOwners adds a rule to rules. Root must be absolute, Depth at least 1,
// and Root must neither equal, contain nor lie under a declared root: with
// overlaps the owner of a file would depend on an implicit precedence.
func DeclareOwners(rules []OwnerRule, root string, depth int) ([]OwnerRule, error) {
	if !filepath.IsAbs(root) {
		return rules, fmt.Errorf("%w: root %q is not absolute", ErrInvalidOwnerRule, root)
	}
	if depth < 1 {
		return rules, fmt.Errorf("%w: depth %d is below 1", ErrInvalidOwnerRule, depth)
	}
	root = filepath.Clean(root)
	for _, r := range rules {
		if pathutil.Under(r.Root, root) || pathutil.Under(root, r.Root) {
			return rules, fmt.Errorf("%w: root %q overlaps the declared root %q", ErrInvalidOwnerRule, root, r.Root)
		}
	}
	return append(rules, OwnerRule{Root: root, Depth: depth}), nil
}

// OwnerOf returns the owner of the file at path: the directory at the declared
// depth below its root, or its parent directory when the file sits closer to
// the root; outside every declared root, the first-level directory under the
// watched path (the watched path itself for a file at its top). Paths are
// compared by component.
func OwnerOf(path string, rules []OwnerRule, watched []string) string {
	path = filepath.Clean(path)
	for _, r := range rules {
		if !pathutil.Under(r.Root, path) {
			continue
		}
		rel, err := filepath.Rel(r.Root, path)
		if err != nil {
			break
		}
		dirs := splitDirs(rel)
		if len(dirs) >= r.Depth {
			return filepath.Join(append([]string{r.Root}, dirs[:r.Depth]...)...)
		}
		return filepath.Dir(path)
	}
	// The shortest watched path: an owner never splits because a second
	// watched path lies under the first.
	best := ""
	for _, w := range watched {
		w = filepath.Clean(w)
		if pathutil.Under(w, path) && (best == "" || len(w) < len(best)) {
			best = w
		}
	}
	if best == "" {
		return filepath.Dir(path)
	}
	rel, err := filepath.Rel(best, path)
	if err != nil {
		return best
	}
	if dirs := splitDirs(rel); len(dirs) > 0 {
		return filepath.Join(best, dirs[0])
	}
	return best
}

// splitDirs returns the directory components of rel, the file name excluded.
func splitDirs(rel string) []string {
	var parts []string
	rel = filepath.ToSlash(rel)
	start := 0
	for i := 0; i <= len(rel); i++ {
		if i == len(rel) || rel[i] == '/' {
			if i > start {
				parts = append(parts, rel[start:i])
			}
			start = i + 1
		}
	}
	if len(parts) == 0 {
		return nil
	}
	return parts[:len(parts)-1]
}
