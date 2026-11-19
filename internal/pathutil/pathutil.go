// Package pathutil compares filesystem paths by component.
package pathutil

import (
	"path/filepath"
	"strings"
)

// Under reports whether p is root or lies under it. Both are compared
// lexically, component by component: /tmp/gmhost-ab is not under /tmp/gmhost-a,
// and a folder named "..x" is under its parent.
func Under(root, p string) bool {
	rel, err := filepath.Rel(root, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// Forms returns the absolute form of p, then its symlink-resolved form when
// different. A path that does not exist yet is resolved through its nearest
// existing ancestor. It touches the filesystem: use it where a link can be
// followed, not on every path of a walk.
func Forms(p string) []string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return []string{filepath.Clean(p)}
	}
	forms := []string{abs}
	if resolved := resolve(abs); resolved != abs {
		forms = append(forms, resolved)
	}
	return forms
}

func resolve(abs string) string {
	rest := ""
	for cur := abs; ; {
		if resolved, err := filepath.EvalSymlinks(cur); err == nil {
			return filepath.Join(resolved, rest)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return abs
		}
		rest = filepath.Join(filepath.Base(cur), rest)
		cur = parent
	}
}

// Same reports whether a and b designate the same path, links resolved.
func Same(a, b string) bool {
	for _, fa := range Forms(a) {
		for _, fb := range Forms(b) {
			if fa == fb {
				return true
			}
		}
	}
	return false
}

// UnderResolved is Under on every combination of the forms of root and p.
func UnderResolved(root, p string) bool {
	for _, fr := range Forms(root) {
		for _, fp := range Forms(p) {
			if Under(fr, fp) {
				return true
			}
		}
	}
	return false
}
