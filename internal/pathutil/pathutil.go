// Package pathutil compares filesystem paths by component.
package pathutil

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
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

// ErrSymlinkInPath is returned when a path component below the root is a
// symbolic link: whoever controls a folder under the root could swap it for a
// link and make the program read, move, delete or write outside its tree.
var ErrSymlinkInPath = errors.New("path crosses a symbolic link")

// CheckNoSymlink Lstat-s every component of path below root, path included. The
// root itself is trusted (an operator may monitor a link), as is anything above
// it. A path outside root, or a component that cannot be examined, is refused.
func CheckNoSymlink(root, path string) error {
	return checkNoSymlink(root, path, false)
}

// CheckExistingNoSymlink is CheckNoSymlink for a path that may not exist yet:
// it stops at the first missing component.
func CheckExistingNoSymlink(root, path string) error {
	return checkNoSymlink(root, path, true)
}

func checkNoSymlink(root, path string, allowMissing bool) error {
	root, path = filepath.Clean(root), filepath.Clean(path)
	if !Under(root, path) {
		return fmt.Errorf("%w: %q is not under %q", ErrSymlinkInPath, path, root)
	}
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == "." {
		return err
	}
	cur := root
	for part := range strings.SplitSeq(rel, string(filepath.Separator)) {
		cur = filepath.Join(cur, part)
		fi, err := os.Lstat(cur)
		switch {
		case err == nil:
		case allowMissing && errors.Is(err, fs.ErrNotExist):
			return nil
		default:
			return err
		}
		if isLinkLike(fi.Mode()) {
			return fmt.Errorf("%w: %q", ErrSymlinkInPath, cur)
		}
	}
	return nil
}

// isLinkLike reports whether mode is a symbolic link, or an irregular entry:
// Go reports a Windows junction as irregular, without the symlink bit.
func isLinkLike(mode fs.FileMode) bool {
	return mode&(os.ModeSymlink|os.ModeIrregular) != 0
}

// IsLinkLike is isLinkLike for callers outside the package.
func IsLinkLike(mode fs.FileMode) bool { return isLinkLike(mode) }

// MaxLinks bounds the links CheckTrustedPath follows in one path.
const MaxLinks = 8

// CheckTrustedPath walks path from the filesystem root, component by
// component, for a destination outside any monitored path. A link is followed
// only when trusted(link, parentDir) allows it; the walk goes on through its
// target and any further link, at most MaxLinks of them. A missing component
// is an error: nothing is created there.
func CheckTrustedPath(path string, trusted func(link, parent fs.FileInfo) bool) error {
	path = filepath.Clean(path)
	vol := filepath.VolumeName(path)
	top := vol + string(filepath.Separator)
	cur := top
	remaining := splitPath(path[len(vol):])
	links := 0
	for len(remaining) > 0 {
		comp := remaining[0]
		remaining = remaining[1:]
		switch comp {
		case "", ".":
			continue
		case "..":
			cur = filepath.Dir(cur)
			continue
		}
		next := filepath.Join(cur, comp)
		fi, err := os.Lstat(next)
		if err != nil {
			return err
		}
		if !isLinkLike(fi.Mode()) {
			cur = next
			continue
		}
		links++
		if fi.Mode()&os.ModeSymlink == 0 || links > MaxLinks {
			return fmt.Errorf("%w: %q", ErrSymlinkInPath, next)
		}
		parent, err := os.Lstat(cur)
		if err != nil {
			return err
		}
		if !trusted(fi, parent) {
			return fmt.Errorf("%w: %q", ErrSymlinkInPath, next)
		}
		target, err := os.Readlink(next)
		if err != nil {
			return err
		}
		if filepath.IsAbs(target) {
			tvol := filepath.VolumeName(target)
			cur = tvol + string(filepath.Separator)
			target = target[len(tvol):]
		}
		remaining = append(splitPath(target), remaining...)
	}
	return nil
}

func splitPath(p string) []string {
	return strings.Split(p, string(filepath.Separator))
}
