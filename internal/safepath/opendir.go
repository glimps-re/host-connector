package safepath

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// beforeCreate is called before each folder is created or opened; tests use it
// to swap a folder for a link at the worst moment.
var beforeCreate = func(string) {}

// OpenDir opens root/rel as a directory without following any symbolic link
// below root, creating the missing components with mode when create is true.
// The result is confined to the directory: a link that appears later cannot
// redirect what is done through it. root itself may be a link (it is trusted);
// rel "." opens root.
func OpenDir(root, rel string, create bool, mode os.FileMode) (*os.Root, error) {
	cur, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	rel = filepath.Clean(rel)
	if rel == "." {
		return cur, nil
	}
	if filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		closeRoot(cur)
		return nil, fmt.Errorf("%w: %q", ErrBadPath, rel)
	}
	for part := range strings.SplitSeq(rel, string(filepath.Separator)) {
		next, err := openChild(cur, part, create, mode)
		closeRoot(cur)
		if err != nil {
			return nil, err
		}
		cur = next
	}
	return cur, nil
}

// openChild opens the directory name of dir, creating it if asked. The entry is
// examined before and after it is opened: it must be a directory, not a link,
// and the same one.
func openChild(dir *os.Root, name string, create bool, mode os.FileMode) (*os.Root, error) {
	beforeCreate(name)
	pre, err := dir.Lstat(name)
	if err != nil && create && os.IsNotExist(err) {
		if err = dir.Mkdir(name, mode); err != nil && !os.IsExist(err) {
			return nil, err
		}
		pre, err = dir.Lstat(name)
	}
	if err != nil {
		return nil, err
	}
	if pre.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		return nil, fmt.Errorf("%w: %q", ErrSymlink, name)
	}
	if !pre.IsDir() {
		return nil, fmt.Errorf("%w: %q", ErrNotDir, name)
	}
	child, err := dir.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	post, err := child.Stat(".")
	if err != nil || !os.SameFile(pre, post) {
		closeRoot(child)
		return nil, fmt.Errorf("%w: %q was replaced while it was opened", ErrSymlink, name)
	}
	return child, nil
}

func closeRoot(r *os.Root) {
	if err := r.Close(); err != nil {
		slog.Warn("cannot close a directory handle", slog.String("error", err.Error()))
	}
}
