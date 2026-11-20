//go:build linux

package plugins

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/glimps-re/host-connector/internal/pathutil"
)

// CheckExecutable decides whether path may be run by the connector. It must be
// absolute and, links resolved, a regular file with an execute bit. The file
// and its directory must belong to root, or to the connector account (to root
// only when the connector runs as root), and must not be writable by others.
// A file or directory writable by the group is a warning, a refusal for a
// connector running as root. It returns the resolved path and the warnings; an
// error names the path, the cause and the remedy.
func CheckExecutable(path string) (resolved string, warnings []string, err error) {
	if !filepath.IsAbs(path) {
		return "", nil, unsafe(path, "the path is not absolute", "give the absolute path of the binary")
	}
	// The plugin runs the configured path, not the resolved one: a link in the
	// chain that someone else can repoint would swap the binary after this check.
	// Only system links (owned by root, in a folder root owns) are accepted.
	if linkErr := pathutil.CheckTrustedPath(path, pathutil.TrustedLink); linkErr != nil && !errors.Is(linkErr, os.ErrNotExist) {
		return "", nil, unsafe(path, "the path crosses a symbolic link that is not a system link: "+linkErr.Error(), "give the real path of the binary, without that link")
	}
	resolved, err = filepath.EvalSymlinks(path)
	if err != nil {
		return "", nil, unsafe(path, "not found: "+err.Error(), "install the binary or fix the configured path")
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", nil, unsafe(path, "cannot be examined: "+err.Error(), "fix the configured path")
	}
	if !info.Mode().IsRegular() {
		return "", nil, unsafe(resolved, "not a regular file", "point to the binary itself")
	}
	if info.Mode().Perm()&0o111 == 0 {
		return "", nil, unsafe(resolved, "no execute permission", "chmod 500 "+resolved)
	}
	root := os.Geteuid() == 0
	for _, entry := range []struct {
		what string
		path string
		info os.FileInfo
	}{{"file", resolved, info}, {"directory", filepath.Dir(resolved), nil}} {
		fi := entry.info
		if fi == nil {
			if fi, err = os.Stat(entry.path); err != nil {
				return "", nil, unsafe(resolved, "its directory cannot be examined: "+err.Error(), "fix the configured path")
			}
		}
		w, err := checkOwnerAndWrite(entry.what, entry.path, fi, root)
		if err != nil {
			return "", nil, err
		}
		warnings = append(warnings, w...)
	}
	return resolved, warnings, nil
}

func checkOwnerAndWrite(what, path string, fi os.FileInfo, root bool) (warnings []string, err error) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, nil
	}
	account := currentAccount()
	fix := fmt.Sprintf("chown root %s ; chmod go-w %s", path, path)
	if root {
		if st.Uid != 0 {
			return nil, unsafe(path, fmt.Sprintf("the %s belongs to uid %d, not to root", what, st.Uid), fix)
		}
	} else if owner := int(st.Uid); owner != 0 && owner != os.Geteuid() {
		return nil, unsafe(path, fmt.Sprintf("the %s belongs to uid %d, not to root nor to the connector account %s", what, owner, account), fix)
	}
	perm := fi.Mode().Perm()
	if perm&0o002 != 0 {
		return nil, unsafe(path, fmt.Sprintf("the %s is writable by others (mode %04o)", what, perm), fix)
	}
	if perm&0o020 != 0 {
		if root {
			return nil, unsafe(path, fmt.Sprintf("the %s is writable by its group (mode %04o) and the connector runs as root", what, perm), fix)
		}
		warnings = append(warnings, fmt.Sprintf("%s %s is writable by its group (mode %04o): %s", what, path, perm, fix))
	}
	return warnings, nil
}

func currentAccount() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return strconv.Itoa(os.Geteuid())
}

func unsafe(path, cause, remedy string) error {
	return fmt.Errorf("%w: %s: %s; %s", ErrUnsafeExecutable, path, cause, remedy)
}

// CheckPluginFile decides whether a file may be loaded into the connector
// process (a plugin .so, the plugins file): it must be reached without any
// link that is not a system link, and the file and its directory must belong
// to root or to the connector account (root only for a connector running as
// root) and not be writable by others. Writable by the group is a warning, a
// refusal for root. Unlike CheckExecutable it does not ask for an execute bit.
func CheckPluginFile(path string) (warnings []string, err error) {
	if !filepath.IsAbs(path) {
		return nil, unsafe(path, "the path is not absolute", "give the absolute path of the file")
	}
	if linkErr := pathutil.CheckTrustedPath(path, pathutil.TrustedLink); linkErr != nil && !errors.Is(linkErr, os.ErrNotExist) {
		return nil, unsafe(path, "the path crosses a symbolic link that is not a system link: "+linkErr.Error(), "give the real path of the file")
	}
	// A system link may lead into a folder owned by someone else: the file and
	// the directory checked are those of the resolved path.
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, unsafe(path, "cannot be examined: "+err.Error(), "fix the configured path")
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return nil, unsafe(path, "cannot be examined: "+err.Error(), "fix the configured path")
	}
	if !info.Mode().IsRegular() {
		return nil, unsafe(resolved, "not a regular file", "point to the file itself")
	}
	root := os.Geteuid() == 0
	dirInfo, err := os.Stat(filepath.Dir(resolved))
	if err != nil {
		return nil, unsafe(resolved, "its directory cannot be examined: "+err.Error(), "fix the configured path")
	}
	for _, entry := range []struct {
		what, path string
		info       os.FileInfo
	}{{"file", resolved, info}, {"directory", filepath.Dir(resolved), dirInfo}} {
		w, checkErr := checkOwnerAndWrite(entry.what, entry.path, entry.info, root)
		if checkErr != nil {
			return nil, checkErr
		}
		warnings = append(warnings, w...)
	}
	return warnings, nil
}
