//go:build linux

package quarantine

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// ErrUnsafeLocation is returned when the quarantine directory could be
// modified by another account: restoring without a registry entry trusts that
// only the connector writes there.
var ErrUnsafeLocation = errors.New("unsafe quarantine directory")

// CheckLocation refuses an existing quarantine directory that is not owned by
// the connector account or root, or that the group or others can write to. An
// absent directory is accepted: the connector creates it with mode 0700. The
// error gives the command that fixes the directory.
func CheckLocation(dir string) error {
	info, err := os.Stat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("cannot check the quarantine directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%w: %q is not a directory", ErrUnsafeLocation, dir)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	account := currentAccount()
	fix := fmt.Sprintf("chown %s %s ; chmod 700 %s", account, dir, dir)
	if owner := int(st.Uid); owner != os.Geteuid() && owner != 0 {
		return fmt.Errorf("%w: %q belongs to uid %d, not to the connector account %s nor root; fix it with: %s", ErrUnsafeLocation, dir, owner, account, fix)
	}
	if perm := info.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("%w: %q is writable by its group or by others (mode %04o); fix it with: %s", ErrUnsafeLocation, dir, perm, fix)
	}
	return nil
}

func currentAccount() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return strconv.Itoa(os.Geteuid())
}
