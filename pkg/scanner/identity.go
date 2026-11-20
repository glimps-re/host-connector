package scanner

import (
	"io/fs"
	"os"
	"time"
)

// FileIdentity identifies one state of one file. ChangeTime cannot be set by
// the file owner and changes on any write, rename-over or metadata update.
// Dev, Ino and ChangeTime are zero where the system does not provide them
// (anything but Linux): the identity then reduces to size and modification time.
type FileIdentity struct {
	Dev, Ino   uint64
	Size       int64
	ModTime    time.Time
	ChangeTime time.Time
}

// IdentityOf returns the identity of the file described by info.
func IdentityOf(info fs.FileInfo) FileIdentity {
	id := FileIdentity{Size: info.Size(), ModTime: info.ModTime()}
	id.Dev, id.Ino, id.ChangeTime = systemIdentity(info)
	return id
}

// Equal reports whether a and b identify the same state of the same file.
func (a FileIdentity) Equal(b FileIdentity) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Size == b.Size &&
		a.ModTime.Equal(b.ModTime) && a.ChangeTime.Equal(b.ChangeTime)
}

// Diff names the first field in which a and b differ, for the diagnostic of a
// file that changed.
func (a FileIdentity) Diff(b FileIdentity) string {
	switch {
	case a.Dev != b.Dev:
		return "device"
	case a.Ino != b.Ino:
		return "inode"
	case a.Size != b.Size:
		return "size"
	case !a.ModTime.Equal(b.ModTime):
		return "modification time"
	case !a.ChangeTime.Equal(b.ChangeTime):
		return "change time"
	default:
		return ""
	}
}

// IsLinkToFolder reports whether path is a symbolic link that leads to a
// folder. A tree walk never goes through one: it would leave the tree (the work
// directory, /etc, a parent) or loop.
func IsLinkToFolder(path string) bool {
	linfo, err := os.Lstat(path)
	if err != nil || linfo.Mode()&fs.ModeSymlink == 0 {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
