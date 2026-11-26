//go:build windows

package quarantine

import "io/fs"

const stagingTooOpen fs.FileMode = 0o700
