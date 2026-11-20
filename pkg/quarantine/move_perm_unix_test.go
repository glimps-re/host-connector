//go:build unix

package quarantine

import "io/fs"

const stagingTooOpen fs.FileMode = 0o750
