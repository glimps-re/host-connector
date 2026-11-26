//go:build !unix

package pathutil

import "io/fs"

// TrustedLink trusts no link: ownership cannot be established portably.
func TrustedLink(_, _ fs.FileInfo) bool { return false }
