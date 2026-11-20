//go:build !linux

package scanner

import "os"

// descriptorPathOS is not available: the plugins and the extractor read the path
// the file was deposited at.
func descriptorPathOS(*os.File) (string, bool) { return "", false }
