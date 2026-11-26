//go:build !unix

package quarantine

import "os"

// containerOpenFlags: no system flag refuses a link here, the file opened is
// checked to be a regular file after the opening.
const containerOpenFlags = os.O_RDONLY
