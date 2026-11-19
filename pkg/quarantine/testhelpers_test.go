package quarantine

import (
	"crypto/sha256"
	"encoding/hex"
)

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

const testRestoreID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
