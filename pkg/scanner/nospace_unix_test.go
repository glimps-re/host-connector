//go:build !windows

package scanner

import (
	"os"
	"syscall"
	"testing"
)

func TestIsNoSpace_aQuotaIsAFullDisk(t *testing.T) {
	for _, errno := range []error{syscall.ENOSPC, syscall.EDQUOT} {
		err := &os.PathError{Op: "write", Err: errno}
		if !isNoSpace(err) || !isResourceAction(err) {
			t.Errorf("%v must be a resource failure", errno)
		}
	}
	if isNoSpace(syscall.EACCES) {
		t.Error("EACCES is not a full disk")
	}
}
