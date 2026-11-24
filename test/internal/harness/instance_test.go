//go:build linux

package harness

import (
	"testing"

	"github.com/glimps-re/host-connector/test/internal/fakes/gmalware"
)

// A scenario announces the uploads it expects the connector to cut, once, on
// the instance: the fake and the final check are told the same number.
func TestInstance_expectAbortedUploads(t *testing.T) {
	in := &Instance{gm: gmalware.New(t, false)}
	in.ExpectAbortedUploads(1)
	in.ExpectAbortedUploads(2)
	if in.abortedUploads != 3 || in.gm.Unconsumed() != 3 {
		t.Errorf("announced = %d, unconsumed = %d, want 3 and 3", in.abortedUploads, in.gm.Unconsumed())
	}
}
