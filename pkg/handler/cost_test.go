package handler

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/glimps-re/host-connector/pkg/scanner"
)

func heapInUse() uint64 {
	var ms runtime.MemStats
	runtime.GC()
	runtime.GC()
	runtime.ReadMemStats(&ms)
	return ms.HeapAlloc
}

// The byte bound is the purpose of the table: the cost it counts must follow
// the measured heap, whatever the path lengths.
func TestCostMatchesRealHeap(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("calibrated on 64-bit")
	}
	const n = 100_000
	for _, plen := range []int{20, 100, 250} {
		t.Run(fmt.Sprintf("path%d", plen), func(t *testing.T) {
			now := time.Unix(1000, 0)
			tab := newFileTable(1<<40, 25, nil, []string{"/in"})
			pad := strings.Repeat("x", plen)
			before := heapInUse()
			for i := range n {
				tab.Track(fmt.Sprintf("/in/u%d/%s%d", i%1000, pad, i), scanner.FileIdentity{}, now, now.Add(time.Hour))
			}
			after := heapInUse()
			measured, counted := float64(after)-float64(before), float64(tab.Used())
			if diff := (counted - measured) / measured; diff < -0.10 || diff > 0.10 {
				t.Errorf("counted %.0f bytes for %.0f measured (%.1f%% off), recalibrate fileOverhead", counted, measured, diff*100)
			}
			runtime.KeepAlive(tab)
		})
	}
	if got := unsafe.Sizeof(trackedFile{}); got != expectedTrackedFileSize {
		t.Errorf("sizeof(trackedFile) = %d, want %d: a field changed, recalibrate fileOverhead", got, expectedTrackedFileSize)
	}
}

// expectedTrackedFileSize is the size fileOverhead was calibrated on (64-bit).
const expectedTrackedFileSize = 248
