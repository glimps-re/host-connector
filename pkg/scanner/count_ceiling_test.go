package scanner

import (
	"math"
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
)

// The count of the files not analyzed can be set by a plugin; every sum the scanner
// makes of it stops at the ceiling and never wraps around to a negative count.
func TestNotAnalyzedCount_stopsAtTheCeilingWhateverAPluginSet(t *testing.T) {
	t.Run("members left out by the limits are added to a count set by a plugin", func(t *testing.T) {
		c := &Connector{}
		c.config.Unanalyzable.TooBig = PolicyPass
		result := datamodel.Result{NotAnalyzedSubfilesCount: math.MaxInt}
		extraction := plugins.Extraction{Skipped: []datamodel.NotAnalyzedFile{{FileName: "big.bin", Size: 10, Reason: datamodel.NotAnalyzedTooBig}}}
		if err := c.applyLimitSkips(extraction, 3, &result, "a.zip"); err != nil {
			t.Fatal(err)
		}
		if result.NotAnalyzedSubfilesCount != datamodel.MaxFileCount {
			t.Errorf("count = %d, want the ceiling %d", result.NotAnalyzedSubfilesCount, datamodel.MaxFileCount)
		}
	})
	t.Run("the count of a child archive is merged into the count of its parent", func(t *testing.T) {
		parent := datamodel.Result{NotAnalyzedSubfilesCount: math.MaxInt}
		child := datamodel.Result{NotAnalyzedSubfilesCount: math.MaxInt, NotAnalyzedSubfiles: []datamodel.NotAnalyzedFile{{FileName: "x", Reason: datamodel.NotAnalyzedTooBig}}}
		got := mergeNotAnalyzed(parent, child, "child.zip")
		if got.NotAnalyzedSubfilesCount != datamodel.MaxFileCount {
			t.Errorf("count = %d, want the ceiling %d", got.NotAnalyzedSubfilesCount, datamodel.MaxFileCount)
		}
	})
	t.Run("a member listed adds one to a count at the ceiling", func(t *testing.T) {
		got := appendNotAnalyzed(datamodel.Result{NotAnalyzedSubfilesCount: math.MaxInt}, datamodel.NotAnalyzedFile{FileName: "m", Reason: datamodel.NotAnalyzedEmpty})
		if got.NotAnalyzedSubfilesCount != datamodel.MaxFileCount {
			t.Errorf("count = %d, want the ceiling %d", got.NotAnalyzedSubfilesCount, datamodel.MaxFileCount)
		}
	})
	t.Run("a count under the ceiling stays exact", func(t *testing.T) {
		got := mergeNotAnalyzed(datamodel.Result{NotAnalyzedSubfilesCount: 5}, datamodel.Result{NotAnalyzedSubfilesCount: 7}, "c.zip")
		if got.NotAnalyzedSubfilesCount != 12 {
			t.Errorf("count = %d, want 12", got.NotAnalyzedSubfilesCount)
		}
	})
}
