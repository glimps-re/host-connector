package scanner

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
)

// With the default (the key left out, the move by copy) an empty file is
// delivered as a new empty file, marked empty in its report, and its source is
// removed; with skip it stays where it is, as before.
func TestPipeline_anEmptyFileIsDeliveredByDefault(t *testing.T) {
	for _, tt := range []struct {
		name      string
		policy    string
		delivered bool
	}{{"default", "", true}, {"explicit pass", PolicyPass, true}, {"skip", PolicySkip, false}} {
		t.Run(tt.name, func(t *testing.T) {
			in, out := t.TempDir(), t.TempDir()
			src := filepath.Join(in, "e.bin")
			if err := os.WriteFile(src, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			c, err := NewConnector(Config{
				Roots: []string{in}, WorkDir: t.TempDir(), Workers: 1, Unanalyzable: Unanalyzable{Empty: tt.policy},
				Actions: Actions{Move: true}, MoveTo: out, MoveFrom: in, MoveMode: MoveModeCopy,
			}, nil, cleanSubmitter())
			if err != nil {
				t.Fatal(err)
			}
			var mu sync.Mutex
			var reports []datamodel.Report
			c.RegisterOnReport(func(r *datamodel.Report) {
				mu.Lock()
				defer mu.Unlock()
				reports = append(reports, *r)
			})
			if err = c.Start(); err != nil {
				t.Fatal(err)
			}
			if err = c.ScanFile(t.Context(), src); err != nil {
				t.Fatal(err)
			}
			c.Close(t.Context())
			dst := filepath.Join(out, "e.bin")
			info, dstErr := os.Stat(dst)
			_, srcErr := os.Stat(src)
			mu.Lock()
			defer mu.Unlock()
			if !tt.delivered {
				if dstErr == nil || srcErr != nil || len(reports) != 0 {
					t.Errorf("skip: destination %v, source %v, %d reports: want the file left in place and no report", dstErr, srcErr, len(reports))
				}
				return
			}
			if dstErr != nil || info.Size() != 0 {
				t.Fatalf("destination: %v (%v), want a new empty file", info, dstErr)
			}
			if srcErr == nil {
				t.Error("the source must be removed")
			}
			if len(reports) != 1 || reports[0].NotAnalyzedReason != datamodel.NotAnalyzedEmpty || reports[0].Error != "" || reports[0].MovedTo == "" {
				t.Errorf("reports = %+v, want one marked empty, moved, without error", reports)
			}
		})
	}
}
