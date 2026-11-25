package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
)

// BenchmarkScanSmallFiles measures a scan of 2000 small files, text or binary,
// with the extraction off (the baseline) and on: each file is looked at for its
// type, to find out whether it is an archive too small to have been extracted
// before. (The small real archives are timed in the extract plugin.)
func BenchmarkScanSmallFiles(b *testing.B) {
	contents := map[string]func(i int) []byte{
		"text":   func(i int) []byte { return fmt.Appendf(nil, "small text file number %d", i) },
		"binary": func(i int) []byte { return fmt.Appendf(nil, "\x7f%04d\xff\xfe\x00\x10\x80", i) },
	}
	for name, content := range contents {
		in := b.TempDir()
		const files = 2000
		for i := range files {
			if err := os.WriteFile(filepath.Join(in, fmt.Sprintf("f%05d.dat", i)), content(i), 0o600); err != nil {
				b.Fatal(err)
			}
		}
		for _, extract := range []bool{false, true} {
			b.Run(fmt.Sprintf("%s/extract=%v", name, extract), func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					c, err := NewConnector(Config{Roots: []string{in}, Extract: extract, WorkDir: b.TempDir(), Workers: 4}, nil, cleanSubmitter())
					if err != nil {
						b.Fatal(err)
					}
					c.action = &MockAction{HandleMock: func(context.Context, Source, datamodel.Result, *datamodel.Report) error { return nil }}
					if err = c.Start(); err != nil {
						b.Fatal(err)
					}
					if err = c.ScanFile(b.Context(), in); err != nil {
						b.Fatal(err)
					}
					c.Close(b.Context())
				}
			})
		}
	}
}
