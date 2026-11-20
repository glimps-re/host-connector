package scanner

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"iter"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
)

// defaultGenerateReport renders the reports as a JSON array, written as the
// sequence is read into a pipe: no report is kept after it is written. The
// content is a ".json" file. The caller closes it on every path: after Close the
// sequence may still produce one more report, and the context is only looked at
// between two reports.
func defaultGenerateReport(ctx context.Context, _ datamodel.ScanContext, reports iter.Seq2[datamodel.Report, error]) (plugins.GeneratedReport, error) {
	pr, pw := io.Pipe()
	go func() {
		defer func() {
			// A sequence that panics (or ignores a stop) must not take the process
			// down: the reader gets an error instead.
			if r := recover(); r != nil {
				pw.CloseWithError(fmt.Errorf("report generation failed: %v", r))
			}
		}()
		// A failing sequence or a cancelled context reaches the reader as the
		// error of its Read: the consumer must not keep what it got so far.
		pw.CloseWithError(writeJSONReports(ctx, pw, reports))
	}()
	return plugins.GeneratedReport{Content: pr, Extension: ".json"}, nil
}

func writeJSONReports(ctx context.Context, w io.Writer, reports iter.Seq2[datamodel.Report, error]) error {
	out := bufio.NewWriter(w)
	if _, err := out.WriteString("["); err != nil {
		return err
	}
	first := true
	for report, err := range reports {
		if err != nil {
			return err
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		if !first {
			if _, err = out.WriteString(","); err != nil {
				return err
			}
		}
		first = false
		encoded, err := json.Marshal(report)
		if err != nil {
			return err
		}
		if _, err = out.Write(encoded); err != nil {
			return err
		}
	}
	if _, err := out.WriteString("]\n"); err != nil {
		return err
	}
	return out.Flush()
}
