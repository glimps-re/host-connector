package scanner

import (
	"context"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"runtime/debug"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
)

// defaultGenerateReport renders the reports as a JSON array, written as the
// sequence is read into a pipe: no report is kept after it is written. The
// content is a ".json" file. Content.Close waits for the writer to end, which
// takes as long as the current step of the sequence, so the sequence must
// return promptly and honour ctx; it is no longer read once Close returns. The
// writer also ends, without anyone reading, when ctx ends, and the reader then
// gets ctx.Err() from Read.
func defaultGenerateReport(ctx context.Context, _ datamodel.ScanContext, reports iter.Seq2[datamodel.Report, error]) (plugins.GeneratedReport, error) {
	pr, pw := io.Pipe()
	content := &pipeContent{reader: pr, done: make(chan struct{})}
	go func() {
		defer close(content.done)
		// Unblocks a write nobody reads when ctx ends.
		stop := context.AfterFunc(ctx, func() { pw.CloseWithError(ctx.Err()) })
		defer stop()
		defer func() {
			// A sequence that panics must not take the process down: the reader
			// gets an error instead, and the stack goes to the log.
			if r := recover(); r != nil {
				logger.Error("the report sequence panicked", slog.Any("panic", r), slog.String("stack", string(debug.Stack())))
				pw.CloseWithError(fmt.Errorf("report generation failed: %v", r))
			}
		}()
		// A failing sequence or a cancelled context reaches the reader as the
		// error of its Read: the consumer must not keep what it got so far.
		pw.CloseWithError(writeJSONReports(ctx, pw, reports))
	}()
	return plugins.GeneratedReport{Content: content, Extension: ".json"}, nil
}

// pipeContent is the read side of the pipe; Close waits for the writer. The
// reader is a named field so that nothing of it, CloseWithError included, is
// promoted past that wait.
type pipeContent struct {
	reader *io.PipeReader
	done   chan struct{}
}

func (c *pipeContent) Read(p []byte) (int, error) { return c.reader.Read(p) }

// Close stops the writer and waits until it has ended.
func (c *pipeContent) Close() error {
	err := c.reader.Close()
	<-c.done
	return err
}

func writeJSONReports(ctx context.Context, w io.Writer, reports iter.Seq2[datamodel.Report, error]) error {
	return datamodel.WriteReportsJSON(ctx, w, reports)
}
