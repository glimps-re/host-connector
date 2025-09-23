package report

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"time"
)

var Logger = slog.New(slog.NewJSONHandler(os.Stderr, nil))

type Report struct {
	FileName           string   `json:"file-name"`
	Sha256             string   `json:"sha256"`
	Malicious          bool     `json:"malicious"`
	Deleted            bool     `json:"deleted,omitempty"`
	QuarantineLocation string   `json:"quarantine-location,omitempty"`
	ExpertViewURL      string   `json:"expert-View-url,omitempty"`
	HasBeenRestored    bool     `json:"has-been-restored,omitempty"`
	MoveTo             string   `json:"move-to,omitempty"`
	Malware            []string `json:"malware,omitempty"`
}

type ReportsWriter struct {
	dst io.WriteSeeker
}

type ScanContext struct {
	ScanID string
	Start  time.Time
	End    time.Time
}

func NewReportsWriter(dst io.WriteSeeker) *ReportsWriter {
	return &ReportsWriter{dst: dst}
}

func (rw *ReportsWriter) Write(r Report) (err error) {
	// try to seek above last "\n]"
	n, _ := rw.dst.Seek(-2, io.SeekEnd)
	out := bufio.NewWriter(rw.dst)
	if n == 0 {
		// start of file
		if _, err = out.WriteString("[\n"); err != nil {
			return
		}
	} else {
		if _, err = out.WriteString(",\n"); err != nil {
			return
		}
	}

	encoder := json.NewEncoder(out)
	// encoder.SetIndent("  ", "")
	err = encoder.Encode(r)
	if err != nil {
		return
	}
	if _, err = out.WriteString("]"); err != nil {
		return
	}
	if flushErr := out.Flush(); flushErr != nil {
		Logger.Error("failed to flush buffer", slog.String("error", flushErr.Error()))
	}
	return
}

func GenerateReport(reportContext ScanContext, reports []Report) (r io.Reader, err error) {
	buffer := &bytes.Buffer{}
	out := json.NewEncoder(buffer)
	out.SetIndent("", "")
	err = out.Encode(reports)
	return buffer, err
}
