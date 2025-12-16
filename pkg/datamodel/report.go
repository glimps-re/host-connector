package datamodel

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"time"
)

var LogLevel = &slog.LevelVar{}

var logger = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
	Level: LogLevel,
}))

type Report struct {
	Filename                string            `json:"filename"`
	SHA256                  string            `json:"sha256"`
	Malicious               bool              `json:"malicious"`
	Deleted                 bool              `json:"deleted,omitempty"`
	QuarantineLocation      string            `json:"quarantine-location,omitempty"`
	MitigationID            string            `json:"mitigation-id,omitempty"`
	GMalwareURL             string            `json:"gmalware-url,omitempty"`
	HasBeenRestored         bool              `json:"has-been-restored,omitempty"`
	MovedTo                 string            `json:"moved-to,omitempty"`
	Malwares                []string          `json:"malwares,omitempty"`
	FileSize                int64             `json:"size,omitempty"`
	FileType                string            `json:"type,omitempty"`
	AnalyzedVolume          int64             `json:"analyzed-volume,omitempty"`
	FilteredVolume          int64             `json:"filtered-volume,omitempty"`
	MalwareReason           MalwareReason     `json:"malware-reason,omitempty"`
	Action                  Action            `json:"mitigation-action,omitempty"`
	TotalExtractedFile      int               `json:"total-extracted-file,omitempty"`
	MaliciousExtractedFiles []ExtractedFile   `json:"malicious-extracted-files,omitempty"`
	ErrorExtractedFiles     map[string]string `json:"error-extracted-files,omitempty"`
}

type Action string

const (
	Logged      Action = "logged"
	Quarantined Action = "quarantined"
	Removed     Action = "removed"
)

type ExtractedFile struct {
	FileName       string          `json:"filename"`
	SHA256         string          `json:"sha256"`
	Malicious      bool            `json:"malicious"`
	Malwares       []string        `json:"malwares,omitempty"`
	Size           int64           `json:"size,omitempty"`
	MalwareReason  MalwareReason   `json:"malware-reason,omitempty"`
	GMalwareURL    string          `json:"gmalware-url,omitempty"`
	ExtractedFiles []ExtractedFile `json:"extracted-files,omitempty"`
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
		logger.Error("failed to flush buffer", slog.String("error", flushErr.Error()))
	}
	return
}

func GenerateReport(_ ScanContext, reports []Report) (r io.Reader, err error) {
	buffer := &bytes.Buffer{}
	out := json.NewEncoder(buffer)
	out.SetIndent("", "")
	err = out.Encode(reports)
	return buffer, err
}
