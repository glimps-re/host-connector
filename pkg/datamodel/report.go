package datamodel

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"iter"
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
	MoveConflictOf          string            `json:"move-conflict-of,omitempty"`
	Error                   string            `json:"error,omitempty"`
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
	// NotAnalyzedReason tells why the file reached its destination without a
	// complete analysis.
	NotAnalyzedReason NotAnalyzedReason `json:"not-analyzed-reason,omitempty"`
	// NotAnalyzedExtractedFiles lists the members of an archive that were not
	// analyzed, at most MaxListedSubfiles.
	NotAnalyzedExtractedFiles []NotAnalyzedFile `json:"not-analyzed-extracted-files,omitempty"`
	// NotAnalyzedExtractedCount is the exact number of such members, which the
	// list may not hold entirely.
	NotAnalyzedExtractedCount int `json:"not-analyzed-extracted-count,omitempty"`
}

// SessionReportPrefix starts the base name of every session report. A
// deposited file using it (in any letter case) is never moved to the
// destination: it could pass for a report.
const SessionReportPrefix = "report-session-"

// SessionSpoolDir is the folder, under the work directory of an instance, where
// the session plugin keeps the reports of its open sessions, one JSON Lines
// file per session ("<random>.jsonl", one Report per line).
const SessionSpoolDir = "session"

// SessionSpoolExt is the extension of the spool files of SessionSpoolDir and of
// the raw copy of a spool written as a last-resort session report.
const SessionSpoolExt = ".jsonl"

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
	n, seekErr := rw.dst.Seek(-2, io.SeekEnd)
	if seekErr != nil {
		// empty or new file, reset to start
		n = 0
	}
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

// ReportsSeq gives reports as the sequence a report generator reads: once, with
// no error.
func ReportsSeq(reports []Report) iter.Seq2[Report, error] {
	return func(yield func(Report, error) bool) {
		for _, r := range reports {
			if !yield(r, nil) {
				return
			}
		}
	}
}

// WriteReportsJSON writes the reports as a JSON array, one at a time as the
// sequence yields them: nothing is kept once written. A failing sequence or a
// cancelled context ends it with that error, and the output must then be
// discarded.
func WriteReportsJSON(ctx context.Context, w io.Writer, reports iter.Seq2[Report, error]) error {
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
