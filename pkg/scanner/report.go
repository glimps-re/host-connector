package scanner

import (
	"bufio"
	"encoding/json"
	"io"
)

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
	err = out.Flush()
	if err != nil {
		return
	}
	return
}
