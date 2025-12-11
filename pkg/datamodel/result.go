package datamodel

type Result struct {
	MaliciousSubfiles  map[string]Result `json:"malicious-subfiles,omitempty"`
	Filename           string            `json:"filename,omitempty"`
	Location           string            `json:"location,omitempty"`
	SHA256             string            `json:"sha256,omitempty"`
	Malware            bool              `json:"malware,omitempty"`
	Malwares           []string          `json:"malwares,omitempty"`
	FileSize           int64             `json:"size,omitempty"`
	FileType           string            `json:"type,omitempty"`
	AnalyzedVolume     int64             `json:"analyzed-volume,omitempty"`
	FilteredVolume     int64             `json:"filtered-volume,omitempty"`
	Score              int               `json:"score,omitempty"`
	TotalExtractedFile int               `json:"total-extracted-file,omitempty"`
	MalwareReason      MalwareReason     `json:"malware-reason"`
	Error              error             `json:"-"`
	AnalysisError      string            `json:"analysis-error"`
	GMalwareURL        string            `json:"glimps-malware-url"`
	Restored           bool              `json:"restored,omitempty"`
}

type MalwareReason string

const (
	MalwareDetected  MalwareReason = "malware-detected"
	AnalysisError    MalwareReason = "analysis-error"
	TooBig           MalwareReason = "too-big"
	FilteredFileType MalwareReason = "filtered-filetype"
	FilteredFilePath MalwareReason = "filtered-filepath"
)
