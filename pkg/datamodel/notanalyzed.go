package datamodel

// NotAnalyzedReason tells why a file was not sent to the analysis.
type NotAnalyzedReason string

// Reasons a file is not analyzed.
const (
	NotAnalyzedTooBig        NotAnalyzedReason = "too-big"
	NotAnalyzedEmpty         NotAnalyzedReason = "empty"
	NotAnalyzedEncrypted     NotAnalyzedReason = "encrypted"
	NotAnalyzedExtractLimit  NotAnalyzedReason = "extract-limit"
	NotAnalyzedExtractError  NotAnalyzedReason = "extract-error"
	NotAnalyzedPolicySkipped NotAnalyzedReason = "policy-skipped"
	NotAnalyzedRestored      NotAnalyzedReason = "restored"
)

const (
	// MaxListedSubfiles bounds the not analyzed files listed in a result.
	MaxListedSubfiles = 1000
	// MaxListedNameLen bounds a listed name, in bytes; a longer one is
	// truncated with a marker.
	MaxListedNameLen = 1024
)

// NotAnalyzedFile is a file, or a member of an archive, that was not analyzed.
type NotAnalyzedFile struct {
	FileName string            `json:"filename"`
	Size     int64             `json:"size,omitempty"`
	Reason   NotAnalyzedReason `json:"reason"`
}
