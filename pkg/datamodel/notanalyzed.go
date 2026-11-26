package datamodel

import (
	"strconv"
	"strings"
)

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
	// NotAnalyzedAnalysisError is a file the analysis failed on, let through by
	// unanalyzable_policy.analysis_error: pass.
	NotAnalyzedAnalysisError NotAnalyzedReason = "analysis-error"
	// NotAnalyzedSkippedPath is a file waived by skipped_paths.
	NotAnalyzedSkippedPath NotAnalyzedReason = "skipped-path"
	// NotAnalyzedSkippedType is a file waived by skipped_types.
	NotAnalyzedSkippedType NotAnalyzedReason = "skipped-type"
	// NotAnalyzedSymlink is a symbolic link found in an archive, not followed and
	// not analyzed.
	NotAnalyzedSymlink NotAnalyzedReason = "symlink"
)

const (
	// MaxListedSubfiles bounds the files listed in a result: not analyzed files,
	// failed files (and the one more entry that counts the failed files not
	// listed).
	MaxListedSubfiles = 1000
	// MaxListedNameLen bounds a listed name or message, in bytes; a longer one
	// is cut with a marker.
	MaxListedNameLen = 1024
)

// The Error of the report of an archive with failed members is a summary of
// them: a sentinel text (transient when a retry may change the outcome,
// permanent otherwise), the number of failed members and the first of them. They
// are listed one by one in ErrorSubfiles, so the summary is not an error of its
// own.
const (
	ExtractedErrorsTransient = "an extracted file could not be analyzed, will retry"
	ExtractedErrorsPermanent = "an extracted file cannot be analyzed"
	extractedErrorsSummary   = "extracted file(s) in error, first: "
)

// ExtractedErrorsSummary is the text of the summary after its sentinel: the
// count of failed members and the first of them.
func ExtractedErrorsSummary(count int, first string) string {
	return strconv.Itoa(count) + " " + extractedErrorsSummary + first
}

// IsExtractedErrorsSummary tells whether an Error is the summary built with
// ExtractedErrorsSummary after one of the two sentinels, and nothing else.
func IsExtractedErrorsSummary(msg string) bool {
	for _, sentinel := range []string{ExtractedErrorsTransient, ExtractedErrorsPermanent} {
		rest, ok := strings.CutPrefix(msg, sentinel+": ")
		if !ok {
			continue
		}
		digits, tail, ok := strings.Cut(rest, " ")
		if !ok || digits == "" || strings.Trim(digits, "0123456789") != "" {
			continue
		}
		if strings.HasPrefix(tail, extractedErrorsSummary) {
			return true
		}
	}
	return false
}

// NotAnalyzedFile is a file, or a member of an archive, that was not analyzed.
type NotAnalyzedFile struct {
	FileName string            `json:"filename"`
	Size     int64             `json:"size,omitempty"`
	Reason   NotAnalyzedReason `json:"reason"`
}
