package scanner

import (
	"fmt"
	"log/slog"

	"github.com/glimps-re/host-connector/pkg/datamodel"
)

// Policies of the unanalyzable files, the values of Unanalyzable.
const (
	// PolicyError fails the file: it is not delivered.
	PolicyError = "error"
	// PolicyPass delivers the file as it is, marked as not analyzed.
	PolicyPass = "pass"
	// PolicyMitigate treats the file as a detected malware.
	PolicyMitigate = "mitigate"
	// PolicySkip ignores the file (the policy of an empty file).
	PolicySkip = "skip"
)

// Unanalyzable is what becomes of the files that cannot be analyzed. A field
// left empty takes its default: PolicyError, and PolicySkip for Empty.
type Unanalyzable struct {
	// TooBig is the policy of a file over max_file_size that is not extracted.
	TooBig string
	// Empty is the policy of a file of size 0.
	Empty string
	// Encrypted is the policy of a file the extraction reports as encrypted.
	Encrypted string
	// ExtractError is the policy of an archive that cannot be extracted; only
	// PolicyError is available.
	ExtractError string
}

func (u Unanalyzable) withDefaults() Unanalyzable {
	if u.TooBig == "" {
		u.TooBig = PolicyError
	}
	if u.Empty == "" {
		u.Empty = PolicySkip
	}
	if u.Encrypted == "" {
		u.Encrypted = PolicyError
	}
	if u.ExtractError == "" {
		u.ExtractError = PolicyError
	}
	return u
}

func (u Unanalyzable) validate() error {
	for _, c := range []struct {
		key, value string
		allowed    []string
	}{
		{"too_big", u.TooBig, []string{PolicyError, PolicyPass, PolicyMitigate}},
		{"empty", u.Empty, []string{PolicySkip, PolicyMitigate}}, // pass is refused: delivering an empty file needs the move by copy to be the rule, which the validation does not know yet
		{"encrypted", u.Encrypted, []string{PolicyError, PolicyPass, PolicyMitigate}},
		{"extract_error", u.ExtractError, []string{PolicyError}},
	} {
		ok := false
		for _, a := range c.allowed {
			ok = ok || c.value == a
		}
		if !ok {
			return fmt.Errorf("unanalyzable_policy.%s: %q is not one of %v", c.key, c.value, c.allowed)
		}
	}
	return nil
}

// unanalyzedResult is the result of a file that was not analyzed because of
// reason, under policy. For PolicyError the result carries failure; for the
// others it carries no error. The file passed through without a full analysis
// is always written in the log.
func (c *Connector) unanalyzedResult(input fileToAnalyze, reason datamodel.NotAnalyzedReason, policy string, failure error) datamodel.Result {
	res := datamodel.Result{
		Filename: input.filename,
		Location: input.location,
		SHA256:   input.sha256,
		FileSize: input.size,
	}
	switch policy {
	case PolicyPass:
		res.NotAnalyzedReason = reason
		res.FilteredVolume = input.size
		logger.Warn("file passed without analysis", slog.String("file", input.location), slog.String(logReasonKey, string(reason)))
	case PolicyMitigate:
		res.Malware = true
		res.Score = mitigationScore
		res.MalwareReason = mitigationReason(reason)
		res.FilteredVolume = input.size
		logger.Warn("file mitigated without analysis", slog.String("file", input.location), slog.String(logReasonKey, string(reason)))
	default:
		res.Error = failure
	}
	return res
}

// mitigationScore is the score of a file mitigated without analysis, the one
// of the former filesize_filter plugin.
const mitigationScore = 1000

func mitigationReason(reason datamodel.NotAnalyzedReason) datamodel.MalwareReason {
	switch reason {
	case datamodel.NotAnalyzedEmpty:
		return datamodel.Empty
	case datamodel.NotAnalyzedEncrypted:
		return datamodel.Encrypted
	default:
		return datamodel.TooBig
	}
}

// markPolicySkipped tells that a file a plugin let through (a result that is
// neither malware nor an error) reaches its destination without analysis: the
// reports say so, and so does the log.
func markPolicySkipped(r *datamodel.Result, location string) {
	if r.Malware || r.Error != nil || r.NotAnalyzedReason != "" {
		return
	}
	r.NotAnalyzedReason = datamodel.NotAnalyzedPolicySkipped
	logger.Warn("file passed without analysis", slog.String("file", location), slog.String(logReasonKey, string(datamodel.NotAnalyzedPolicySkipped)))
}
