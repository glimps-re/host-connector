package scanner

import (
	"errors"
	"fmt"
	"log/slog"
	"math"
	"sort"
	"strings"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
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
	// PolicyAsFile treats an archive that cannot be extracted as a plain file,
	// submitted as is and marked extract-error (Unanalyzable.ExtractError only).
	PolicyAsFile = "as_file"
)

// Unanalyzable is what becomes of the files that cannot be analyzed. A field
// left empty takes its default: PolicyError, and for Empty PolicyPass, or
// PolicySkip when the move action renames files (see resolve).
type Unanalyzable struct {
	// TooBig is the policy of a file over max_file_size that is not extracted.
	TooBig string
	// Empty is the policy of a file of size 0.
	Empty string
	// Encrypted is the policy of a file the extraction reports as encrypted.
	Encrypted string
	// ExtractError is the policy of an archive found damaged or inconsistent by
	// the extractor: PolicyError or PolicyAsFile.
	ExtractError string
	// AnalysisError is the policy of a file the analysis reported an error on
	// and found no detection in: PolicyError, PolicyMitigate or PolicyPass. A
	// detection is malware whatever this value.
	AnalysisError string
}

// resolve gives each empty field its default and checks the result. An empty
// file is delivered (PolicyPass) as a new empty file, which only the move by copy
// can make: with MoveModeRename an absent Empty becomes PolicySkip, so that a site
// kept in that mode still starts (fallback is then true), and an explicit
// PolicyPass is refused.
func (u Unanalyzable) resolve(mode MoveMode) (resolved Unanalyzable, fallback bool, err error) {
	if u.TooBig == "" {
		u.TooBig = PolicyError
	}
	if u.Empty == "" {
		u.Empty = PolicyPass
		if mode == MoveModeRename {
			u.Empty, fallback = PolicySkip, true
		}
	}
	if u.Encrypted == "" {
		u.Encrypted = PolicyError
	}
	if u.ExtractError == "" {
		u.ExtractError = PolicyError
	}
	if u.AnalysisError == "" {
		u.AnalysisError = PolicyError
	}
	return u, fallback, u.validate(mode)
}

// EffectiveMoveMode is the mode that counts for the empty files: the one of the
// move action when it is on, and the copy when it is off (there is no move to
// rename anything then).
func EffectiveMoveMode(moveOn bool, mode MoveMode) MoveMode {
	if !moveOn {
		return MoveModeCopy
	}
	return mode
}

// CheckUnanalyzable tells whether the policies and the mode of the move action
// can be applied together, before anything is stopped to apply them.
func CheckUnanalyzable(u Unanalyzable, mode MoveMode) error {
	_, _, err := u.resolve(mode)
	return err
}

func (u Unanalyzable) validate(mode MoveMode) error {
	if u.Empty == PolicyPass && mode == MoveModeRename {
		return errors.New("unanalyzable_policy.empty: pass delivers an empty file as a new empty file, which needs move.mode copy: it is refused with rename while the move action is on (leave the key out to skip empty files in that mode)")
	}
	for _, c := range []struct {
		key, value string
		allowed    []string
	}{
		{"too_big", u.TooBig, []string{PolicyError, PolicyPass, PolicyMitigate}},
		{"empty", u.Empty, []string{PolicySkip, PolicyPass, PolicyMitigate}},
		{"encrypted", u.Encrypted, []string{PolicyError, PolicyPass, PolicyMitigate}},
		{"extract_error", u.ExtractError, []string{PolicyError, PolicyAsFile}},
		{"analysis_error", u.AnalysisError, []string{PolicyError, PolicyPass, PolicyMitigate}},
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
//
// The volume rule: a file that was not analyzed adds its size to the filtered
// volume and nothing to the analyzed volume (a byte is never counted as both), and
// the volumes of the members of an archive are added to the archive's without
// wrapping around (see addVolume).
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
		markMitigated(&res, mitigationReason(reason))
		res.FilteredVolume = input.size
		logger.Warn("file mitigated without analysis", slog.String("file", input.location), slog.String(logReasonKey, string(reason)))
	default:
		res.Error = failure
	}
	return res
}

// mitigationScore is the score of a file mitigated without analysis.
const mitigationScore = 1000

// markMitigated makes res malware for a policy that mitigates: the reason, and a
// score that is never lower than mitigationScore nor lowers one that is higher.
func markMitigated(res *datamodel.Result, reason datamodel.MalwareReason) {
	res.Malware = true
	res.Score = max(res.Score, mitigationScore)
	res.MalwareReason = reason
}

// addVolume adds two volumes, which an archive can make as large as it declares:
// the sum saturates.
func addVolume(a, b int64) int64 {
	if b > 0 && a > math.MaxInt64-b {
		return math.MaxInt64
	}
	return a + b
}

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

// unanalyzableState is what made a file unanalyzable by nature, and the policy
// that decides what becomes of it.
type unanalyzableState struct {
	reason  datamodel.NotAnalyzedReason
	policy  string
	failure error
}

// stateOf tells what made a file unanalyzable by nature, if anything did: an
// encrypted archive, one the limits of the extraction left unopened, one the
// extractor found damaged. It decides, and does nothing.
func (c *Connector) stateOf(input fileToAnalyze) (state unanalyzableState, ok bool) {
	switch {
	case input.encrypted:
		return unanalyzableState{datamodel.NotAnalyzedEncrypted, c.config.Unanalyzable.Encrypted, input.encryptedFailure()}, true
	case input.limitSkipped:
		return unanalyzableState{datamodel.NotAnalyzedExtractLimit, c.limitSkippedPolicy(), errLimitSkipped}, true
	case input.extractError:
		return unanalyzableState{datamodel.NotAnalyzedExtractError, PolicyPass, nil}, true
	}
	return unanalyzableState{}, false
}

// applyUnanalyzableState applies to the result of a file the policy of what made
// it unanalyzable by nature, if anything did.
func (c *Connector) applyUnanalyzableState(input fileToAnalyze, result datamodel.Result) datamodel.Result {
	if state, ok := c.stateOf(input); ok {
		return c.policiedResult(input, result, state.reason, state.policy, state.failure)
	}
	return result
}

// applyAnalysisErrorPolicy applies unanalyzable_policy.analysis_error to the result
// of a file the analysis failed on (result.AnalysisError is set), and nothing was
// analyzed. A detection stays malware whatever the error. A file unanalyzable by
// nature follows its own policy first when that policy holds it (an error, or
// malware): analysis_error then only decides what its own policy lets through, and
// the reason of that policy never marks a file it did not hold. error leaves the
// file where it is, mitigate makes it malware (analysis-error), pass delivers it
// marked analysis-error, whatever its own policy let through.
func (c *Connector) applyAnalysisErrorPolicy(input fileToAnalyze, result datamodel.Result) datamodel.Result {
	if result.Malware {
		return result
	}
	if state, ok := c.stateOf(input); ok && state.policy != PolicyPass {
		logger.Warn("analysis failed on a file that its own policy holds", slog.String("file", input.location), slog.String(logErrorKey, result.AnalysisError))
		held := c.policiedResult(input, result, state.reason, state.policy, state.failure)
		held.AnalysisError = ""
		return held
	}
	switch c.config.Unanalyzable.AnalysisError {
	case PolicyMitigate:
		markMitigated(&result, datamodel.AnalysisError)
		result.AnalyzedVolume, result.FilteredVolume = 0, input.size
		logger.Warn("file mitigated, its analysis failed", slog.String("file", input.location), slog.String(logErrorKey, result.AnalysisError))
	case PolicyPass:
		logger.Warn("file passed, its analysis failed", slog.String("file", input.location), slog.String(logReasonKey, string(datamodel.NotAnalyzedAnalysisError)), slog.String(logErrorKey, result.AnalysisError))
		result.AnalysisError = ""
		result.NotAnalyzedReason = datamodel.NotAnalyzedAnalysisError
		result.AnalyzedVolume, result.FilteredVolume = 0, input.size
	}
	return result
}

// markPolicySkipped tells that a file a plugin let through (a result that is
// neither malware nor an error) reaches its destination without analysis: the
// reports say so, and so does the log.
func markPolicySkipped(r *datamodel.Result, location string) {
	if r.Malware || r.Error != nil || r.AnalysisError != "" || r.NotAnalyzedReason != "" {
		return
	}
	r.NotAnalyzedReason = datamodel.NotAnalyzedPolicySkipped
	logger.Warn("file passed without analysis", slog.String("file", location), slog.String(logReasonKey, string(datamodel.NotAnalyzedPolicySkipped)))
}

// applyLimitSkips applies the policy of the files too big to the members the
// extraction left out because of its limits (a member over the remaining extraction budget, too
// many members, too large a total). With PolicyError the archive fails for good:
// it stays where it is, and nothing is let through unseen. With PolicyPass the
// members are listed as not analyzed, with an exact count; with PolicyMitigate
// the archive is malware with the reason TooBig, and they are listed too.
func (c *Connector) applyLimitSkips(extraction plugins.Extraction, count int, result *datamodel.Result, location string) error {
	policy := c.config.Unanalyzable.TooBig
	if policy == PolicyError {
		return fmt.Errorf("%w: %d members were left out by the limits of the extraction", errInnerPermanent, count)
	}
	reasons := map[datamodel.NotAnalyzedReason]bool{}
	for _, f := range extraction.Skipped {
		reasons[f.Reason] = true
		result.FilteredVolume = addVolume(result.FilteredVolume, f.Size)
	}
	listNotAnalyzed(result, extraction.Skipped, count)
	reason := strings.Join(sortedReasons(reasons), ",")
	if policy == PolicyMitigate {
		markMitigated(result, datamodel.TooBig)
		logger.Warn("archive mitigated: members were left out by the limits of the extraction", slog.String("file", location), slog.Int("members", count), slog.String(logReasonKey, reason))
		return nil
	}
	logger.Warn("archive passed with members left out by the limits of the extraction", slog.String("file", location), slog.Int("members", count), slog.String(logReasonKey, reason))
	return nil
}

// listNotAnalyzed adds members to the files not analyzed of a result, within
// datamodel.MaxListedSubfiles, and their exact count. A plugin may have set the
// count of the result already: it is added to without wrapping around.
func listNotAnalyzed(result *datamodel.Result, members []datamodel.NotAnalyzedFile, count int) {
	for _, f := range members {
		if len(result.NotAnalyzedSubfiles) >= datamodel.MaxListedSubfiles {
			break
		}
		f.FileName = datamodel.CutText(f.FileName, datamodel.MaxListedNameLen)
		result.NotAnalyzedSubfiles = append(result.NotAnalyzedSubfiles, f)
	}
	result.NotAnalyzedSubfilesCount = datamodel.AddCount(result.NotAnalyzedSubfilesCount, count)
}

func sortedReasons(set map[datamodel.NotAnalyzedReason]bool) []string {
	out := make([]string, 0, len(set))
	for r := range set {
		out = append(out, string(r))
	}
	sort.Strings(out)
	return out
}
