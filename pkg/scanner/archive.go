package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/google/uuid"
)

type parentArchive struct {
	statusID string
	relPath  string // relative path within parent archive
}

const (
	maxErrorSubfiles = 1000
	maxErrorTextLen  = 1 << 10
	truncatedMark    = "…[truncated]"
	// moreErrorsKey stands in ErrorSubfiles for the failed files beyond
	// maxErrorSubfiles; its value says how many.
	moreErrorsKey = "…[more failed files]"
)

// innerErrors summarizes the extracted files that failed, for the archive
// result: ErrorSubfiles is bounded, the count here is not.
type innerErrors struct {
	count         int
	first         string
	permanent     bool
	analysisCount int
	firstAnalysis string
}

type archiveStatus struct {
	inner         innerErrors
	started       bool
	finished      bool
	finishClaimed bool
	// abandoned archives get no result: the extraction of a sub-archive failed for
	// a reason that says nothing about the archive. Their folder is removed when
	// the last member in flight is done.
	abandoned       bool
	archiveLocation string
	identity        FileIdentity // of the top-level archive, checked before its action
	input           *inputFD     // descriptor of the top-level archive, closed before its action
	run             *ongoing     // the run of the top-level file it belongs to
	result          datamodel.Result
	analyzed        int
	total           int
	tmpFolder       string
	parentArchive   parentArchive // only for sub-archives (= empty for top-level)
}

type archiveStatusHandler struct {
	*sync.RWMutex
	statusByID map[string]archiveStatus
}

func newArchiveStatusHandler() (a *archiveStatusHandler) {
	a = &archiveStatusHandler{
		RWMutex:    new(sync.RWMutex),
		statusByID: make(map[string]archiveStatus),
	}
	return
}

// claimStart atomically claims the right to start an archive analysis.
// Only the first caller gets claimed=true with the status. Subsequent callers get claimed=false.
// found indicates whether the archive exists in the handler.
func (a *archiveStatusHandler) claimStart(id string) (status archiveStatus, claimed, found bool) {
	a.Lock()
	defer a.Unlock()
	status, found = a.statusByID[id]
	if !found || status.started {
		return
	}
	status.started = true
	claimed = true
	a.statusByID[id] = status
	return
}

// getStatus returns the archive status.
func (a *archiveStatusHandler) getStatus(id string) (status archiveStatus, ok bool) {
	a.RLock()
	status, ok = a.statusByID[id]
	a.RUnlock()
	return
}

func (a *archiveStatusHandler) addStatus(status archiveStatus) (id string) {
	id = uuid.NewString()
	a.Lock()
	a.statusByID[id] = status
	a.Unlock()
	return
}

func (a *archiveStatusHandler) decreaseTotal(id string) (finished bool, ok bool) {
	a.Lock()
	defer a.Unlock()
	status, ok := a.statusByID[id]
	if !ok || status.finishClaimed {
		return finished, false
	}
	ok = true
	status.total--
	if status.total == status.analyzed {
		status.finished = true
	}
	finished = status.finished
	a.statusByID[id] = status
	return
}

// addInnerError records an extracted file that was lost on its way to the
// analysis (unreadable, sub-archive that could not be extracted): the archive
// can no longer be taken for clean. It replaces decreaseTotal for such files.
func (a *archiveStatusHandler) addInnerError(id string, filename string, err error) (finished bool, ok bool) {
	a.Lock()
	defer a.Unlock()
	status, ok := a.statusByID[id]
	if !ok || status.finishClaimed {
		return finished, false
	}
	r := datamodel.Result{Error: err}
	status.result.ErrorSubfiles = addErrorSubfile(status.result.ErrorSubfiles, filename, err.Error())
	status.noteInner(filename, r)
	status.total--
	if status.total == status.analyzed {
		status.finished = true
	}
	finished = status.finished
	a.statusByID[id] = status
	return
}

// abandon marks the archive as abandoned. unsent is the number of its members
// that will never be sent. When no member is in flight any more, the status is
// deleted and removeNow is true: the caller removes the folder; otherwise the
// last member to come back finishes the archive, which then only cleans up.
func (a *archiveStatusHandler) abandon(id string, unsent int) (tmpFolder string, removeNow, ok bool) {
	a.Lock()
	defer a.Unlock()
	status, ok := a.statusByID[id]
	if !ok || status.finishClaimed {
		return "", false, false
	}
	status.abandoned = true
	status.total -= unsent
	if status.total <= status.analyzed {
		delete(a.statusByID, id)
		return status.tmpFolder, true, true
	}
	a.statusByID[id] = status
	return status.tmpFolder, false, true
}

func (a *archiveStatusHandler) deleteStatus(id string) {
	a.Lock()
	delete(a.statusByID, id)
	a.Unlock()
}

// claimFinish atomically claims the right to finalize an archive.
// Only the first caller gets claimed=true with the status. Subsequent callers get claimed=false.
// found indicates whether the archive exists in the handler.
func (a *archiveStatusHandler) claimFinish(id string) (status archiveStatus, claimed, found bool) {
	a.Lock()
	defer a.Unlock()
	status, found = a.statusByID[id]
	if !found || status.finishClaimed {
		return
	}
	status.finishClaimed = true
	claimed = true
	a.statusByID[id] = status
	return
}

func (a *archiveStatusHandler) setStarted(id string) {
	a.Lock()
	defer a.Unlock()
	status, ok := a.statusByID[id]
	if !ok {
		return
	}
	status.started = true
	a.statusByID[id] = status
}

func (a *archiveStatusHandler) addInnerFileResult(id string, filename string, result datamodel.Result) (finished bool, ok bool) {
	a.Lock()
	defer a.Unlock()
	status, ok := a.statusByID[id]
	if !ok || status.finishClaimed {
		return finished, false
	}
	status.analyzed++
	status.result = mergeResult(status.result, result, filename)
	status.noteInner(filename, result)
	if status.total == status.analyzed {
		status.finished = true
	}
	finished = status.finished
	a.statusByID[id] = status
	return
}

// setArchiveResult sets the archive result and marks the archive as finished.
// Any previously merged inner file results are discarded.
func (a *archiveStatusHandler) setArchiveResult(id string, result datamodel.Result) (ok bool) {
	a.Lock()
	defer a.Unlock()
	status, ok := a.statusByID[id]
	if !ok {
		return
	}
	status.analyzed++
	status.started = true
	status.finished = true
	status.result = result
	a.statusByID[id] = status
	return
}

// noteInner counts a failed extracted file and refreshes the archive Error and
// AnalysisError. Any failure except "too big" (handled by its own policy) keeps
// the archive from being treated as clean. A permanent cause wins over a
// transient one; an unknown cause is transient: in doubt the archive is
// retried.
func (s *archiveStatus) noteInner(filename string, r datamodel.Result) {
	if r.Error != nil && !errors.Is(r.Error, errFileTooBig) {
		s.inner.count++
		if s.inner.first == "" {
			s.inner.first = truncateText(filename+": "+r.Error.Error(), maxErrorTextLen)
		}
		if errors.Is(r.Error, errInnerPermanent) || errors.Is(r.Error, errInconsistentPluginResult) {
			s.inner.permanent = true
		}
		sentinel := errInnerTransient
		if s.inner.permanent {
			sentinel = errInnerPermanent
		}
		s.result.Error = fmt.Errorf("%w: %d extracted file(s) in error, first: %s", sentinel, s.inner.count, s.inner.first)
		if listed := listedErrors(s.result.ErrorSubfiles); s.inner.count > listed && listed >= maxErrorSubfiles {
			s.result.ErrorSubfiles[moreErrorsKey] = fmt.Sprintf("%d more failed file(s) not listed", s.inner.count-listed)
		}
	}
	if r.AnalysisError != "" {
		s.inner.analysisCount++
		if s.inner.firstAnalysis == "" {
			s.inner.firstAnalysis = truncateText(filename+": "+r.AnalysisError, maxErrorTextLen)
		}
		s.result.AnalysisError = s.inner.firstAnalysis
		if s.inner.analysisCount > 1 {
			s.result.AnalysisError = fmt.Sprintf("%s (and %d more)", s.inner.firstAnalysis, s.inner.analysisCount-1)
		}
	}
}

// truncateText cuts s to n bytes (on a character boundary) and marks the cut.
func truncateText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "") + truncatedMark
}

// truncateKey is truncateText for a name: a cut name gets a short hash of the
// whole name, so two long names with the same beginning stay distinct.
func truncateKey(name string) string {
	if len(name) <= maxErrorTextLen {
		return name
	}
	sum := sha256.Sum256([]byte(name))
	return truncateText(name, maxErrorTextLen) + "-" + hex.EncodeToString(sum[:4])
}

// addErrorSubfile records a failed extracted file, bounded in count and in
// text length: an archive can hold thousands of members with huge names.
func addErrorSubfile(m map[string]string, filename, msg string) map[string]string {
	if m == nil {
		m = make(map[string]string)
	}
	key := truncateKey(filename)
	if _, exists := m[key]; !exists && listedErrors(m) >= maxErrorSubfiles {
		return m
	}
	m[key] = truncateText(msg, maxErrorTextLen)
	return m
}

func listedErrors(m map[string]string) int {
	if _, ok := m[moreErrorsKey]; ok {
		return len(m) - 1
	}
	return len(m)
}

func mergeResult(baseResult, resultToMerge datamodel.Result, filename string) (result datamodel.Result) {
	result = baseResult
	for _, m := range resultToMerge.Malwares {
		if !slices.Contains(result.Malwares, m) {
			result.Malwares = append(result.Malwares, m)
		}
	}
	// Add 1 for current file + any files extracted from sub-archives
	result.TotalExtractedFile += 1 + resultToMerge.TotalExtractedFile
	result.Malware = baseResult.Malware || resultToMerge.Malware

	if result.MaliciousSubfiles == nil {
		result.MaliciousSubfiles = make(map[string]datamodel.Result)
	}
	if resultToMerge.Malware {
		resultToMerge.Location = baseResult.Location // We put archive location as location (cause extracted file won't be accessible after analysis)
		result.MaliciousSubfiles[filename] = resultToMerge
	}
	if resultToMerge.Error != nil {
		result.ErrorSubfiles = addErrorSubfile(result.ErrorSubfiles, filename, resultToMerge.Error.Error())
	}
	if resultToMerge.AnalysisError != "" {
		result.ErrorSubfiles = addErrorSubfile(result.ErrorSubfiles, filename, resultToMerge.AnalysisError)
	}
	result.AnalyzedVolume += resultToMerge.AnalyzedVolume
	result.FilteredVolume += resultToMerge.FilteredVolume
	if resultToMerge.Score > result.Score {
		result.Score = resultToMerge.Score
	}

	switch {
	case resultToMerge.MalwareReason == datamodel.MalwareDetected || baseResult.MalwareReason == datamodel.MalwareDetected:
		result.MalwareReason = datamodel.MalwareDetected
	case resultToMerge.MalwareReason == datamodel.AnalysisError || baseResult.MalwareReason == datamodel.AnalysisError:
		result.MalwareReason = datamodel.AnalysisError
	case resultToMerge.MalwareReason == datamodel.TooBig || baseResult.MalwareReason == datamodel.TooBig:
		result.MalwareReason = datamodel.TooBig
	case resultToMerge.MalwareReason == datamodel.FilteredFileType || baseResult.MalwareReason == datamodel.FilteredFileType:
		result.MalwareReason = datamodel.FilteredFileType
	case resultToMerge.MalwareReason == datamodel.FilteredFilePath || baseResult.MalwareReason == datamodel.FilteredFilePath:
		result.MalwareReason = datamodel.FilteredFilePath
	default:
		result.MalwareReason = ""
	}
	return
}
