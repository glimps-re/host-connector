package scanner

import (
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/google/uuid"
)

type parentArchive struct {
	statusID string
	relPath  string // relative path within parent archive
}

// innerErrors summarizes the extracted files that failed, for the archive
// result: ErrorSubfiles is bounded, the count here is not.
type innerErrors struct {
	// resume is the state of datamodel.UniqueKey for the keys of ErrorSubfiles,
	// kept for the life of the archive: names forced onto one key then cost one
	// step each, under the lock of the handler.
	resume        map[string]int
	count         int
	first         string
	permanent     bool
	analysisCount int
	firstAnalysis string
}

type archiveStatus struct {
	inner         innerErrors
	finished      bool
	finishClaimed bool
	// abandoned archives get no result: the extraction of a sub-archive failed for
	// a reason that says nothing about the archive. Their folder is removed when
	// the last member in flight is done.
	abandoned bool
	// dispatching is set once the members start to be sent: from then on the
	// result of the archive is what its members merge, and nothing replaces it.
	dispatching     bool
	archiveLocation string
	sha256          string       // hash computed by the pipeline, never replaced by a plugin
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

// skipInner ends a member that is not analyzed and not counted as a result
// (an empty file): the total of the archive is decreased and f is listed in
// its NotAnalyzedSubfiles, within MaxListedSubfiles, with an exact count.
func (a *archiveStatusHandler) skipInner(id string, f datamodel.NotAnalyzedFile) (finished, ok bool) {
	a.Lock()
	defer a.Unlock()
	status, ok := a.statusByID[id]
	if !ok || status.finishClaimed {
		return false, false
	}
	status.result = appendNotAnalyzed(status.result, f)
	status.total--
	if status.total == status.analyzed {
		status.finished = true
	}
	a.statusByID[id] = status
	return status.finished, true
}

// addInnerError records an extracted file that was lost on its way to the
// analysis (unreadable, sub-archive that could not be extracted): the archive
// can no longer be taken for clean. It replaces skipInner for such files.
func (a *archiveStatusHandler) addInnerError(id string, filename string, err error) (finished bool, ok bool) {
	a.Lock()
	defer a.Unlock()
	status, ok := a.statusByID[id]
	if !ok || status.finishClaimed {
		return finished, false
	}
	r := datamodel.Result{Error: err}
	status.result.ErrorSubfiles = addErrorSubfile(status.result.ErrorSubfiles, status.keyResume(), filename, err.Error())
	status.noteInner(filename, r)
	status.total--
	if status.total == status.analyzed {
		status.finished = true
	}
	finished = status.finished
	a.statusByID[id] = status
	return
}

// abandon gives up the extraction of an archive: unsent are the names of its
// members that will never be sent, and they no longer count in its total. Unless
// the outcome is abandonConcluded or abandonRemoveNow they are recorded at once
// as inner errors (see abandonOutcome). folder is the temporary folder of the archive, meaningful
// only for abandonRemoveNow.
func (a *archiveStatusHandler) abandon(id string, unsent []string) (outcome abandonOutcome, folder string) {
	a.Lock()
	defer a.Unlock()
	status, ok := a.statusByID[id]
	if !ok || status.finishClaimed {
		return abandonConcluded, ""
	}
	folder = status.tmpFolder
	status.total -= len(unsent)
	if !status.result.Malware && status.total <= status.analyzed {
		delete(a.statusByID, id)
		return abandonRemoveNow, folder
	}
	status.recordUnsent(unsent, len(unsent))
	if status.result.Malware {
		// The archive ends with its detection and is not abandoned.
		outcome = abandonDetectedLate
		if status.total <= status.analyzed {
			status.finished = true
			outcome = abandonDetectedNow
		}
		a.statusByID[id] = status
		return outcome, folder
	}
	status.abandoned = true
	a.statusByID[id] = status
	a.abandonAncestors(status.parentArchive.statusID)
	return abandonInFlight, folder
}

// abandonAncestors marks every live ancestor, up to the first one that has
// claimed its finish, as abandoned. It is done in the critical section of the
// abandon of the archive below: until its caller reaches the parent, the last
// member in flight of that archive can end it, and the parent would then count it
// as a normal member and end as a clean archive. An ancestor that already holds a
// detection is marked too and still ends with it (finishArchiveAnalysis only
// cleans up an abandoned archive that holds none). The walk stops at an ancestor
// whose finish is claimed or that is gone: nothing above it can be reached. The
// caller holds the lock.
func (a *archiveStatusHandler) abandonAncestors(id string) {
	for id != "" {
		p, found := a.statusByID[id]
		if !found || p.finishClaimed {
			return
		}
		p.abandoned = true
		a.statusByID[id] = p
		id = p.parentArchive.statusID
	}
}

// abandonOutcome is what abandoning an archive came to.
type abandonOutcome uint8

const (
	// abandonConcluded: the archive is gone or its finish was claimed, it ended elsewhere.
	abandonConcluded abandonOutcome = iota
	// abandonDetectedNow: the archive holds a detection and nothing is in flight, the caller finishes it.
	abandonDetectedNow
	// abandonDetectedLate: the archive holds a detection and members are in flight, the last one finishes it.
	abandonDetectedLate
	// abandonInFlight: no detection and members are in flight, the last one ends the archive.
	abandonInFlight
	// abandonRemoveNow: no detection and nothing in flight, the status is gone and the caller removes the folder.
	abandonRemoveNow
)

// errUnsent is why a member of an archive whose extraction was abandoned has no
// verdict: transient, since the extractor was only unavailable.
var errUnsent = fmt.Errorf("%w: the extractor was unavailable, the file was not analyzed", errInnerTransient)

// recordUnsent records members that were never sent as inner errors: the first
// datamodel.MaxListedSubfiles names are listed and all of them are counted, in one
// update of the summary.
func (s *archiveStatus) recordUnsent(names []string, count int) {
	if count <= 0 {
		return
	}
	for _, name := range names[:min(len(names), datamodel.MaxListedSubfiles)] {
		s.result.ErrorSubfiles = addErrorSubfile(s.result.ErrorSubfiles, s.keyResume(), name, errUnsent.Error())
	}
	first := ""
	if len(names) > 0 {
		first = names[0]
	}
	s.inner.count += count
	if s.inner.first == "" {
		s.inner.first = datamodel.CutText(first+": "+errUnsent.Error(), datamodel.MaxListedNameLen)
	}
	s.refreshInnerError()
}

// refreshInnerError rebuilds the error of the archive from the count of its failed
// members, and the count of those that are not listed.
func (s *archiveStatus) refreshInnerError() {
	sentinel := errInnerTransient
	if s.inner.permanent {
		sentinel = errInnerPermanent
	}
	s.result.Error = fmt.Errorf("%w: %s", sentinel, datamodel.ExtractedErrorsSummary(s.inner.count, s.inner.first))
	if listed := datamodel.ListedErrors(s.result.ErrorSubfiles); s.inner.count > listed && listed >= datamodel.MaxListedSubfiles {
		s.result.ErrorSubfiles[datamodel.MoreErrorsKey] = datamodel.MoreErrorsText(s.inner.count - listed)
	}
}

// markDispatching says that the members of the archive are being sent.
func (a *archiveStatusHandler) markDispatching(id string) {
	a.Lock()
	defer a.Unlock()
	if status, ok := a.statusByID[id]; ok {
		status.dispatching = true
		a.statusByID[id] = status
	}
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

func (a *archiveStatusHandler) addInnerFileResult(id string, filename string, result datamodel.Result) (finished bool, ok bool) {
	a.Lock()
	defer a.Unlock()
	status, ok := a.statusByID[id]
	if !ok || status.finishClaimed {
		return finished, false
	}
	status.analyzed++
	status.result = mergeResult(status.result, result, filename, status.keyResume())
	status.noteInner(filename, result)
	if status.total == status.analyzed {
		status.finished = true
	}
	finished = status.finished
	a.statusByID[id] = status
	return
}

// setArchiveResult gives the archive its own result and finishes it. What the
// archive learned from its members is merged into that result, never replaced
// by it. It is refused (busy) once members were sent and not all merged: the last
// of them finishes the archive.
func (a *archiveStatusHandler) setArchiveResult(id string, result datamodel.Result) (ok, busy bool) {
	a.Lock()
	defer a.Unlock()
	status, ok := a.statusByID[id]
	if !ok {
		return
	}
	if status.dispatching && status.analyzed < status.total {
		return true, true
	}
	restoreHardened(status.result, &result)
	ensureMalwareReason(&result)
	status.analyzed++
	status.finished = true
	status.result = result
	a.statusByID[id] = status
	return
}

// ensureMalwareReason gives a detection without reason the reason of a
// detection: a result that is malware always says why. It is enforced where
// plugin results enter the core and where results are combined.
func ensureMalwareReason(r *datamodel.Result) {
	if r.Malware && r.MalwareReason == "" {
		r.MalwareReason = datamodel.MalwareDetected
	}
}

// keyResume is the state that datamodel.UniqueKey keeps across the failed files
// of the archive.
func (s *archiveStatus) keyResume() map[string]int {
	if s.inner.resume == nil {
		s.inner.resume = make(map[string]int)
	}
	return s.inner.resume
}

// noteInner counts a failed extracted file and refreshes the archive Error and
// AnalysisError. Any failure keeps the archive from being treated as clean
// (a member too big or encrypted under the "error" policy included, and for
// good). A permanent cause wins over a transient one; an unknown cause is
// transient: in doubt the archive is retried.
func (s *archiveStatus) noteInner(filename string, r datamodel.Result) {
	if r.Error != nil {
		s.inner.count++
		if s.inner.first == "" {
			s.inner.first = datamodel.CutText(filename+": "+r.Error.Error(), datamodel.MaxListedNameLen)
		}
		if errors.Is(r.Error, errInnerPermanent) || errors.Is(r.Error, errInconsistentPluginResult) || errors.Is(r.Error, errFileTooBig) || errors.Is(r.Error, errEncrypted) {
			s.inner.permanent = true
		}
		s.refreshInnerError()
	}
	if r.AnalysisError != "" {
		s.inner.analysisCount++
		if s.inner.firstAnalysis == "" {
			s.inner.firstAnalysis = datamodel.CutText(filename+": "+r.AnalysisError, datamodel.MaxListedNameLen)
		}
		s.result.AnalysisError = s.inner.firstAnalysis
		if s.inner.analysisCount > 1 {
			s.result.AnalysisError = fmt.Sprintf("%s (and %d more)", s.inner.firstAnalysis, s.inner.analysisCount-1)
		}
	}
}

// addErrorSubfile records a failed extracted file, bounded in count and in
// text length: an archive can hold thousands of members with huge names. The key
// is unique and within the limit (datamodel.UniqueKey, which keeps resume for the
// archive): two members whose names share their beginning, or the same path
// twice, are both listed, and none takes the key of the count of those not listed.
func addErrorSubfile(m map[string]string, resume map[string]int, filename, msg string) map[string]string {
	if m == nil {
		m = make(map[string]string)
	}
	if datamodel.ListedErrors(m) >= datamodel.MaxListedSubfiles {
		return m
	}
	m[datamodel.UniqueKey(filename, m, resume)] = datamodel.CutText(msg, datamodel.MaxListedNameLen)
	return m
}

// memberAnalysisFailedText is what ErrorSubfiles says of a member the analysis
// failed on.
const memberAnalysisFailedText = "the analysis of the file failed"

func mergeResult(baseResult, resultToMerge datamodel.Result, filename string, keyResume map[string]int) (result datamodel.Result) {
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
		result.ErrorSubfiles = addErrorSubfile(result.ErrorSubfiles, keyResume, filename, resultToMerge.Error.Error())
	}
	if resultToMerge.AnalysisError != "" {
		// The text of the service stays in the log: the report names the member only.
		result.ErrorSubfiles = addErrorSubfile(result.ErrorSubfiles, keyResume, filename, memberAnalysisFailedText)
	}
	result = mergeNotAnalyzed(result, resultToMerge, filename)
	result.AnalyzedVolume = addVolume(result.AnalyzedVolume, resultToMerge.AnalyzedVolume)
	result.FilteredVolume = addVolume(result.FilteredVolume, resultToMerge.FilteredVolume)
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
	case resultToMerge.MalwareReason == datamodel.Encrypted || baseResult.MalwareReason == datamodel.Encrypted:
		result.MalwareReason = datamodel.Encrypted
	case resultToMerge.MalwareReason == datamodel.Empty || baseResult.MalwareReason == datamodel.Empty:
		result.MalwareReason = datamodel.Empty
	case resultToMerge.MalwareReason == datamodel.FilteredFileType || baseResult.MalwareReason == datamodel.FilteredFileType:
		result.MalwareReason = datamodel.FilteredFileType
	case resultToMerge.MalwareReason == datamodel.FilteredFilePath || baseResult.MalwareReason == datamodel.FilteredFilePath:
		result.MalwareReason = datamodel.FilteredFilePath
	default:
		result.MalwareReason = ""
	}
	ensureMalwareReason(&result)
	return
}

// mergeNotAnalyzed adds to base the members that merged did not analyze: the
// member itself when it was let through, and what its own sub-archive listed.
// The list is bounded, the count is exact.
func mergeNotAnalyzed(base, merged datamodel.Result, filename string) datamodel.Result {
	if merged.NotAnalyzedReason != "" {
		base = appendNotAnalyzed(base, datamodel.NotAnalyzedFile{FileName: filename, Size: merged.FileSize, Reason: merged.NotAnalyzedReason})
	}
	for _, f := range merged.NotAnalyzedSubfiles {
		base = appendNotAnalyzed(base, datamodel.NotAnalyzedFile{FileName: filename + "/" + f.FileName, Size: f.Size, Reason: f.Reason})
	}
	if extra := merged.NotAnalyzedSubfilesCount - len(merged.NotAnalyzedSubfiles); extra > 0 {
		base.NotAnalyzedSubfilesCount = datamodel.AddCount(base.NotAnalyzedSubfilesCount, extra)
	}
	return base
}

func appendNotAnalyzed(r datamodel.Result, f datamodel.NotAnalyzedFile) datamodel.Result {
	// Even an increment can wrap: a plugin can have set the count of the result.
	r.NotAnalyzedSubfilesCount = datamodel.AddCount(r.NotAnalyzedSubfilesCount, 1)
	if len(r.NotAnalyzedSubfiles) < datamodel.MaxListedSubfiles {
		f.FileName = datamodel.CutText(f.FileName, datamodel.MaxListedNameLen)
		r.NotAnalyzedSubfiles = append(r.NotAnalyzedSubfiles, f)
	}
	return r
}
