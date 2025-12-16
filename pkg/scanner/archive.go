package scanner

import (
	"slices"
	"sync"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/google/uuid"
)

type parentArchive struct {
	statusID string
	relPath  string // relative path within parent archive
}

type archiveStatus struct {
	started         bool
	finished        bool
	archiveLocation string
	result          datamodel.Result
	analyzed        int
	total           int
	tmpFolder       string
	parentArchive   parentArchive // only for sub-archives (= empty for top-level)
}

type archiveStatusHandler struct {
	*sync.RWMutex
	statusByID map[string]archiveStatus

	wg *sync.WaitGroup
}

func newArchiveStatusHandler() (a *archiveStatusHandler) {
	a = &archiveStatusHandler{
		RWMutex:    new(sync.RWMutex),
		statusByID: make(map[string]archiveStatus),
		wg:         &sync.WaitGroup{},
	}
	return
}

func (a *archiveStatusHandler) getArchiveStatus(id string, startArchiveAnalysis bool) (status archiveStatus, started bool, ok bool) {
	if startArchiveAnalysis {
		a.Lock()
		status, ok = a.statusByID[id]
		if !status.started {
			status.started = true
			started = true
			a.statusByID[id] = status
		}
		a.Unlock()
		return
	}
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
	if !ok {
		return
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

func (a *archiveStatusHandler) deleteStatus(id string) {
	a.Lock()
	delete(a.statusByID, id)
	a.Unlock()
}

func (a *archiveStatusHandler) addInnerFileResult(id string, filename string, result datamodel.Result) (finished bool, ok bool) {
	a.Lock()
	defer a.Unlock()
	status, ok := a.statusByID[id]
	if !ok {
		return
	}
	status.analyzed++
	status.result = mergeResult(status.result, result, filename)
	if status.total == status.analyzed {
		status.finished = true
	}
	finished = status.finished
	a.statusByID[id] = status
	return
}

func (a *archiveStatusHandler) addArchiveResult(id string, result datamodel.Result) (ok bool) {
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
		if result.ErrorSubfiles == nil {
			result.ErrorSubfiles = make(map[string]string)
		}
		result.ErrorSubfiles[filename] = resultToMerge.Error.Error()
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
