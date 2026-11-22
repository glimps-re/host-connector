package scanner

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
)

// errPathRulesSlow is the failure of a scan whose listings the forbidden paths
// could not be matched against within pathRulesBudget of matching time.
// errRestoredUnchecked refuses a restored archive whose members cannot be known
// while paths are forbidden: it is not delivered unchecked.
var errRestoredUnchecked = fmt.Errorf("%w: restored archive could not be checked against forbidden_paths", errInnerPermanent)

var errPathRulesSlow = fmt.Errorf("%w: the path rules took too long on the listings of the archives of a file", errInnerPermanent)

// pathRulesBudget bounds the time spent matching the listings of the archives of
// one top-level file, added up over them; the clock is a variable for the tests.
const pathRulesBudget = 30 * time.Second

var pathRulesClock = time.Now

// errNoRun is the failure of matching the listing of an archive that belongs to no
// run of a top-level file: the time it takes could not be accounted for.
var errNoRun = errors.New("no run to account for the time of the path rules")

// spendRulesTime adds d to the time that the matching of the listings of the
// archives of the file has taken, and says whether the total is still within
// pathRulesBudget. Only the time spent matching counts, not the time between two
// listings.
func (o *ongoing) spendRulesTime(d time.Duration) (within bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.rulesSpent += d
	return o.rulesSpent <= pathRulesBudget
}

// rulesTimeLeft is what is left of pathRulesBudget.
func (o *ongoing) rulesTimeLeft() time.Duration {
	o.mu.Lock()
	defer o.mu.Unlock()
	return pathRulesBudget - o.rulesSpent
}

// skipAllowed tells whether the skipped paths may waive the file. They do not when
// the skip was withdrawn (the members of the archive could not be listed), nor,
// with forbidden paths set, for an archive that the limits did not let list.
func (c *Connector) skipAllowed(f fileToAnalyze) bool {
	return !f.noSkip && (!f.limitSkipped || !c.config.PathFilter.hasForbidden())
}

// skippedArchive handles an archive that a skipped path covers. It is not
// extracted and none of its members is analyzed, but a forbidden path still refuses
// it: with forbidden paths set, the extractor lists the names of its members
// (nothing is written or decompressed) and each is matched at any depth; archives
// nested in it are not opened. The archive goes on as a file, which the skipped
// path waives, or the refusal of its members ends. Each listing takes at least one
// file from the extraction budget of the top-level file.
//
// handled is false when the archive must go on as an archive: no skipped path
// covers it, or withdrawn is true because its names cannot be known (the extractor
// cannot list, the listing failed, the archive is not plain), in which case the skip
// does not apply to it. An extractor that is down, or matching that takes too long,
// is an error.
func (c *Connector) skippedArchive(archive fileToAnalyze, totalFiles *int, archiveLogger *slog.Logger) (handled, withdrawn bool, err error) {
	pf := c.config.PathFilter
	if !pf.skipsPath(archive.logical(), archive.rawLogical()) {
		return false, false, nil
	}
	file := archive.named()
	if pf.hasForbidden() {
		maxFiles := c.config.RecursiveExtractMaxFiles - *totalFiles
		if maxFiles <= 0 {
			archiveLogger.Debug("no budget of the extraction is left to list an archive")
			return true, false, c.sendForAnalyze(file.limited(), archiveLogger)
		}
		*totalFiles++
		names, known, listErr := c.listedNames(archive, maxFiles, archiveLogger)
		if listErr != nil {
			return true, false, listErr
		}
		if !known {
			archiveLogger.Info("the members of an archive are not known, the skip is withdrawn", slog.String("archive", archive.logical()))
			return false, true, nil
		}
		*totalFiles += max(len(names)-1, 0)
		refusal, matchErr := c.matchMembers(archive, names, archiveLogger)
		if matchErr != nil {
			return true, false, matchErr
		}
		file.pathRefusal = refusal
	}
	return true, false, c.sendForAnalyze(file, archiveLogger)
}

// listedNames asks the extractor for the names of the members of archive. known is
// false when it cannot say, whatever the reason but its being down.
func (c *Connector) listedNames(archive fileToAnalyze, maxFiles int, archiveLogger *slog.Logger) (names []string, known bool, err error) {
	outputDir, err := os.MkdirTemp(c.work.extractDir(), "x-")
	if err != nil {
		return nil, false, err
	}
	defer func() {
		if e := os.RemoveAll(outputDir); e != nil {
			archiveLogger.Error("could not remove temp folder after a listing", slog.String("folder", outputDir), slog.String(logErrorKey, e.Error()))
		}
	}()
	extraction, extractErr, stopped := c.runExtractor(archive, outputDir, plugins.ExtractLimits{
		MaxFileSize: c.config.MaxFileSize, MaxFiles: maxFiles, MaxTotalSize: c.config.RecursiveExtractMaxSize, NamesOnly: true,
	}, archiveLogger)
	if stopped {
		return nil, false, extractErr
	}
	switch {
	case extractErr != nil:
		archiveLogger.Warn("the members of an archive could not be listed", slog.String(logErrorKey, extractErr.Error()))
		return nil, false, nil
	case len(extraction.Files) > 0 || len(extraction.Skipped) > 0 || extraction.SkippedCount > 0 || len(extraction.Names) > maxFiles:
		// An extractor that ignores NamesOnly extracts, and one that lists leaves
		// nothing out: either way the names are not the whole truth.
		archiveLogger.Warn("an extractor answered a listing with more than names", slog.Int("files", len(extraction.Files)), slog.Int("names", len(extraction.Names)))
		return nil, false, nil
	}
	return extraction.Names, extraction.Names != nil, nil
}

// matchMembers matches the names of the members of archive against the forbidden
// paths, each as the extractor would write it. It returns the refusal of the
// archive if one is forbidden: the archive once, and the members (the first
// datamodel.MaxListedSubfiles) named in MaliciousSubfiles, as the refusal of an
// extracted archive does; the count of all is in the log. The time is bounded for
// all the listings of the file.
func (c *Connector) matchMembers(archive fileToAnalyze, names []string, archiveLogger *slog.Logger) (*datamodel.Result, error) {
	pf := c.config.PathFilter
	ctx := c.workContext()
	if archive.run == nil {
		return nil, errNoRun
	}
	left, start := archive.run.rulesTimeLeft(), pathRulesClock()
	defer func() { archive.run.spendRulesTime(pathRulesClock().Sub(start)) }()
	var refusal *datamodel.Result
	taken, resume := map[string]string{}, map[string]int{}
	refused := 0
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if pathRulesClock().Sub(start) > left {
			archiveLogger.Error("the path rules took too long on the listings of the archives of a file", slog.Int("members", len(names)))
			return nil, errPathRulesSlow
		}
		rel := extractedPath(name)
		logical := sanitizeControl(joinMember(archive.logical(), rel))
		switch d, rule := pf.decide(logical, joinMember(archive.rawLogical(), rel), false); d {
		case pathTooLong:
			return nil, errPathTooLong
		case pathForbidden:
			refused++
			if refusal == nil {
				refusal = pf.refusal(pathForbidden, rule, archive.logical(), archive.location, archive.sha256)
				refusal.MaliciousSubfiles = make(map[string]datamodel.Result)
			}
			if len(refusal.MaliciousSubfiles) < datamodel.MaxListedSubfiles {
				key := datamodel.UniqueKey(datamodel.CutText(logical, datamodel.MaxListedNameLen), taken, resume)
				taken[key] = ""
				refusal.MaliciousSubfiles[key] = *forbiddenResult(logical, "", "", 0)
			}
		}
	}
	if refused > 0 {
		archiveLogger.Warn("members of an archive are refused by the path rules", slog.Int("members", refused))
	}
	return refusal, nil
}
