package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"maps"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/glimps-re/connector-integration/sdk/events"
	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/quarantine"
)

type Actions struct {
	Deleted    bool
	Quarantine bool
	Log        bool
	Inform     bool
	Verbose    bool
	InformDest io.WriteCloser
	Move       bool
}

// for test purposes
var (
	now      = time.Now
	moveFile = quarantine.MoveResolvingConflicts
	mkdirAll = os.MkdirAll
	create   = createExclusive
	lstat    = os.Lstat
)

// maxMoveConflicts is how many conflict names are tried after the plain one.
const maxMoveConflicts = 5

// What the report of a file says when an action on it failed: short, and with no
// path or system error (the log has the cause), so that the file counts as in
// error and not as analyzed whatever the action was.
const (
	quarantineFailedText = "the file could not be quarantined"
	moveFailedText       = "the file could not be moved to the destination"
	removeFailedText     = "the file could not be removed"
	// analysisFailedText is what the report says of a file whose analysis failed
	// without an error of the pipeline: the text of the service stays in the log.
	analysisFailedText = "the file could not be analyzed"
)

// membersAnalysisFailedText is what the report of an archive says when the
// analysis failed on some of its members: their names are in ErrorExtractedFiles,
// the text of the service stays in the log. The list is capped, so past the cap
// the count is a lower bound.
func membersAnalysisFailedText(listed int) string {
	if listed >= datamodel.MaxListedSubfiles {
		return fmt.Sprintf("%d or more extracted file(s) could not be analyzed", listed)
	}
	return fmt.Sprintf("%d extracted file(s) could not be analyzed", listed)
}

// setErrorIfNone puts text in the report of a file that cannot be delivered as it
// is, unless the report already says what is wrong with the file (an error of the
// analysis, a refusal with its own reason): the first cause stays.
func setErrorIfNone(report *datamodel.Report, text string) {
	if report.Error == "" {
		report.Error = text
	}
}

// errPermanentAction marks an action failure that retrying cannot fix.
var errPermanentAction = errors.New("permanent action failure")

// Action handles the result of the analysis of one file. src is the verified
// file the action applies to: an action that reads or deletes it does so through
// src.Open and src.Remove, never by its path; one that only names it uses
// src.Path.
type Action interface {
	Handle(ctx context.Context, src Source, result datamodel.Result, analysisReport *datamodel.Report) error
}

type ReportAction struct{}

func (a *ReportAction) Handle(ctx context.Context, src Source, result datamodel.Result, analysisReport *datamodel.Report) (err error) {
	path := src.Path
	analysisReport.Filename = path
	analysisReport.Malicious = result.Malware
	analysisReport.SHA256 = result.SHA256
	analysisReport.Malwares = slices.Clone(result.Malwares)
	analysisReport.FileSize = result.FileSize
	analysisReport.FileType = result.FileType
	analysisReport.AnalyzedVolume = result.AnalyzedVolume
	analysisReport.FilteredVolume = result.FilteredVolume
	analysisReport.MalwareReason = result.MalwareReason
	analysisReport.TotalExtractedFile = result.TotalExtractedFile
	analysisReport.GMalwareURL = result.GMalwareURL
	analysisReport.MaliciousExtractedFiles = collectExtractedFiles(result.MaliciousSubfiles)
	analysisReport.ErrorExtractedFiles = maps.Clone(result.ErrorSubfiles)
	analysisReport.HasBeenRestored = result.Restored
	analysisReport.NotAnalyzedReason = result.NotAnalyzedReason
	analysisReport.NotAnalyzedExtractedFiles = slices.Clone(result.NotAnalyzedSubfiles)
	analysisReport.NotAnalyzedExtractedCount = max(result.NotAnalyzedSubfilesCount, len(result.NotAnalyzedSubfiles))
	switch {
	case result.Error != nil:
		analysisReport.Error = result.Error.Error()
	case result.AnalysisError != "" && len(result.ErrorSubfiles) == 0:
		analysisReport.Error = analysisFailedText
	case result.AnalysisError != "" && !result.Malware:
		// "Analyzed" means the archive and every member analyzed: an archive with a
		// member the analysis failed on is an error, not an analyzed file.
		analysisReport.Error = membersAnalysisFailedText(datamodel.ListedErrors(result.ErrorSubfiles))
	}
	analysisReport.Bound()
	return
}

// collectExtractedFiles recursively collects extracted files from malicious subfiles.
func collectExtractedFiles(subfiles map[string]datamodel.Result) (extractedFiles []datamodel.ExtractedFile) {
	for filename, subfile := range subfiles {
		ef := datamodel.ExtractedFile{
			FileName:      filename,
			SHA256:        subfile.SHA256,
			Malicious:     true,
			Malwares:      subfile.Malwares,
			Size:          subfile.FileSize,
			MalwareReason: subfile.MalwareReason,
			GMalwareURL:   subfile.GMalwareURL,
		}
		if len(subfile.MaliciousSubfiles) > 0 {
			ef.ExtractedFiles = collectExtractedFiles(subfile.MaliciousSubfiles)
		}
		extractedFiles = append(extractedFiles, ef)
	}
	return
}

func getMitigationReason(malwareReason datamodel.MalwareReason) (mitigationReason events.MitigationReason) {
	switch malwareReason {
	case datamodel.TooBig:
		mitigationReason = events.ReasonTooBig
	case datamodel.AnalysisError:
		mitigationReason = events.ReasonError
	case datamodel.MalwareDetected:
		mitigationReason = events.ReasonMalware
	case datamodel.FilteredFileType:
		mitigationReason = events.ReasonFileType
	case datamodel.FilteredFilePath:
		mitigationReason = events.ReasonFilePath
	case datamodel.Empty, datamodel.Encrypted:
		mitigationReason = events.ReasonInvalid
	default:
		// Only a result that is malware gets here: an unknown reason, or none, is
		// still a detection, never an empty mitigation reason.
		mitigationReason = events.ReasonMalware
	}
	return
}

func getMitigationAction(action datamodel.Action) (mitigationAction events.MitigationAction) {
	switch action {
	case datamodel.Removed:
		mitigationAction = events.ActionRemove
	case datamodel.Logged:
		mitigationAction = events.ActionLog
	case datamodel.Quarantined:
		mitigationAction = events.ActionQuarantine
	}
	return
}

type LogAction struct {
	logger *slog.Logger
}

func (a *LogAction) Handle(ctx context.Context, src Source, result datamodel.Result, report *datamodel.Report) (err error) {
	path := src.Path
	if !result.Malware {
		a.logger.Debug("info scanned", slog.String("file", path), slog.String("sha256", result.SHA256), slog.Bool("malware", false))
		return
	}
	report.Action = datamodel.Logged
	if len(result.Malwares) == 0 {
		result.Malwares = []string{}
	}
	if len(result.MaliciousSubfiles) == 0 {
		a.logger.Info("info scanned", slog.String("file", path), slog.String("sha256", result.SHA256), slog.Bool("malware", true), slog.Any("malwares", result.Malwares))
		return
	}
	attrs := collectMaliciousSubfilesAttrs(result.MaliciousSubfiles)
	a.logger.Info("info scanned", slog.String("file", path), slog.String("sha256", result.SHA256), slog.Bool("malware", true), slog.Any("malwares", result.Malwares), slog.String("reason", string(result.MalwareReason)), slog.GroupAttrs("malicious-subfiles", attrs...))
	return
}

// collectMaliciousSubfilesAttrs recursively collects slog attributes for all malicious subfiles.
// Keys are sorted to ensure deterministic log output.
func collectMaliciousSubfilesAttrs(subfiles map[string]datamodel.Result) (attrs []slog.Attr) {
	keys := make([]string, 0, len(subfiles))
	for k := range subfiles {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	for _, filename := range keys {
		v := subfiles[filename]
		subAttrs := []any{slog.String("sha256", v.SHA256), slog.Any("malwares", v.Malwares)}
		if len(v.MaliciousSubfiles) > 0 {
			nestedAttrs := collectMaliciousSubfilesAttrs(v.MaliciousSubfiles)
			subAttrs = append(subAttrs, slog.GroupAttrs("malicious-subfiles", nestedAttrs...))
		}
		attrs = append(attrs, slog.Group(filename, subAttrs...))
	}
	return
}

type MultiAction struct {
	Actions []Action
}

func NewMultiAction(actions ...Action) *MultiAction {
	return &MultiAction{Actions: actions}
}

// Handle runs the actions in order. An action that fails does not stop the
// ones that follow, so that the mitigation already done is still reported to
// the console, except the ones that destroy the file (a failed quarantine must
// not be followed by the removal of the file). All the errors are returned.
func (a *MultiAction) Handle(ctx context.Context, src Source, result datamodel.Result, report *datamodel.Report) error {
	var errs []error
	for _, h := range a.Actions {
		if len(errs) > 0 {
			if d, ok := h.(interface{ SkipAfterError() bool }); ok && d.SkipAfterError() {
				continue
			}
			if d, ok := h.(interface{ SkipAfterRestored() bool }); ok && d.SkipAfterRestored() && restoredRefusal(errs) {
				continue
			}
		}
		if err := h.Handle(ctx, src, result, report); err != nil {
			errs = append(errs, err)
		}
	}
	a.notifyMitigation(ctx, src.Path, result, report)
	if len(errs) == 0 {
		return nil
	}
	return joinedErrors(errs)
}

// joinedErrors is what MultiAction returns when several actions failed.
type joinedErrors []error

func (j joinedErrors) Error() string {
	msgs := make([]string, len(j))
	for i, e := range j {
		msgs[i] = e.Error()
	}
	return strings.Join(msgs, "; ")
}

func (j joinedErrors) Unwrap() []error { return j }

// IsPermanentAction reports whether retrying the actions cannot help. When
// several actions failed it is true only if EVERY failure is permanent: a
// transient failure (a quarantine that could not be written) must keep the
// file eligible for a retry even though another action failed for good (a
// move onto a taken name).
func IsPermanentAction(err error) bool {
	if err == nil {
		return false
	}
	if joined, ok := errors.AsType[joinedErrors](err); ok {
		for _, e := range joined {
			if !IsPermanentAction(e) {
				return false
			}
		}
		return len(joined) > 0
	}
	return errors.Is(err, errPermanentAction)
}

func (a *MultiAction) notifyMitigation(ctx context.Context, path string, result datamodel.Result, report *datamodel.Report) {
	if report.Action == "" {
		return
	}

	gmalwareURLs := []string{}
	if result.GMalwareURL != "" {
		gmalwareURLs = append(gmalwareURLs, result.GMalwareURL)
	}
	for _, subFile := range result.MaliciousSubfiles {
		if subFile.GMalwareURL != "" {
			gmalwareURLs = append(gmalwareURLs, subFile.GMalwareURL)
		}
	}
	if result.Malwares == nil {
		result.Malwares = make([]string, 0)
	}

	// The console is told of what was done even when the work was cut just after:
	// the context of the work is not the one of the event.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), eventTimeout)
	defer cancel()
	if e := EventHandler.NotifyFileMitigation(ctx, getMitigationAction(report.Action), report.MitigationID, getMitigationReason(report.MalwareReason), events.FileInfos{
		CommonDetails: events.CommonDetails{
			Malwares:           result.Malwares,
			GmalwareURLs:       gmalwareURLs,
			QuarantineLocation: report.QuarantineLocation,
			SHA256:             result.SHA256,
			AnalysisError:      result.AnalysisError,
		},
		File:     path,
		Size:     report.FileSize,
		Filetype: report.FileType,
	}); e != nil {
		logger.Warn("could not push quarantine event to console", slog.String("error", e.Error()))
	}
}

type RemoveFileAction struct{}

// restoredRefusal reports whether an earlier action was refused because the
// content was restored: the file is going to be handled as a restored one at the
// next pass, nothing may be written or taken from it meanwhile.
func restoredRefusal(errs []error) bool {
	for _, err := range errs {
		if errors.Is(err, quarantine.ErrRestored) {
			return true
		}
	}
	return false
}

// SkipAfterRestored keeps the move action from writing a detection report or
// moving a file whose quarantine was refused because the content was restored.
func (a *MoveAction) SkipAfterRestored() bool { return true }

// SkipAfterError keeps MultiAction from removing a file when an earlier action
// failed: a failed quarantine must not end with the loss of the file.
func (a *RemoveFileAction) SkipAfterError() bool { return true }

func (a *RemoveFileAction) Handle(ctx context.Context, src Source, result datamodel.Result, report *datamodel.Report) (err error) {
	defer func() {
		if err != nil {
			setErrorIfNone(report, removeFailedText)
			err = fmt.Errorf("remove action: %w", err)
		}
	}()
	if !result.Malware {
		return
	}
	err = src.Remove()
	if err != nil {
		if errors.Is(err, errSourceLink) {
			setErrorIfNone(report, "malware behind a symbolic link: the link and its target are left in place")
		}
		if quarantine.IsRemovalRefused(err) {
			err = fmt.Errorf("%w: %w", errPermanentAction, err)
		}
		return
	}
	report.Deleted = true
	// Only a removal that happened is announced; a quarantine already done
	// keeps its own action.
	if report.Action != datamodel.Quarantined {
		report.Action = datamodel.Removed
		report.MitigationID = result.SHA256
	}
	return
}

type QuarantineAction struct {
	quarantiner quarantine.Quarantiner
}

func NewQuarantineAction(quarantiner quarantine.Quarantiner) *QuarantineAction {
	return &QuarantineAction{quarantiner: quarantiner}
}

func (a *QuarantineAction) Handle(ctx context.Context, src Source, result datamodel.Result, report *datamodel.Report) (err error) {
	path := src.Path
	defer func() {
		if err != nil {
			// A content that was restored is refused on purpose, and the next pass
			// handles the file as restored: that is not a failure of the quarantine.
			if !errors.Is(err, quarantine.ErrRestored) {
				setErrorIfNone(report, quarantineFailedText)
			}
			err = fmt.Errorf("quarantine action: %w", err)
		}
	}()
	if a.quarantiner == nil {
		return
	}
	// skip legit files
	if !result.Malware {
		return
	}
	// What is quarantined is checked against the hash the pipeline computed, not
	// the one of the result, which a plugin can replace.
	if err = src.actionable(); err != nil && !errors.Is(err, errSourceLink) {
		return
	}
	in, release, err := src.Open()
	if err != nil {
		return
	}
	defer release()
	quarantineLocation, quarantineID, err := a.quarantiner.Quarantine(ctx, path, in, src.SHA256, result.Malwares)
	if err != nil {
		return
	}
	report.QuarantineLocation = quarantineLocation
	report.MitigationID = quarantineID
	report.Action = datamodel.Quarantined
	return nil
}

type PrintAction struct {
	Verbose bool
	Out     io.Writer
	mu      sync.Mutex // protects Out from concurrent writes by worker goroutines
}

func (a *PrintAction) Handle(ctx context.Context, src Source, result datamodel.Result, report *datamodel.Report) (err error) {
	path := src.Path
	defer func() {
		if err != nil {
			err = fmt.Errorf("print action: %w", err)
		}
	}()
	if a.Out == nil {
		a.Out = os.Stdout
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	reason := "seems safe"
	switch {
	case result.Malware:
		reason = string(result.MalwareReason)
	case result.NotAnalyzedReason != "":
		reason = notAnalyzedLabel(result.NotAnalyzedReason)
	}
	if n := max(result.NotAnalyzedSubfilesCount, len(result.NotAnalyzedSubfiles)); n > 0 {
		reason += fmt.Sprintf(" (%d extracted file(s) not analyzed)", n)
	}
	actions := []string{}
	details := []string{}
	if result.Malware {
		details = result.Malwares
		if report.QuarantineLocation != "" {
			actions = append(actions, "quarantined")
			details = append(details, report.QuarantineLocation)
		}
		if report.Deleted {
			actions = append(actions, "deleted")
		}
	} else if report.MovedTo != "" {
		details = append(details, report.MovedTo)
		actions = append(actions, "moved")
	}
	s := fmt.Sprintf("time: %s, file: %s, sha256: %s, flagged: %s, reason: %s, actions: %v, details: %v", now().UTC().Format(time.RFC3339), path, result.SHA256, strconv.FormatBool(result.Malware), reason, actions, details)
	notAnalyzed := result.NotAnalyzedReason != "" || result.NotAnalyzedSubfilesCount > 0 || len(result.NotAnalyzedSubfiles) > 0
	if result.Malware || a.Verbose || report.MovedTo != "" || notAnalyzed {
		_, err = fmt.Fprintln(a.Out, s)
		if err != nil {
			return
		}
	}
	return nil
}

// notAnalyzedLabel is how the console tells a file was let through unanalyzed.
// A file too big, or whose analysis failed, is moved as it is: its content was
// not verified.
func notAnalyzedLabel(reason datamodel.NotAnalyzedReason) string {
	label := "not analyzed (" + strings.ReplaceAll(string(reason), "-", " ") + ")"
	if reason == datamodel.NotAnalyzedTooBig || reason == datamodel.NotAnalyzedAnalysisError {
		label += ", content not verified"
	}
	return label
}

// MoveMode is the way the move action puts a file in the destination.
type MoveMode string

const (
	// MoveModeCopy writes a copy whose SHA256 is the one analyzed: the inode of
	// the source never reaches the destination, so a writer that kept the file
	// open cannot change what was published.
	MoveModeCopy MoveMode = "copy"
	// MoveModeRename moves the inode itself (link or rename, then removal of
	// the old name): cheaper, but a writer holding the file open can still write
	// to what reached the destination.
	MoveModeRename MoveMode = "rename"
)

// copies tells whether the mode copies the file: everything but MoveModeRename,
// the empty mode included.
func (m MoveMode) copies() bool { return m != MoveModeRename }

// DefaultMoveMinThroughput is the throughput, in bytes per second, below which
// a copy is given up as a resource failure.
const DefaultMoveMinThroughput int64 = 10 << 20

// minThroughputOrDefault is the throughput a copy is held to: the configured
// one, or the default when it is not positive.
func minThroughputOrDefault(v int64) int64 {
	if v <= 0 {
		return DefaultMoveMinThroughput
	}
	return v
}

// satAdd adds two durations and saturates instead of wrapping around.
func satAdd(a, b time.Duration) time.Duration {
	if a > math.MaxInt64-b {
		return math.MaxInt64
	}
	return a + b
}

// moveGrace is added to the time a copy is given for its size.
const moveGrace = time.Minute

// errResourceAction marks a move that failed for lack of space or throughput at
// the destination: the file is not at fault, it is retried without consuming an
// attempt.
var errResourceAction = errors.New("not enough space or throughput at the destination")

// moveTimeout is the time a copy of size bytes is given: its size at the
// minimum throughput, plus a grace. It saturates at the largest duration.
func moveTimeout(size, minThroughput int64) time.Duration {
	secs := size / minThroughputOrDefault(minThroughput)
	if secs > math.MaxInt64/int64(time.Second) {
		return math.MaxInt64
	}
	return satAdd(time.Duration(secs)*time.Second, moveGrace)
}

// MoveAction puts the analyzed files that are not malware in Dest, under the
// same relative path as below Src.
type MoveAction struct {
	Dest string
	Src  string
	// Mode is how a file reaches Dest. Only MoveModeRename renames: the zero
	// value copies, as the default of the connector does.
	Mode MoveMode
	// MinThroughput is the throughput in bytes per second below which a copy is
	// given up; DefaultMoveMinThroughput when not positive.
	MinThroughput int64

	resourceDown atomic.Bool
}

// NewMoveAction is NewMoveActionWithMode in MoveModeRename: it is kept for the
// callers and the tests that predate the copy mode, it is not the default.
func NewMoveAction(dest string, src string) (a *MoveAction, err error) {
	return NewMoveActionWithMode(dest, src, MoveModeRename, 0)
}

// NewMoveActionWithMode builds a move action. An empty mode is MoveModeCopy; any
// other value than copy and rename is refused.
func NewMoveActionWithMode(dest, src string, mode MoveMode, minThroughput int64) (a *MoveAction, err error) {
	switch mode {
	case "":
		mode = MoveModeCopy
	case MoveModeCopy, MoveModeRename:
	default:
		return nil, fmt.Errorf("unknown move mode %q", mode)
	}
	absDst, err := filepath.Abs(dest)
	if err != nil {
		return
	}
	absSrc, err := filepath.Abs(src)
	if err != nil {
		return
	}
	a = &MoveAction{
		Src:           absSrc,
		Dest:          absDst,
		Mode:          mode,
		MinThroughput: minThroughput,
	}
	return
}

func (a *MoveAction) Handle(ctx context.Context, src Source, result datamodel.Result, report *datamodel.Report) (err error) {
	path := src.Path
	defer func() {
		if err != nil {
			setErrorIfNone(report, moveFailedText)
			err = fmt.Errorf("move action: %w", err)
		}
	}()
	// move only file analyzed with no error
	if result.Error != nil {
		ConsoleLogger.Warn(fmt.Sprintf("file %s will not be moved to destination, error in analysis: %s", path, result.Error.Error()))
		logger.Warn("file will not be moved to destination, error in analysis", slog.String("file", path), slog.String("error", result.Error.Error()))
		// A detection is never lost behind an error: its report is still written.
		if !result.Malware {
			return
		}
	}

	path, err = filepath.Abs(path)
	if err != nil {
		return
	}

	relPath, relErr := filepath.Rel(a.Src, path)
	if relErr != nil || relPath == ".." || strings.HasPrefix(relPath, ".."+string(filepath.Separator)) {
		err = fmt.Errorf("%w: file not in source directory", errPermanentAction)
		return
	}
	if first, _, _ := strings.Cut(relPath, string(filepath.Separator)); strings.EqualFold(first, quarantine.StagingDir) {
		err = fmt.Errorf("%w: %s is the transit directory of the destination", errPermanentAction, quarantine.StagingDir)
		return
	}
	if hasReservedName(filepath.Base(path)) {
		const msg = "file name reserved for session reports"
		logger.Warn("file will not be moved to destination, "+msg, slog.String("file", path))
		ConsoleLogger.Warn(fmt.Sprintf("file %s will not be moved to destination: %s", path, msg))
		setErrorIfNone(report, msg)
		if result.Malware {
			// The detection must reach the other actions and the console: the
			// file simply stays where it is.
			return
		}
		err = fmt.Errorf("%w: %s", errPermanentAction, msg)
		return
	}

	// A source the pipeline did not verify, or reached through a link, is refused
	// before anything is created at the destination; the identity is checked
	// again right before the move.
	if !result.Malware && result.AnalysisError == "" {
		if err = src.actionable(); err != nil {
			if errors.Is(err, errSourceLink) {
				setErrorIfNone(report, "the file is a symbolic link: it was analyzed but is not moved")
			}
			return
		}
	}
	dest := filepath.Join(a.Dest, relPath)
	if err = mkdirAll(filepath.Dir(dest), 0o755); err != nil {
		err = classifyDestinationError(err)
		return
	}

	if result.Malware {
		return writeLockReport(dest, report)
	}

	if result.AnalysisError != "" {
		logger.Warn("file will not be moved to destination, error in analysis", slog.String("file", path), slog.String("error", result.AnalysisError))
		ConsoleLogger.Warn(fmt.Sprintf("file %s will not be moved to destination, error in analysis: %s", path, result.AnalysisError))
		return
	}

	// Fails early, before the destination is touched; on Linux the move itself
	// publishes the verified descriptor, elsewhere it goes by name and the window
	// left is the documented one.
	if err = src.ready(); err != nil {
		return
	}
	target, err := a.place(ctx, src, dest)
	if err != nil {
		return
	}
	report.MovedTo = target
	if target != dest {
		report.MoveConflictOf = relPath
		msg := fmt.Sprintf("%s already existed at the destination (the first file may have been partial): moved to %s", relPath, target)
		logger.Warn(msg, slog.String("file", path))
		ConsoleLogger.Warn(msg)
	}
	ConsoleLogger.Debug(fmt.Sprintf("file %s moved from %s to %s", report.Filename, path, target))
	return
}

// moveWithoutReplace moves path to dest, or when dest exists to a conflict name
// next to it: a file already in the destination is never overwritten.
// moveClass is how a file is put in the destination in MoveModeCopy.
type moveClass int

const (
	// classCopy: the content is copied and verified against the analyzed
	// SHA256 (analyzed files, archives, files skipped by type or path, restored
	// files, encrypted files within the size limit).
	classCopy moveClass = iota
	// classEmpty: a new empty file is created; there is no content to copy.
	classEmpty
	// classByPath: the file is moved as in MoveModeRename. The only such file is
	// one too big to be analyzed that the policy lets through: copying it would
	// take longer than the analysis refused it for.
	classByPath
)

// classOf tells how a file is put in the destination in MoveModeCopy. Only the
// pipeline's own decision sends a file by name (src.TooBig): a plugin can change
// a result, the reason of a member too big is carried to its archive, and a
// large archive that was extracted and analyzed is not too big.
func classOf(src Source) moveClass {
	switch {
	case src.Identity.Size == 0:
		return classEmpty
	case src.TooBig:
		return classByPath
	default:
		return classCopy
	}
}

// place puts the file in dest according to the mode, and returns the path it
// has there.
func (a *MoveAction) place(ctx context.Context, src Source, dest string) (string, error) {
	class := classOf(src)
	if !a.Mode.copies() || class == classByPath {
		return a.moveWithoutReplace(ctx, src, dest)
	}
	if fi, statErr := lstat(dest); statErr == nil && fi.IsDir() {
		return "", fmt.Errorf("%w: %s is a directory", errPermanentAction, dest)
	}
	var (
		target string
		err    error
	)
	switch class {
	case classEmpty:
		target, err = a.moveEmpty(src, dest)
	default:
		target, err = a.moveCopy(ctx, src, dest)
	}
	if err != nil {
		return "", a.classifyCopyError(ctx, err, dest)
	}
	a.resourceRecovered(ctx)
	return target, nil
}

func (a *MoveAction) stagingDir() string { return filepath.Join(a.Dest, quarantine.StagingDir) }

func (a *MoveAction) moveCopy(ctx context.Context, src Source, dest string) (string, error) {
	f, release, err := src.Open()
	if err != nil {
		return "", err
	}
	defer release()
	ctx, cancel := context.WithTimeout(ctx, moveTimeout(src.Identity.Size, a.MinThroughput))
	defer cancel()
	return quarantine.MoveVerifiedCopy(ctx, f, src.Remove, dest, a.stagingDir(), src.SHA256, now, maxMoveConflicts)
}

func (a *MoveAction) moveEmpty(src Source, dest string) (string, error) {
	f, release, err := src.Open()
	if err != nil {
		return "", err
	}
	defer release()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if info.Size() != 0 {
		return "", fmt.Errorf("%w: %s", quarantine.ErrSourceChanged, src.Path)
	}
	return quarantine.MoveEmpty(src.Remove, src.Path, info.Mode(), dest, now, maxMoveConflicts)
}

// classifyCopyError sorts the failure of a copy: no space or throughput is a
// resource failure of the destination, names all taken is permanent, the rest is
// as for any move.
func (a *MoveAction) classifyCopyError(ctx context.Context, err error, dest string) error {
	switch {
	case errors.Is(err, context.DeadlineExceeded), isNoSpace(err):
		a.resourceFailed(ctx, err)
		return fmt.Errorf("%w: %w", errResourceAction, err)
	case errors.Is(err, quarantine.ErrDestinationExists):
		return fmt.Errorf("%w: %d names taken for %s", errPermanentAction, maxMoveConflicts+1, dest)
	case errors.Is(err, quarantine.ErrNoExpectedHash):
		return fmt.Errorf("%w: %w", errPermanentAction, err)
	default:
		return classifyDestinationError(err)
	}
}

// moveResourceEvent is the console event raised while a move fails for lack of
// space or throughput at the destination.
const moveResourceEvent events.ErrorEventType = "host-move-resource"

// resourceFailed raises the console error (once until it is resolved).
func (a *MoveAction) resourceFailed(ctx context.Context, cause error) {
	if !a.resourceDown.CompareAndSwap(false, true) {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), eventTimeout)
	defer cancel()
	if e := EventHandler.NotifyError(ctx, moveResourceEvent, fmt.Errorf("not enough space or throughput at the destination of the move: %w", cause)); e != nil {
		a.resourceDown.Store(false)
		logger.Warn("could not push console error", slog.String(logErrorKey, e.Error()))
	}
}

// resourceRecovered resolves the console error once a file was moved.
func (a *MoveAction) resourceRecovered(ctx context.Context) {
	if !a.resourceDown.CompareAndSwap(true, false) {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), eventTimeout)
	defer cancel()
	if e := EventHandler.NotifyResolution(ctx, "the destination of the move accepts files again", moveResourceEvent); e != nil {
		a.resourceDown.Store(true)
		logger.Warn("could not push resolution event to connector manager", slog.String(logErrorKey, e.Error()))
	}
}

func (a *MoveAction) moveWithoutReplace(ctx context.Context, src Source, dest string) (target string, err error) {
	if fi, statErr := lstat(dest); statErr == nil && fi.IsDir() {
		return "", fmt.Errorf("%w: %s is a directory", errPermanentAction, dest)
	}
	target, err = moveFile(ctx, src.moveSource(), dest, a.stagingDir(), now, maxMoveConflicts)
	switch {
	case err == nil:
		return target, nil
	case errors.Is(err, quarantine.ErrDestinationExists):
		return "", fmt.Errorf("%w: %d names taken for %s", errPermanentAction, maxMoveConflicts+1, dest)
	default:
		return "", classifyDestinationError(err)
	}
}

// writeLockReport writes the detection report next to where the file would
// have been moved, never over an existing file.
func writeLockReport(dest string, report *datamodel.Report) (err error) {
	stamp := now().Format("020106_1504")
	first := quarantine.FitName(filepath.Dir(dest)+string(filepath.Separator), filepath.Base(dest), "-lockreport"+stamp+".json")
	name := first
	var f *os.File
	for attempt := 0; ; attempt++ {
		f, err = create(name)
		if err == nil {
			break
		}
		if !errors.Is(err, fs.ErrExist) {
			return classifyDestinationError(err)
		}
		if attempt >= maxMoveConflicts {
			return fmt.Errorf("%w: %d names taken for %s", errPermanentAction, maxMoveConflicts+1, name)
		}
		name = quarantine.ConflictName(first, now(), attempt)
	}
	defer func() {
		if e := f.Close(); e != nil {
			logger.Error("MoveAction cannot close file", slog.String(logErrorKey, e.Error()))
		}
	}()
	w := json.NewEncoder(f)
	w.SetIndent("", "  ")
	return w.Encode(report)
}

// hasReservedName reports whether name starts with the session report prefix,
// in any letter case: a reader cannot tell Report-Session-x.pdf from it.
func hasReservedName(name string) bool {
	return len(name) >= len(datamodel.SessionReportPrefix) && strings.EqualFold(name[:len(datamodel.SessionReportPrefix)], datamodel.SessionReportPrefix)
}

// classifyDestinationError marks the destination errors no retry can fix.
func classifyDestinationError(err error) error {
	if errors.Is(err, syscall.ENAMETOOLONG) || errors.Is(err, syscall.ENOTDIR) || errors.Is(err, syscall.EISDIR) || errors.Is(err, syscall.EXDEV) || errors.Is(err, quarantine.ErrStagingUnsafe) || errors.Is(err, quarantine.ErrSourceNotRemovable) {
		return fmt.Errorf("%w: %w", errPermanentAction, err)
	}
	return err
}

// createExclusive creates name and fails when it exists.
func createExclusive(name string) (*os.File, error) {
	return os.OpenFile(filepath.Clean(name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
}
