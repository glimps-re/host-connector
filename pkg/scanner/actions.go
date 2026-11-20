package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
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
	analysisReport.Malwares = result.Malwares
	analysisReport.FileSize = result.FileSize
	analysisReport.FileType = result.FileType
	analysisReport.AnalyzedVolume = result.AnalyzedVolume
	analysisReport.FilteredVolume = result.FilteredVolume
	analysisReport.MalwareReason = result.MalwareReason
	analysisReport.TotalExtractedFile = result.TotalExtractedFile
	analysisReport.GMalwareURL = result.GMalwareURL
	analysisReport.MaliciousExtractedFiles = collectExtractedFiles(result.MaliciousSubfiles)
	analysisReport.ErrorExtractedFiles = result.ErrorSubfiles
	analysisReport.HasBeenRestored = result.Restored
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
			err = fmt.Errorf("remove action: %w", err)
		}
	}()
	if !result.Malware {
		return
	}
	err = src.Remove()
	if err != nil {
		if errors.Is(err, errSourceLink) && report.Error == "" {
			report.Error = "malware behind a symbolic link: the link and its target are left in place"
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
	if result.Malware {
		reason = string(result.MalwareReason)
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
	if result.Malware || a.Verbose || report.MovedTo != "" {
		_, err = fmt.Fprintln(a.Out, s)
		if err != nil {
			return
		}
	}
	return nil
}

type MoveAction struct {
	Dest string
	Src  string
}

func NewMoveAction(dest string, src string) (a *MoveAction, err error) {
	absDst, err := filepath.Abs(dest)
	if err != nil {
		return
	}
	absSrc, err := filepath.Abs(src)
	if err != nil {
		return
	}
	a = &MoveAction{
		Src:  absSrc,
		Dest: absDst,
	}
	return
}

func (a *MoveAction) Handle(ctx context.Context, src Source, result datamodel.Result, report *datamodel.Report) (err error) {
	path := src.Path
	defer func() {
		if err != nil {
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
		report.Error = msg
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
				report.Error = "the file is a symbolic link: it was analyzed but is not moved"
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
	target, err := a.moveWithoutReplace(src, dest)
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
func (a *MoveAction) moveWithoutReplace(src Source, dest string) (target string, err error) {
	if fi, statErr := lstat(dest); statErr == nil && fi.IsDir() {
		return "", fmt.Errorf("%w: %s is a directory", errPermanentAction, dest)
	}
	target, err = moveFile(src.moveSource(), dest, filepath.Join(a.Dest, quarantine.StagingDir), now, maxMoveConflicts)
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
