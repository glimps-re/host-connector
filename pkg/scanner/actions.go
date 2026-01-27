package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
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
	InformDest io.Writer
	Move       bool
}

// for test purposes
var (
	Now      = time.Now
	Rename   = os.Rename
	MkdirAll = os.MkdirAll
	Create   = os.Create
)

type Action interface {
	Handle(ctx context.Context, path string, result datamodel.Result, analysisReport *datamodel.Report) error
}

type ReportAction struct{}

func (a *ReportAction) Handle(ctx context.Context, path string, result datamodel.Result, analysisReport *datamodel.Report) (err error) {
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

func (a *LogAction) Handle(ctx context.Context, path string, result datamodel.Result, report *datamodel.Report) (err error) {
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

func NewMultiAction(eventHandler events.EventHandler, actions ...Action) *MultiAction {
	return &MultiAction{Actions: actions}
}

func (a *MultiAction) Handle(ctx context.Context, path string, result datamodel.Result, report *datamodel.Report) (err error) {
	for _, h := range a.Actions {
		if err = h.Handle(ctx, path, result, report); err != nil {
			return
		}
	}

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
	return
}

type RemoveFileAction struct{}

func (a *RemoveFileAction) Handle(ctx context.Context, path string, result datamodel.Result, report *datamodel.Report) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("remove action: %w", err)
		}
	}()
	if !result.Malware {
		return
	}
	// We don't want to overwrite mitigation action
	if report.Action != datamodel.Quarantined {
		report.Action = datamodel.Removed
		report.MitigationID = result.SHA256
	}
	err = os.Remove(path)
	if err != nil {
		return
	}
	report.Deleted = true
	return
}

type QuarantineAction struct {
	quarantiner quarantine.Quarantiner
}

func NewQuarantineAction(quarantiner quarantine.Quarantiner) *QuarantineAction {
	return &QuarantineAction{quarantiner: quarantiner}
}

func (a *QuarantineAction) Handle(ctx context.Context, path string, result datamodel.Result, report *datamodel.Report) (err error) {
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
	quarantineLocation, quarantineID, err := a.quarantiner.Quarantine(ctx, path, report.SHA256, result.Malwares)
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

func (a *PrintAction) Handle(ctx context.Context, path string, result datamodel.Result, report *datamodel.Report) (err error) {
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

	switch {
	case result.Malware:
		sb := strings.Builder{}
		fmt.Fprintf(&sb, "file %s seems malicious", path)
		if len(result.Malwares) > 0 {
			fmt.Fprintf(&sb, " [%v]", result.Malwares)
		}
		if report.QuarantineLocation != "" {
			fmt.Fprintf(&sb, ", it has been quarantined to %s", report.QuarantineLocation)
		}
		if report.Deleted {
			fmt.Fprint(&sb, ", it has been deleted")
		}
		_, err = fmt.Fprintln(a.Out, sb.String())
		if err != nil {
			return
		}
	case report.MovedTo != "":
		_, err = fmt.Fprintf(a.Out, "file %s has been moved to %s\n", path, report.MovedTo)
		if err != nil {
			return
		}
	case a.Verbose:
		_, err = fmt.Fprintf(a.Out, "file %s no malware found\n", path)
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

func NewMoveAction(dest string, src string) (*MoveAction, error) {
	a := &MoveAction{}
	var err error
	a.Dest, err = filepath.Abs(dest)
	if err != nil {
		return nil, err
	}
	pp, err := filepath.Abs(src)
	if err != nil {
		return nil, err
	}
	a.Src = pp
	return a, nil
}

func (a *MoveAction) Handle(ctx context.Context, path string, result datamodel.Result, report *datamodel.Report) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("move action: %w", err)
		}
	}()
	// move only file analyzed with no error
	if result.Error != nil {
		ConsoleLogger.Warn(fmt.Sprintf("file %s will not be moved to destination, error in analysis: %s", path, result.Error.Error()))
		logger.Warn("file will not be moved to destination, error in analysis", slog.String("file", path), slog.String("error", result.Error.Error()))
		return
	}

	path, err = filepath.Abs(path)
	if err != nil {
		return
	}

	if !strings.HasPrefix(path, a.Src) {
		err = errors.New("file not in source directory")
		return
	}

	destSubpath, ok := strings.CutPrefix(path, a.Src)
	if !ok {
		destSubpath = path
	}
	dest := filepath.Join(a.Dest, destSubpath)
	err = MkdirAll(filepath.Dir(dest), 0o755)
	if err != nil {
		return
	}

	if result.Malware {
		now := time.Now().Format("020106_1504")
		f, createErr := Create(dest + fmt.Sprintf("-lockreport%s.json", now))
		if createErr != nil {
			err = createErr
			return
		}
		defer func() {
			if e := f.Close(); e != nil {
				logger.Error("MoveAction cannot close file", slog.String(logErrorKey, e.Error()))
			}
		}()
		w := json.NewEncoder(f)
		w.SetIndent("", "  ")
		if err = w.Encode(report); err != nil {
			return
		}
		return
	}

	if result.AnalysisError != "" {
		logger.Warn("file will not be moved to destination, error in analysis", slog.String("file", path), slog.String("error", result.AnalysisError))
		ConsoleLogger.Warn(fmt.Sprintf("file %s will not be moved to destination, error in analysis: %s", path, result.AnalysisError))
		return
	}

	// move safe file
	err = moveFile(path, dest)
	if err != nil {
		return
	}
	report.MovedTo = dest
	ConsoleLogger.Debug(fmt.Sprintf("file %s moved from %s to %s", report.Filename, path, dest))
	return
}

func moveFile(src, dst string) (err error) {
	err = Rename(src, dst)
	linkErr := new(os.LinkError)
	switch {
	case err == nil:
	case errors.As(err, &linkErr) && errors.Is(linkErr.Err, syscall.EXDEV):
		// Fall back to copy + delete for cross-device moves
		return copyAndDelete(src, dst)
	default:
		return fmt.Errorf("could not move file %s to %s, error: %w", src, dst, err)
	}
	return nil
}

func copyAndDelete(src, dst string) (err error) {
	srcInfo, err := os.Stat(src)
	if err != nil {
		return
	}

	srcFile, err := os.Open(filepath.Clean(src))
	if err != nil {
		return
	}
	defer func() {
		if e := srcFile.Close(); e != nil {
			logger.Error("copyAndDelete cannot close source file", slog.String("file", src), slog.String(logErrorKey, e.Error()))
		}
	}()

	dstFile, err := Create(dst)
	if err != nil {
		return
	}

	success := false
	defer func() {
		if e := dstFile.Close(); e != nil {
			logger.Error("copyAndDelete cannot close destination file", slog.String("file", dst), slog.String(logErrorKey, e.Error()))
		}
		if !success {
			if e := os.Remove(dst); e != nil {
				logger.Error("copyAndDelete cannot remove destination file after failed copy", slog.String("file", dst), slog.String(logErrorKey, e.Error()))
			}
		}
	}()
	if _, err = io.Copy(dstFile, srcFile); err != nil {
		return
	}
	if err = os.Chmod(dst, srcInfo.Mode()); err != nil {
		return
	}
	success = true
	err = os.Remove(src)
	if err != nil {
		return
	}
	return
}
