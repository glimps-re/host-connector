package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/glimps-re/host-connector/pkg/plugins"
)

const (
	szFileListHeader1  = "   Date      Time    Attr         Size   Compressed  Name"
	szFileListHeader2  = "------------------- ----- ------------ ------------  ------------------------"
	szFileListFooter   = "------------------- ----- ------------ ------------  ------------------------"
	szDateTimePrefix   = 0
	szDateTimeSize     = 19
	szAttrPrefix       = 1
	szAttrSize         = 5
	szSizePrefix       = 1
	szSizeSize         = 12
	szCompressedPrefix = 1
	szCompressedSize   = 12
	szNamePrefix       = 2
	szMinLineSize      = szDateTimePrefix + szDateTimeSize + szAttrPrefix + szAttrSize + szSizePrefix + szSizeSize + szCompressedPrefix + szCompressedSize + szNamePrefix
	sevenZipMaxFile    = 200

	zipBombThreshold int64 = 3 * 1000 * 1000 * 1000 // 3GB
	zipBombRatio     int64 = 100

	szRunTimeout time.Duration = 1 * time.Hour // deliberately large timeout, more to have at least a deadline and avoid indefinite run
	// szExtractTimeout bounds the whole extraction of one archive.
	szExtractTimeout time.Duration = 2 * time.Hour
)

type SevenZipFileAttr int

const (
	Directory SevenZipFileAttr = iota
	ReadOnly
	Hidden
	System
	Archive
)

type extractorConfig struct {
	MaxFileSize           int64
	MaxExtractedFiles     int
	MaxTotalExtractedSize int64
	DefaultPasswords      []string
}

type FileProperties struct {
	Name           string `json:"name"`
	Date           string `json:"date"`
	IsDirectory    bool   `json:"is_directory"`
	IsHidden       bool   `json:"is_hidden"`
	Size           int    `json:"size"`
	CompressedSize int    `json:"compressed_size"`
}

type extractResult struct {
	extractedFiles []ExtractedFile
	symlinkFiles   []string
	passwordUsed   string
	skipped        skipList
	anomalies      []string
	logger         *slog.Logger
}

type ExtractedFile struct {
	Path                 string `json:"path"`
	ArchivePath          string `json:"archive_path"`
	Size                 int    `json:"size"`
	LastModificationDate string `json:"last_modification_date"`
}

type sevenZipExtract struct {
	config       extractorConfig
	sevenZipPath string
	tmpSevenZip  bool
	logger       *slog.Logger
}

func newSevenZipExtract(config extractorConfig, sevenZipPath string, logger *slog.Logger) (sze *sevenZipExtract, err error) {
	sze = &sevenZipExtract{
		config:       config,
		sevenZipPath: sevenZipPath,
		logger:       logger,
	}

	if sevenZipPath == "" {
		if err = sze.resolve7zzs(); err != nil {
			err = fmt.Errorf("resolving 7zzs binary: %w", err)
			return
		}
	}
	return
}

// resolve7zzs locates 7zzs in PATH or deploys the embedded binary.
func (sze *sevenZipExtract) resolve7zzs() (err error) {
	fname, err := exec.LookPath("7zzs")
	if err == nil {
		sze.sevenZipPath, err = filepath.Abs(fname)
		return
	}

	f, err := os.CreateTemp(os.TempDir(), "7zzs")
	if err != nil {
		return
	}
	defer func() {
		if e := f.Close(); e != nil {
			sze.logger.Error("could not close created 7zzs temp file", slog.String("file", f.Name()), slog.String("error", e.Error()))
		}
	}()

	_, err = f.Write(SevenZip)
	if err != nil {
		return
	}

	err = f.Chmod(0o755)
	if err != nil {
		return
	}
	sze.sevenZipPath = f.Name()
	sze.tmpSevenZip = true
	return
}

// effectiveLimits is the strictest of the plugin's own keys and the limits the
// core passes.
func (sze *sevenZipExtract) effectiveLimits(l plugins.ExtractLimits) (maxFileSize int64, maxFiles int, maxTotal int64) {
	return min(sze.config.MaxFileSize, l.MaxFileSize), min(sze.config.MaxExtractedFiles, l.MaxFiles), min(sze.config.MaxTotalExtractedSize, l.MaxTotalSize)
}

func (sze *sevenZipExtract) passwordCandidates(passwords []string) []string {
	all := []string{""}
	all = append(all, sze.config.DefaultPasswords...)
	return append(all, passwords...)
}

// recoverableAnomaly records a recoverable 7z error as an anomaly of the
// archive.
func (sze *sevenZipExtract) recoverableAnomaly(anomalies *[]string, step string, err error) {
	*anomalies = noteAnomaly(*anomalies, "7z could not "+step+" the archive cleanly")
	sze.logger.Warn("7z reported a recoverable error", slog.String("step", step), slog.String("error", err.Error()))
}

// list streams the listing of the archive into sink, trying each password in
// turn. Anomalies 7z reports are left in sink.anomalies. A list that did not
// reach its end is an error unless 7z said why.
func (sze *sevenZipExtract) list(ctx context.Context, archivePath string, passwords []string, sink *listSink) error {
	// -spd: member names are literal, a member named "*" or "?" is no wildcard.
	args := []string{"-spd", "--", "l", archivePath}
	var err error
	for _, pwd := range sze.passwordCandidates(passwords) {
		*sink = *newListSink(sink.maxFileSize, sink.maxFiles, sink.maxTotal)
		_, err = sze.runStream(ctx, pwd, args, sink.scan, archivePath)
		switch {
		case err == nil:
		case errors.Is(err, errSevenZipRecoverable):
			sze.recoverableAnomaly(&sink.anomalies, "list", err)
		case errors.Is(err, ErrInvalidPassword):
			continue
		default:
			return err
		}
		// A listing that stops early is an anomaly 7z explained, or a failure.
		if !sink.complete && len(sink.anomalies) == 0 {
			return fmt.Errorf("%w: header or footer not found", errBadListing)
		}
		sink.finish()
		return nil
	}
	return err
}

func (sze *sevenZipExtract) extract(ctx context.Context, archivePath string, extractLocation string, passwords []string, limits plugins.ExtractLimits) (extraction extractResult, err error) {
	// we do not extract the all archive at once for security reasons
	// first list files then extract one by one
	maxFileSize, maxFiles, maxTotal := sze.effectiveLimits(limits)
	sink := newListSink(maxFileSize, maxFiles, maxTotal)
	extraction.logger = sze.logger
	if err = sze.list(ctx, archivePath, passwords, sink); err != nil {
		return
	}
	baseAnomalies := slices.Clone(sink.anomalies)
	extraction.anomalies = slices.Clone(baseAnomalies)
	extraction.skipped = sink.table.skipped
	t := &sink.table

	// zip bomb detection (only count files that would pass MaxFileSize filter)
	if t.totalSize > zipBombThreshold && t.totalCompressed > 0 && t.totalSize/t.totalCompressed > zipBombRatio {
		err = fmt.Errorf("size of files within archive is high compared to archive size, potential ZipBomb (total: %d, compressed: %d, ratio: %d)", t.totalSize, t.totalCompressed, t.totalSize/t.totalCompressed)
		return
	}

	filesToExtract := slices.Clone(t.selected)
	slices.Sort(filesToExtract)
	filesToExtract = slices.Compact(filesToExtract)
	if len(filesToExtract) == 0 {
		return
	}

	// Once the archive was listed, nothing it says afterwards makes it a plain
	// file: "not an archive" is for the listing only.
	var ignoredLinks []string
	if err = sze.extractBatches(ctx, archivePath, extractLocation, passwords, filesToExtract, &extraction, &ignoredLinks, baseAnomalies); err != nil {
		if errors.Is(err, ErrUnsupportedFormat) {
			err = fmt.Errorf("7z failed to extract an archive it had listed: %s", sanitizeOutput(err.Error()))
		}
		return
	}

	removed := removeLinkPlaceholders(extractLocation, ignoredLinks, sze.logger)
	produced := 0
	err = filepath.WalkDir(extractLocation, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			sze.logger.Error("error listing directory", slog.String("error", err.Error()), slog.String("path", path))
			return err
		}
		if d.IsDir() {
			return nil
		}
		produced++
		relPath, err := filepath.Rel(extractLocation, path)
		if err != nil {
			return err
		}
		if hasControl(relPath) {
			extraction.anomalies = noteAnomaly(extraction.anomalies, "an extracted file name contains a control character")
		}
		return extraction.update(path, relPath)
	})
	if err != nil {
		return
	}

	// Counted, not matched by name: a name 7z sanitizes can hide behind a
	// genuine file of the sanitized name.
	if expected := t.selectedCount - removed; produced != expected {
		sze.logger.Error("extraction does not match the listing",
			slog.Int("expected", expected), slog.Int("produced", produced), slog.String("archive", sanitizeOutput(archivePath)))
		extraction.anomalies = noteAnomaly(extraction.anomalies, fmt.Sprintf("extracted %d files, the listing announced %d", produced, expected))
	}
	return
}

const (
	// maxNamesPerRun and maxArgBytesPerRun bound one 7z command line: the
	// system limit on arguments is far above, but Windows' is 32 KiB.
	maxNamesPerRun    = sevenZipMaxFile
	maxArgBytesPerRun = 24 << 10
)

// extractBatches extracts the names in groups, trying each password in turn.
func (sze *sevenZipExtract) extractBatches(ctx context.Context, archivePath, extractLocation string, passwords, names []string, extraction *extractResult, ignoredLinks *[]string, baseAnomalies []string) error {
	commonArgs := []string{"-aou", "-o" + extractLocation, "-y", "-spd", "--", "x", archivePath}
	batches := batchNames(names, maxNamesPerRun, maxArgBytesPerRun)
	var err error
PASSWORD_LOOP:
	for _, pwd := range sze.passwordCandidates(passwords) {
		for _, batch := range batches {
			var links []string
			links, err = sze.runStream(ctx, pwd, slices.Concat(commonArgs, batch), nil, archivePath, extractLocation)
			switch {
			case err == nil:
				extraction.passwordUsed = pwd
			case errors.Is(err, ErrInvalidPassword):
				if rmErr := os.RemoveAll(extractLocation); rmErr != nil {
					return rmErr
				}
				if mkdErr := os.MkdirAll(extractLocation, 0o750); mkdErr != nil {
					return mkdErr
				}
				*ignoredLinks = nil
				extraction.symlinkFiles = nil
				extraction.anomalies = slices.Clone(baseAnomalies)
				continue PASSWORD_LOOP
			case errors.Is(err, errSevenZipRecoverable):
				sze.recoverableAnomaly(&extraction.anomalies, "extract", err)
			default:
				return err
			}
			*ignoredLinks = append(*ignoredLinks, links...)
			extraction.symlinkFiles = append(extraction.symlinkFiles, links...)
		}
		return nil
	}
	return err
}

// removeLinkPlaceholders deletes the empty files 7z leaves where it refused a
// link, and returns how many it deleted. Names come from 7z's messages, so
// they are only resolved inside the output folder.
func removeLinkPlaceholders(extractLocation string, names []string, logger *slog.Logger) (removed int) {
	if len(names) == 0 {
		return 0
	}
	root, err := os.OpenRoot(extractLocation)
	if err != nil {
		logger.Error("cannot open the output folder", slog.String("error", err.Error()))
		return 0
	}
	defer func() {
		if e := root.Close(); e != nil {
			logger.Warn("cannot close the output folder", slog.String("error", e.Error()))
		}
	}()
	for _, name := range names {
		fi, err := root.Lstat(name)
		if err != nil || !fi.Mode().IsRegular() || fi.Size() != 0 {
			continue
		}
		if err := root.Remove(name); err != nil {
			logger.Warn("cannot remove the placeholder of a refused link", slog.String("error", err.Error()))
			continue
		}
		removed++
	}
	return removed
}

// errSevenZipTimeout is returned when 7z ran past the time allowed.
var errSevenZipTimeout = errors.New("7z exceeded the time allowed")

// runStream runs 7z with the given password. The standard output is handed
// to consume as a stream (nil: discarded), never buffered; the standard error
// is kept up to maxSevenZipStderr. 7z is killed when it prints past a cap, when
// ctx ends or when consume fails. paths are what 7z may copy into its error
// output (the archive, the output folder).
func (sze *sevenZipExtract) runStream(ctx context.Context, password string, args []string, consume func(io.Reader) error, paths ...string) (symLinkFiles []string, err error) {
	passwordArg := "-P" + password
	if password == "" {
		passwordArg = "-p-"
	}
	runCtx, runCancel := context.WithTimeout(ctx, szRunTimeout)
	defer runCancel()
	cmd := exec.CommandContext(runCtx, sze.sevenZipPath, append([]string{passwordArg}, args...)...) //nolint:gosec // G204: binary path checked by DeclareExecutable at Init; arguments passed as argv, never through a shell
	stderr := &cappedBuffer{limit: maxSevenZipStderr, cancel: runCancel}
	cmd.Stderr = stderr
	cmd.WaitDelay = time.Second
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", plugins.ErrExtractorUnavailable, err)
	}
	if err = cmd.Start(); err != nil {
		// An argument list too long is the archive's fault, not the extractor's.
		if errors.Is(err, syscall.E2BIG) {
			return nil, fmt.Errorf("7z cannot be given this many member names: %w", err)
		}
		return nil, fmt.Errorf("%w: %w", plugins.ErrExtractorUnavailable, err)
	}

	limited := &io.LimitedReader{R: stdout, N: int64(maxSevenZipStdout) + 1}
	if consume == nil {
		consume = discard
	}
	consumeErr := consume(limited)
	if consumeErr == nil && limited.N <= 0 {
		consumeErr = errSevenZipOutputTooLarge
	}
	if consumeErr != nil {
		runCancel()
	}
	if _, copyErr := io.Copy(io.Discard, stdout); copyErr != nil {
		sze.logger.Debug("draining 7z output", slog.String("error", copyErr.Error()))
	}
	cmdErr := cmd.Wait()

	switch {
	case consumeErr != nil:
		return nil, consumeErr
	case errors.Is(runCtx.Err(), context.DeadlineExceeded):
		return nil, errSevenZipTimeout
	case stderr.exceeded:
		return nil, fmt.Errorf("%w: %s", errSevenZipOutputTooLarge, sanitizeOutput(stderr.buf.String()))
	}
	return handleSevenZipError(cmdErr, stderr.buf.String(), sze.logger, paths...)
}

func discard(r io.Reader) error {
	_, err := io.Copy(io.Discard, r)
	return err
}

// errSevenZipOutputTooLarge is returned when 7z printed more than the caps.
var errSevenZipOutputTooLarge = errors.New("7z output exceeds the allowed size")

// The caps on what 7z may print. Variables so tests can lower them. The
// standard output is streamed, not kept: its cap only stops an endless output.
var (
	maxSevenZipStdout = 1 << 30
	maxSevenZipStderr = 1 << 20
)

// cappedBuffer keeps what it is given up to limit; past it, it drops the data,
// notes the overflow and cancels the process that writes to it.
type cappedBuffer struct {
	buf      bytes.Buffer
	limit    int
	exceeded bool
	cancel   context.CancelFunc
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if c.exceeded {
		return len(p), nil
	}
	if c.buf.Len()+len(p) > c.limit {
		c.exceeded = true
		c.cancel()
		return len(p), nil
	}
	return c.buf.Write(p)
}

const dateFormat7z = "2006-01-02 15:04:05"

func parse7ZFileListLine(line string) (content FileProperties, err error) {
	// From https://github.com/ip7z/7zip/blob/5b39dc76f1bc82f941d5c800ab9f34407a06b53a/CPP/7zip/UI/Console/List.cpp//L195
	// The line is composed of 5 fields of fixed size with a space prefix, in this order:
	//  - Date Time, 19 characters, no prefix,
	//  - Attr, 5 characters, one space prefix,
	//  - Size, 12 characters, one space prefix,
	//  - Compressed size, 12 characters, one space prefix,
	//  - Name, 24 characters, 2 spaces prefix.
	//
	// Date, Size and Compressed can be missing, in this case, the matching field contains only spaces.
	if len(line) < szMinLineSize {
		err = errors.New("unable to parse 7z output: line is smaller than expected")
		return
	}

	// datetime
	dateTimeStr := ""
	dateTime, errParse := time.ParseInLocation(dateFormat7z, strings.Trim(line[szDateTimePrefix:szDateTimePrefix+szDateTimeSize], " "), time.UTC)
	if errParse == nil {
		dateTimeStr = dateTime.UTC().Format(time.RFC3339)
	}
	line = line[szDateTimePrefix+szDateTimeSize:]

	// Attributes are, in this order :
	//  - 'D' for directory, or '.',
	//  - 'R' for read-only, or '.',
	//  - 'H' for hidden, or '.',
	//  - 'S' for system, or '.',
	//  - 'A' for archive, or '.'.
	// The only interesting information is hidden
	hidden := false
	directory := false
	attrStr := strings.Trim(line[szAttrPrefix:szAttrPrefix+szAttrSize], " ")
	line = line[szAttrPrefix+szAttrSize:]
	if strings.Contains(attrStr, "D") {
		directory = true
	}
	if strings.Contains(attrStr, "H") {
		hidden = true
	}

	// size
	sizeStr := strings.Trim(line[szSizePrefix:szSizePrefix+szSizeSize], " ")
	size, errConv := strconv.Atoi(sizeStr)
	if errConv != nil {
		size = -1
	}
	line = line[szSizePrefix+szSizeSize:]

	// compressed size
	compressedStr := strings.Trim(line[szCompressedPrefix:szCompressedPrefix+szCompressedSize], " ")
	compressed, errConv := strconv.Atoi(compressedStr)
	if errConv != nil {
		compressed = -1
	}
	line = line[szCompressedPrefix+szCompressedSize:]

	// file name
	nameStr := line[szNamePrefix:]

	content = FileProperties{
		Name:           nameStr,
		Date:           dateTimeStr,
		IsDirectory:    directory,
		IsHidden:       hidden,
		Size:           size,
		CompressedSize: compressed,
	}
	return
}

func (ec *extractResult) update(filePath string, archivePath string) (err error) {
	var fi fs.FileInfo
	fi, err = os.Lstat(filePath)
	if err != nil {
		ec.logger.Error("unable to get stats on file", slog.String("file", filePath), slog.String("error", err.Error()))
		return
	}

	if fi.Mode()&os.ModeSymlink == os.ModeSymlink {
		ec.symlinkFiles = append(ec.symlinkFiles, filePath)
		errRm := os.Remove(filePath)
		if errRm != nil {
			ec.logger.Warn("could not remove extracted symlink", slog.String("error", errRm.Error()), slog.String("path", filePath))
		}
		return
	}

	ec.extractedFiles = append(ec.extractedFiles, ExtractedFile{
		Path:                 filePath,
		ArchivePath:          archivePath,
		Size:                 int(fi.Size()),
		LastModificationDate: fi.ModTime().UTC().Format(time.RFC3339),
	})

	// Ensure that user has read permission on the file, add it otherwise
	var f *os.File
	f, err = os.Open(filepath.Clean(filePath))
	switch {
	case err == nil:
		if errClose := f.Close(); errClose != nil {
			ec.logger.Error("failed closing file", slog.String("error", errClose.Error()), slog.String("path", f.Name()))
		}
	case errors.Is(err, os.ErrPermission):
		err = os.Chmod(filePath, 0o400)
		if err != nil {
			ec.logger.Error("could not add read permission to file", slog.String("error", err.Error()), slog.String("path", filePath))
			return
		}
	default:
		ec.logger.Error("unable to open file", slog.String("error", err.Error()), slog.String("path", filePath))
		return
	}
	return
}
