package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/glimps-re/host-connector/pkg/datamodel"
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
	DefaultPasswords []string
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
	// relaunches counts the runs of 7z started again after a member past the
	// size limit, over the whole extraction.
	relaunches int
	// listed is the number of files in the listing; listedEntries all its entries.
	listed        int
	listedEntries int
	// dataEntries counts, by name, the members of the listing that carry data.
	dataEntries map[string]int
	listedSize  int64
	// tail is set when 7z reported data after the end of the archive.
	tail bool
	// produced and announced are the files found on disk and the files the
	// listing announced; set once the extraction has run.
	produced, announced int
	// dropped counts the selected members that were not extracted (too big once
	// written, or abandoned after a breach): they are in skipped.
	dropped   int
	skipped   skipList
	anomalies []string
	// dataFailure is set when 7z reported a failure on the data of the archive
	// during the listing or the extraction, even one a later password cured.
	dataFailure bool
	// listComplete is set when the listing reached its end.
	listComplete bool
	// overBudget is set by a check that holds the listing to a budget it exceeds,
	// with nothing else wrong: the members are left out, not damaged.
	overBudget bool
	// encryptionExcluded is set, when there are anomalies, once it is proven that
	// the archive holds no encrypted content.
	encryptionExcluded bool
	logger             *slog.Logger
}

// drop reports a selected member that will not be extracted.
func (ec *extractResult) drop(name string, size int64, reason datamodel.NotAnalyzedReason) {
	ec.skipped.add(name, size, reason)
	ec.dropped++
}

// skipState is what the listing decided about the members, kept to start again
// after a wrong password.
type skipState struct {
	skipped skipList
	dropped int
}

func (ec *extractResult) saveSkips() skipState {
	return skipState{skipped: skipList{entries: slices.Clone(ec.skipped.entries), count: ec.skipped.count}, dropped: ec.dropped}
}

func (ec *extractResult) restoreSkips(s skipState) {
	ec.skipped = skipList{entries: slices.Clone(s.skipped.entries), count: s.skipped.count}
	ec.dropped = s.dropped
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
	logger       *slog.Logger
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
	var trace encTrace
	failed := false
	for _, pwd := range sze.passwordCandidates(passwords) {
		*sink = *newListSink(sink.maxFileSize, sink.maxFiles, sink.maxTotal)
		_, err = sze.runStream(ctx, pwd, args, sink.scan, archivePath)
		switch {
		case err == nil:
		case errors.Is(err, errSevenZipRecoverable):
			sze.recoverableAnomaly(&sink.anomalies, "list", err)
			sink.dataFailure = true
		case errors.Is(err, ErrInvalidPassword):
			trace.wrong++
			failed = true
			continue
		case errors.Is(err, errEncryptionHint):
			trace.hintRuns++
			failed = true
			continue
		default:
			return err
		}
		sink.dataFailure = sink.dataFailure || failed
		// A listing that stops early is an anomaly 7z explained, or a failure.
		if !sink.complete && len(sink.anomalies) == 0 {
			return fmt.Errorf("%w: header or footer not found", errBadListing)
		}
		sink.finish()
		return nil
	}
	entries := 0
	if sink.complete {
		entries = sink.table.entries
	}
	return sze.decideEncryption(ctx, archivePath, trace, entries, err)
}

// encTrace is what the passwords tried said about an archive: how many runs
// said a password is wrong for sure, how many only failed in a way an encryption
// can explain, and whether a member was extracted cleanly.
type encTrace struct {
	wrong, hintRuns int
	extracted       bool
}

// decideEncryption settles the failure of every password.
//   - No run only suggested an encryption: a wrong password for sure is an
//     encrypted archive if nothing was extracted; anything else is err.
//   - Otherwise the technical listing decides. An archive that was opened is a
//     corrupted one (extraction error, never encrypted): a run of hints named
//     fewer members than the batch held (the others were extracted), or it is a
//     zip in which a password passed the check of its members (a run with only
//     data errors and no "Wrong password") and then failed. An archive that
//     nothing opened is encrypted if a member says so or a password was refused
//     for sure.
//   - A listing that is not as expected, whichever path it is read on, leaves
//     the extraction error. entries is the number of entries the listing
//     announced, 0 when it did not get to say. When the context ends, its error
//     is returned, as the timeout of the listing.
//
// A "Wrong password" for a member is partial encryption, however many members
// were extracted before: the archive is encrypted. A 7z archive every member of
// which is corrupted, with a known password, cannot be told from an unknown
// password: it is taken for encrypted. A 7z archive that mixes a member with an
// unknown password and a plain one is an extraction error. ZipCrypto checks a
// password with one byte: about one wrong password in 256 passes the check of a
// member and then fails on its data, as a run of hints.
func (sze *sevenZipExtract) decideEncryption(ctx context.Context, archivePath string, trace encTrace, entries int, err error) error {
	if trace.hintRuns == 0 {
		if trace.wrong > 0 && !trace.extracted {
			return ErrInvalidPassword
		}
		return err
	}
	failure := err
	if !errors.Is(failure, errEncryptionHint) {
		failure = errors.Join(errEncryptionHint, errors.New("a member failed in a way an encryption can explain"))
	}
	info, infoErr := sze.encryptionInfo(ctx, archivePath, entries)
	switch {
	case ctx.Err() != nil && infoErr != nil:
		return ctx.Err()
	case errors.Is(infoErr, errSevenZipTimeout):
		return infoErr
	case infoErr != nil:
		sze.logger.Warn("the technical listing of an archive is not as expected", slog.String("error", infoErr.Error()))
		return failure
	case trace.extracted || info.zip:
		return failure
	case info.encrypted || trace.wrong > 0:
		return ErrInvalidPassword
	}
	return failure
}

// encryptionInfo is what the technical listing of an archive says.
type encryptionInfo struct {
	zip       bool // the archive is a zip
	encrypted bool // a member says Encrypted = +
	// allPlain is set when every member says Encrypted = -, and none says anything
	// else or nothing.
	allPlain bool
	// attached is set when the archive says it has data after its end (Tail Size)
	// or before it (Offset, Embedded Stub Size, or the warning that it is open
	// with an offset), or says it with a value that cannot be read: another
	// archive can hide there, which 7z does not list.
	attached bool
}

// nonZero tells whether the value of a size line is not zero; a value that cannot
// be read counts as not zero.
func nonZero(value []byte) bool {
	n, err := strconv.ParseUint(string(bytes.TrimSpace(value)), 10, 64)
	return err != nil || n > 0
}

const technicalSeparator = "----------"

// encryptionInfo reads the technical listing of the archive, by block. What is
// before the first separator is the archive's own (its comment is printed raw
// and can hold any line): only its first "Type =" counts. After it, each member
// is a block starting with "Path = ", of which only the first "Encrypted =" line
// counts. The number of members must be the number the listing announced, when
// that is known.
func (sze *sevenZipExtract) encryptionInfo(ctx context.Context, archivePath string, entries int) (info encryptionInfo, err error) {
	var archiveType string
	var records, separators, plain int
	inBlock, sawEncrypted := false, false
	_, runErr := sze.runStream(ctx, "", []string{"-spd", "-slt", "--", "l", archivePath}, func(r io.Reader) error {
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 0, buffSize), maxListingLine)
		sc.Split(splitLines)
		for sc.Scan() {
			line := sc.Bytes()
			switch {
			case separators == 0:
				switch {
				case string(line) == technicalSeparator:
					separators++
				case archiveType == "" && bytes.HasPrefix(line, []byte("Type = ")):
					archiveType = string(bytes.TrimPrefix(line, []byte("Type = ")))
				case bytes.HasPrefix(line, []byte("Tail Size = ")):
					info.attached = info.attached || nonZero(bytes.TrimPrefix(line, []byte("Tail Size = ")))
				case bytes.HasPrefix(line, []byte("Offset = ")):
					info.attached = info.attached || nonZero(bytes.TrimPrefix(line, []byte("Offset = ")))
				case bytes.HasPrefix(line, []byte("Embedded Stub Size = ")):
					info.attached = info.attached || nonZero(bytes.TrimPrefix(line, []byte("Embedded Stub Size = ")))
				case bytes.HasPrefix(line, []byte("Warning: The archive is open with offset")):
					info.attached = true
				}
			case string(line) == technicalSeparator:
				// One separator, between the archive and its members: a second one is
				// a comment's.
				return fmt.Errorf("%w: more than one separator", errBadListing)
			case bytes.HasPrefix(line, []byte("Path = ")):
				records++
				inBlock, sawEncrypted = true, false
				if records > maxListedEntries {
					return errTooManyEntries
				}
			case !inBlock && (bytes.HasPrefix(line, []byte("Type = ")) || bytes.HasPrefix(line, []byte("Encrypted = "))):
				return fmt.Errorf("%w: a member field before the first member", errBadListing)
			case inBlock && !sawEncrypted && bytes.HasPrefix(line, []byte("Encrypted = ")):
				sawEncrypted = true
				switch string(line) {
				case "Encrypted = +":
					info.encrypted = true
				case "Encrypted = -":
					plain++
				}
			}
		}
		return sc.Err()
	}, archivePath)
	switch {
	case runErr != nil:
		return info, runErr
	case separators == 0 || records == 0:
		return info, fmt.Errorf("%w: no member in the technical listing", errBadListing)
	case entries > 0 && records != entries:
		return info, fmt.Errorf("%w: %d members in the technical listing, %d announced", errBadListing, records, entries)
	}
	info.zip = archiveType == "zip"
	info.allPlain = plain == records
	return info, nil
}

// checkOnly lists the archive and tests every member, with the password of no one
// (noPassword), without writing anything. A member that needs a password, a known
// one included, is encrypted: nothing is extracted and nothing would be analyzed.
// What the test finds is told apart by decideEncryption, as for an extraction; the
// integrity test is what catches an encryption that the listing hides. The listing
// is held to the budget of the extraction (members, total size, ratio) before
// anything is read.
func (sze *sevenZipExtract) checkOnly(ctx context.Context, archivePath string, limits plugins.ExtractLimits) (res extractResult, err error) {
	ctx, cancel := context.WithTimeout(ctx, archiveTimeout(archivePath, 0))
	defer cancel()
	nopw := *sze
	nopw.config = extractorConfig{}
	// No cap per member: the budget of the extraction (members, total size, ratio) is
	// what the check holds the listing to, as a document may hold a large medium.
	const unlimited = 1 << 62
	sink := newListSink(unlimited, max(limits.MaxFiles, 0), max(limits.MaxTotalSize, 0))
	res.logger = sze.logger
	if err = nopw.list(ctx, archivePath, nil, sink); err != nil {
		return res, err
	}
	res.anomalies = slices.Clone(sink.anomalies)
	res.dataFailure, res.listComplete, res.listedEntries = sink.dataFailure, sink.complete, sink.table.entries
	res.skipped = sink.table.skipped
	defer func() {
		if err == nil && len(res.anomalies) > 0 {
			res.encryptionExcluded = nopw.excludesEncryption(ctx, archivePath, &res)
		}
	}()
	t := &sink.table
	switch {
	// The bomb first: a member that declares gigabytes is over any small budget,
	// and must stay what it is, an anomaly, not a document left out by the limits.
	case t.isBomb():
		res.anomalies = noteAnomaly(res.anomalies, "the sizes of the members are high compared to the archive, potential ZipBomb")
		res.dataFailure = true
		return res, nil
	case t.skipped.count > 0:
		if len(res.anomalies) == 0 {
			res.overBudget = true
			return res, nil
		}
		res.anomalies = noteAnomaly(res.anomalies, "the listing announces more members or bytes than the extraction budget allows")
		return res, nil
	}
	_, runErr := nopw.runStream(ctx, "", []string{"-spd", "--", "t", archivePath}, discard, archivePath)
	var trace encTrace
	switch {
	case runErr == nil:
		return res, nil
	case errors.Is(runErr, ErrInvalidPassword):
		trace.wrong++
		res.dataFailure = true
	case errors.Is(runErr, errEncryptionHint):
		trace.hintRuns++
		res.dataFailure = true
	case errors.Is(runErr, errSevenZipRecoverable):
		nopw.recoverableAnomaly(&res.anomalies, "test", runErr)
		res.dataFailure = true
		return res, nil
	default:
		return res, runErr
	}
	return res, nopw.decideEncryption(ctx, archivePath, trace, res.listedEntries, runErr)
}

// excludesEncryption is the one proof that an archive with anomalies holds no
// encrypted content, which the archive controls the flags of (7z's own
// Encrypted flag can be cleared, and a check byte can collide). It holds only
// when nothing could hide an encryption: the listing was complete, 7z reported no
// failure on the data of any member (nor a wrong password, nor a hint of
// encryption, even one a later password cured), every listed member was
// extracted, and the technical listing, complete and parsed, says Encrypted = -
// for every member and no data before or after the archive (an archive hidden
// there is not listed by 7z). Anything else leaves the encryption possible.
func (sze *sevenZipExtract) excludesEncryption(ctx context.Context, archivePath string, res *extractResult) bool {
	if res.dataFailure || !res.listComplete || res.skipped.count > 0 || res.dropped > 0 || res.produced != res.announced {
		return false
	}
	info, err := sze.encryptionInfo(ctx, archivePath, res.listedEntries)
	if err != nil {
		sze.logger.Warn("the technical listing of an archive with anomalies is not as expected", slog.String("error", err.Error()))
	}
	return err == nil && info.allPlain && !info.attached
}

// maxListingLine bounds a line of a technical listing, as buffSize bounds a line
// of the table: the technical listing prints the comment of the archive and the
// names of the members, which are the archive's, and a longer line is an error.
const maxListingLine = 1 << 20

func (sze *sevenZipExtract) extract(ctx context.Context, archivePath string, extractLocation string, passwords []string, limits plugins.ExtractLimits) (extraction extractResult, err error) {
	// we do not extract the all archive at once for security reasons
	// first list files then extract one by one
	maxFileSize, maxFiles, maxTotal := limits.MaxFileSize, limits.MaxFiles, limits.MaxTotalSize
	ctx, cancel := context.WithTimeout(ctx, archiveTimeout(archivePath, maxTotal))
	defer cancel()
	sink := newListSink(maxFileSize, maxFiles, maxTotal)
	extraction.logger = sze.logger
	defer func() {
		if err == nil && len(extraction.anomalies) > 0 {
			extraction.encryptionExcluded = sze.excludesEncryption(ctx, archivePath, &extraction)
		}
	}()
	if err = sze.list(ctx, archivePath, passwords, sink); err != nil {
		return
	}
	baseAnomalies := slices.Clone(sink.anomalies)
	extraction.anomalies = slices.Clone(baseAnomalies)
	extraction.skipped = sink.table.skipped
	extraction.listed = sink.table.files
	extraction.listedEntries = sink.table.entries
	extraction.listedSize = sink.table.totalSize
	extraction.tail = sink.tail
	extraction.dataFailure = sink.dataFailure
	extraction.listComplete = sink.complete
	t := &sink.table

	// zip bomb detection (only count files that would pass MaxFileSize filter)
	if t.isBomb() {
		err = fmt.Errorf("size of files within archive is high compared to archive size, potential ZipBomb (total: %d, compressed: %d, ratio: %d)", t.totalSize, t.totalCompressed, t.totalSize/t.totalCompressed)
		return
	}

	filesToExtract := slices.Clone(t.selected)
	slices.Sort(filesToExtract)
	extraction.dataEntries = t.dataEntries
	filesToExtract = slices.Compact(filesToExtract)
	if len(filesToExtract) == 0 {
		return
	}

	// Once the archive was listed, nothing it says afterwards makes it a plain
	// file: "not an archive" is for the listing only.
	var ignoredLinks []string
	lim := limits
	if err = sze.extractBatches(ctx, archivePath, extractLocation, passwords, filesToExtract, &extraction, &ignoredLinks, baseAnomalies, lim); err != nil {
		if errors.Is(err, ErrUnsupportedFormat) {
			err = fmt.Errorf("%w: %w: 7z failed to extract an archive it had listed: %s", plugins.ErrArchiveAnomaly, plugins.ErrEncryptionPossible, sanitizeOutput(err.Error()))
		}
		return
	}

	removed := removeLinkPlaceholders(extractLocation, ignoredLinks, sze.logger)
	produced := 0
	var producedBytes int64
	err = filepath.WalkDir(extractLocation, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			sze.logger.Error("error listing directory", slog.String("error", err.Error()), slog.String("path", path))
			return err
		}
		if d.IsDir() {
			return nil
		}
		relPath, err := filepath.Rel(extractLocation, path)
		if err != nil {
			return err
		}
		// The bytes produced are measured whatever 7z said: its exit code and
		// the sizes of the listing are not trusted.
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			if info.Size() > maxFileSize {
				if rmErr := removeInside(extractLocation, relPath); rmErr != nil {
					return rmErr
				}
				extraction.drop(filepath.ToSlash(relPath), info.Size(), datamodel.NotAnalyzedTooBig)
				return nil
			}
			producedBytes += info.Size()
		}
		produced++
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
	if producedBytes > maxTotal {
		sze.logger.Error("7z wrote more bytes than the extraction budget allows", slog.String("archive", sanitizeOutput(archivePath)))
		for _, f := range extraction.extractedFiles {
			if rmErr := removeInside(extractLocation, f.ArchivePath); rmErr != nil {
				err = fmt.Errorf("%w: a file over the budget could not be removed: %w", errOutputFolder, rmErr)
				return
			}
			extraction.drop(f.ArchivePath, int64(f.Size), datamodel.NotAnalyzedExtractLimit)
		}
		extraction.extractedFiles, produced = nil, 0
	}
	expected := t.selectedCount - removed - extraction.dropped
	extraction.produced, extraction.announced = produced, expected
	if produced != expected {
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

// Relaunches of 7z after a member found past the size limit: at most this many
// for one batch of names, and this many for the whole extraction.
const (
	maxRelaunches      = 8
	maxTotalRelaunches = 8
)

// batchData is the number of members of the listing with data that a batch of
// names stands for: with the homonyms of each name, and without the empty ones.
func (e *extractResult) batchData(batch []string) int {
	n := 0
	for _, name := range batch {
		n += e.dataEntries[name]
	}
	return n
}

// extractBatches extracts the names in groups, trying each password in turn.
func (sze *sevenZipExtract) extractBatches(ctx context.Context, archivePath, extractLocation string, passwords, names []string, extraction *extractResult, ignoredLinks *[]string, baseAnomalies []string, lim plugins.ExtractLimits) error {
	batches := batchNames(names, maxNamesPerRun, maxArgBytesPerRun)
	baseSkips := extraction.saveSkips()
	var err error
	var trace encTrace
PASSWORD_LOOP:
	for _, pwd := range sze.passwordCandidates(passwords) {
		aborted := false
		for _, batch := range batches {
			if aborted {
				sze.abandon(extraction, batch, "7z was stopped before this member")
				continue
			}
			var links []string
			links, aborted, err = sze.runBatch(ctx, pwd, archivePath, extractLocation, batch, extraction, lim)
			switch {
			case err == nil:
				extraction.passwordUsed = pwd
				trace.extracted = true
			case errors.Is(err, ErrInvalidPassword), errors.Is(err, errEncryptionHint):
				extraction.dataFailure = true
				if errors.Is(err, ErrInvalidPassword) {
					trace.wrong++
				} else {
					trace.hintRuns++
					// A hint run that failed on fewer members than the batch held
					// extracted the others cleanly: the password opened the archive.
					if hint, ok := errors.AsType[*encryptionHintError](err); ok && hint.members > 0 && hint.members < extraction.batchData(batch) {
						trace.extracted = true
					}
				}
				if rmErr := os.RemoveAll(extractLocation); rmErr != nil {
					return rmErr
				}
				if mkdErr := os.MkdirAll(extractLocation, 0o750); mkdErr != nil {
					return mkdErr
				}
				*ignoredLinks = nil
				extraction.symlinkFiles = nil
				extraction.relaunches = 0
				// What the listing decided (too-big, extract-limit) stays.
				extraction.restoreSkips(baseSkips)
				extraction.anomalies = slices.Clone(baseAnomalies)
				continue PASSWORD_LOOP
			case errors.Is(err, errSevenZipRecoverable):
				extraction.dataFailure = true
				sze.recoverableAnomaly(&extraction.anomalies, "extract", err)
			default:
				return err
			}
			*ignoredLinks = append(*ignoredLinks, links...)
			extraction.symlinkFiles = append(extraction.symlinkFiles, links...)
		}
		return nil
	}
	return sze.decideEncryption(ctx, archivePath, trace, extraction.listedEntries, err)
}

// abandon leaves the members that will not be extracted because a limit was
// breached in the skipped list as extract-limit: the policy of the files too big
// decides, nothing lets them through unseen.
func (sze *sevenZipExtract) abandon(extraction *extractResult, names []string, why string) {
	sze.logger.Warn("members left out", slog.String("reason", why), slog.Int("members", len(names)))
	for _, n := range names {
		extraction.drop(n, 0, datamodel.NotAnalyzedExtractLimit)
	}
}

// errOutputFolder is the failure of the host: the output folder of 7z cannot be
// read, measured or cleaned. It says nothing of the archive, which is retried.
var errOutputFolder = errors.New("the output folder of 7z cannot be used")

// fileLimitFor is the size the kernel lets one file grow to, plus one byte (a
// file that reaches it is past the limit): the per-file limit, or what is left
// of the budget when that is smaller, so that a single member cannot go past the
// budget either. 0 means no limit could be computed. What a file that reaches
// the limit means depends on the term that applied: the per-file limit (a
// member too big, reported alone) or what was left of the budget (the archive
// announced less than it wrote, an anomaly). On a tie the per-file limit wins.
func fileLimitFor(maxFileSize, maxTotal, written int64) int64 {
	left := max(maxTotal-written, 0)
	limit := min(maxFileSize, left)
	if limit == math.MaxInt64 {
		return 0
	}
	return limit + 1
}

// runBatch extracts one batch of names with the output watched.
//
// 7z that stopped by itself with a member past the size limit (exit code 0):
// the other members are complete, only the offender is removed and reported
// too-big. 7z stopped by the guard or the kernel: files written by the run are
// deleted and the batch is run again without the offender, at most maxRelaunches
// times for the batch and maxTotalRelaunches for the extraction. A breach of the
// budget, a member that cannot be identified or the end of the relaunches leave
// the rest of the batch out as extract-limit; an output folder that cannot be read,
// measured or cleaned is the failure of the host, returned as an error.
// aborted tells that the remaining batches must be abandoned too.
func (sze *sevenZipExtract) runBatch(ctx context.Context, pwd, archivePath, extractLocation string, batch []string, extraction *extractResult, lim plugins.ExtractLimits) (links []string, aborted bool, err error) {
	remaining := batch
	for relaunch := 0; ; relaunch++ {
		before, snapErr := snapshot(extractLocation)
		written, writtenErr := bytesWritten(extractLocation)
		if readErr := errors.Join(snapErr, writtenErr); readErr != nil {
			return nil, true, fmt.Errorf("%w: %w", errOutputFolder, readErr)
		}
		args := slices.Concat([]string{"-aou", "-o" + extractLocation, "-y", "-spd", "--", "x", archivePath}, remaining)
		spec := runSpec{password: pwd, args: args, paths: []string{archivePath, extractLocation}, fileLimit: fileLimitFor(lim.MaxFileSize, lim.MaxTotalSize, written)}
		if guardEnabled {
			spec.guard = &guard{dir: extractLocation, maxFileSize: lim.MaxFileSize, maxTotal: lim.MaxTotalSize, maxFiles: lim.MaxFiles, logger: sze.logger}
		}
		links, err = sze.run(ctx, spec)
		var hit *limitHit
		if !errors.As(err, &hit) {
			return links, false, err
		}
		switch {
		case hit.broken:
			return nil, true, errors.Join(fmt.Errorf("%w: it could not be measured", errOutputFolder), sze.removeRun(extractLocation, before))
		case hit.budget:
			if err = sze.removeRun(extractLocation, before); err != nil {
				return nil, true, err
			}
			sze.abandon(extraction, remaining, "7z wrote more than the sizes announced by the archive")
			return nil, true, nil
		case !slices.Contains(remaining, hit.offender):
			if err = sze.removeRun(extractLocation, before); err != nil {
				return nil, true, err
			}
			sze.abandon(extraction, remaining, "a file written past the size limit cannot be matched to a member")
			return nil, true, nil
		case hit.completed:
			if rmErr := removeInside(extractLocation, hit.offender); rmErr != nil {
				return nil, true, fmt.Errorf("%w: a file past the size limit could not be removed: %w", errOutputFolder, rmErr)
			}
			extraction.drop(hit.offender, hit.size, datamodel.NotAnalyzedTooBig)
			return links, false, nil
		}
		if err = sze.removeRun(extractLocation, before); err != nil {
			return nil, true, err
		}
		extraction.relaunches++
		if relaunch >= maxRelaunches || extraction.relaunches > maxTotalRelaunches {
			sze.abandon(extraction, remaining, "too many members written past the size limit")
			return nil, true, nil
		}
		extraction.drop(hit.offender, hit.size, datamodel.NotAnalyzedTooBig)
		remaining = slices.DeleteFunc(slices.Clone(remaining), func(n string) bool { return n == hit.offender })
		if len(remaining) == 0 {
			return nil, false, nil
		}
	}
}

// removeRun deletes what a run of 7z wrote. A failure is the host's: the files
// left would be taken for the output of the next run.
func (sze *sevenZipExtract) removeRun(dir string, before map[string]struct{}) error {
	if err := removeNewFiles(dir, before, sze.logger); err != nil {
		return fmt.Errorf("%w: the files of a stopped run cannot be removed: %w", errOutputFolder, err)
	}
	return nil
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

// The time one archive may take: a base plus the time to read the archive and
// write the budget at a slow disk rate, never more than szRunTimeout. Variables
// for tests.
var (
	baseArchiveTimeout          = 2 * time.Minute
	archiveBytesPerSecond int64 = 5 << 20
)

// archiveTimeout is the time budget of the extraction of the archive at path.
func archiveTimeout(path string, maxTotal int64) time.Duration {
	size := int64(0)
	if fi, err := os.Stat(path); err == nil {
		size = fi.Size()
	}
	// Bounded before the addition: a limit near MaxInt64 must not overflow.
	const bound = int64(1) << 50
	seconds := min((min(size, bound)+min(max(maxTotal, 0), bound))/archiveBytesPerSecond, int64(szRunTimeout/time.Second))
	return min(baseArchiveTimeout+time.Duration(seconds)*time.Second, szRunTimeout)
}

// removeInside deletes the file rel under dir, resolved inside dir only.
func removeInside(dir, rel string) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer func() {
		if e := root.Close(); e != nil {
			slog.Warn("cannot close the output folder", slog.String("error", e.Error()))
		}
	}()
	return root.Remove(rel)
}

// errSevenZipTimeout is returned when 7z ran past the time allowed.
var errSevenZipTimeout = fmt.Errorf("7z exceeded the time allowed: %w", context.DeadlineExceeded)

// runSpec describes one run of 7z.
type runSpec struct {
	password string
	args     []string
	// consume receives the standard output as a stream; nil: discarded.
	consume func(io.Reader) error
	// paths are what 7z may copy into its error output (the archive, the
	// output folder).
	paths []string
	// guard, when set, watches the output folder and stops 7z past the limits.
	guard *guard
	// fileLimit, when positive, is the size the kernel lets a file grow to.
	fileLimit int64
}

// runStream runs 7z with the given password. The standard output is handed
// to consume as a stream (nil: discarded), never buffered; the standard error
// is kept up to maxSevenZipStderr. 7z is killed when it prints past a cap, when
// ctx ends or when consume fails. paths are what 7z may copy into its error
// output (the archive, the output folder).
func (sze *sevenZipExtract) runStream(ctx context.Context, password string, args []string, consume func(io.Reader) error, paths ...string) (symLinkFiles []string, err error) {
	return sze.run(ctx, runSpec{password: password, args: args, consume: consume, paths: paths})
}

// noPassword is the password of every run that is meant to run without one: a
// random one, drawn once per process and known to no archive. 7-Zip takes "-p-" for
// the literal password "-", which an archive can be encrypted with, so it is never
// used to mean "no password": the listing, the first attempt of an extraction and
// the check all run with this one, and a member that it does not open needs a
// password.
//
// The password is on the command line of 7-Zip, which the users of the account of
// the connector can read in /proc: it is not a secret, and does not need to be, as
// it only has to be a password that no archive can have been encrypted with. The
// known passwords are on that command line too.
//
// A failure of the random source is kept until the process restarts (the draw is
// made once): every run then fails as an unavailable extractor, which is fail
// closed.
var noPassword = sync.OnceValues(func() (string, error) { return drawNoPassword(rand.Reader) })

// drawNoPassword draws 16 bytes from r, as 32 hexadecimal characters.
func drawNoPassword(r io.Reader) (string, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", fmt.Errorf("no random source for the password of 7z: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// run is runStream with the limits on what 7z writes: the kernel's limit on
// each file, and the watch of the output folder. A run stopped by them returns
// a *limitHit.
func (sze *sevenZipExtract) run(ctx context.Context, spec runSpec) (symLinkFiles []string, err error) {
	if spec.password == "" {
		random, drawErr := noPassword()
		if drawErr != nil {
			return nil, fmt.Errorf("%w: %w", plugins.ErrExtractorUnavailable, drawErr)
		}
		spec.password = random
	}
	passwordArg := "-P" + spec.password
	runCtx, runCancel := context.WithTimeout(ctx, szRunTimeout)
	defer runCancel()
	stderr := &cappedBuffer{limit: maxSevenZipStderr, cancel: runCancel}
	cmd, stdout, err := startRetryingBusy(runCtx, sze.sevenZipPath, append([]string{passwordArg}, spec.args...), stderr)
	if err != nil {
		// A cancelled or expired context says nothing about the extractor.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		// An argument list too long is the archive's fault, not the extractor's.
		if errors.Is(err, syscall.E2BIG) {
			return nil, fmt.Errorf("7z cannot be given this many member names: %w", err)
		}
		return nil, fmt.Errorf("%w: %w", plugins.ErrExtractorUnavailable, err)
	}
	if e := limitProcess(cmd.Process.Pid, spec.fileLimit); e != nil {
		sze.logger.Warn("cannot limit what 7z writes, relying on the watch of the output folder", slog.String("error", e.Error()))
	}
	var watching sync.WaitGroup
	watchCtx, stopWatch := context.WithCancel(runCtx)
	if spec.guard != nil {
		watching.Go(func() { spec.guard.watch(watchCtx, runCancel) })
	}

	limited := &io.LimitedReader{R: stdout, N: int64(maxSevenZipStdout) + 1}
	consume := spec.consume
	if consume == nil {
		consume = discard
	}
	consumeErr := consume(limited)
	if consumeErr != nil {
		runCancel()
	}
	// What the consumer did not read is drained, still under the cap.
	if _, copyErr := io.Copy(io.Discard, limited); copyErr != nil {
		sze.logger.Debug("draining 7z output", slog.String("error", copyErr.Error()))
	}
	if consumeErr == nil && limited.N <= 0 {
		consumeErr = errSevenZipOutputTooLarge
		runCancel()
	}
	cmdErr := cmd.Wait()
	stopWatch()
	watching.Wait()

	if spec.guard != nil {
		if hit, killed := spec.guard.result(); hit != nil {
			hit.completed = !killed && cmdErr == nil
			return nil, hit
		}
	}
	switch {
	case ctx.Err() != nil && !errors.Is(runCtx.Err(), context.DeadlineExceeded):
		// Interrupted: whatever 7z said before it was killed, the extraction is
		// not complete.
		return nil, ctx.Err()
	case errors.Is(runCtx.Err(), context.DeadlineExceeded):
		return nil, errSevenZipTimeout
	case consumeErr != nil:
		return nil, consumeErr
	case stderr.exceeded:
		return nil, fmt.Errorf("%w: %s", errSevenZipOutputTooLarge, sanitizeOutput(stderr.buf.String()))
	}
	return handleSevenZipError(cmdErr, stderr.buf.String(), sze.logger, spec.paths...)
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

// startCmd starts a command; a variable so tests can inject start failures.
var startCmd = func(cmd *exec.Cmd) error { return cmd.Start() }

const (
	busyAttempts = 10
	busyPause    = 50 * time.Millisecond
)

// startRetryingBusy starts 7z. A binary written a moment ago can be reported
// busy (ETXTBSY) while another goroutine's fork still holds the descriptor that
// wrote it: a short retry, with a new command each time, gets past it. The
// pause stops with ctx and there is none after the last attempt.
func startRetryingBusy(ctx context.Context, path string, args []string, stderr io.Writer) (cmd *exec.Cmd, stdout io.ReadCloser, err error) {
	for attempt := range busyAttempts {
		cmd = exec.CommandContext(ctx, path, args...) //nolint:gosec // G204: binary path checked by DeclareExecutable at Init; arguments passed as argv, never through a shell
		cmd.Stderr = stderr
		cmd.WaitDelay = time.Second
		confineProcess(cmd)
		if stdout, err = cmd.StdoutPipe(); err != nil {
			return nil, nil, err
		}
		if err = startCmd(cmd); !errors.Is(err, syscall.ETXTBSY) {
			return cmd, stdout, err
		}
		if attempt == busyAttempts-1 {
			break
		}
		select {
		case <-ctx.Done():
			return cmd, stdout, ctx.Err()
		case <-time.After(busyPause):
		}
	}
	return cmd, stdout, err
}
