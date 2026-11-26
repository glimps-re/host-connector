//go:build linux

package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"hash/maphash"
	"io"
	"math"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/glimps-re/host-connector/pkg/datamodel"
)

const (
	// maxMemberNameLen is the longest member name accepted: no path is longer.
	maxMemberNameLen = 4096
	// maxNameComponent is the longest name a file system takes (NAME_MAX).
	maxNameComponent = 255
	// maxMemberDepth is the number of path separators from which a member is an
	// anomaly: nothing legitimate is nested that deep.
	maxMemberDepth = 64

	szTypePrefix      = "Type = "
	szTailSizePrefix  = "Tail Size ="
	szWarningsPrefix  = "WARNINGS:"
	szWarningsCount   = "Warnings: "
	szErrorsPrefix    = "ERRORS:"
	szErrorsCount     = "Errors: "
	szOpenErrorPrefix = "Open ERROR:"

	truncationMarker = "..."
	buffSize         = 64 * 1024
)

// maxListedEntries bounds the entries read from one listing; a variable for tests.
var maxListedEntries = 1_000_000

var (
	errTooManyEntries = errors.New("the archive lists too many entries")
	errBadListing     = errors.New("unexpected 7z listing")

	// szSummaryLine matches the last line of a listing: "<date or blanks> <sizes> N files[, M folders]".
	szSummaryLine = regexp.MustCompile(`^[\d: -]{19}[\d ]*\b(\d+) files?(?:, \d+ folders?)?$`)
)

// listSink consumes a 7z listing as a stream and keeps only what the rest of
// the extraction needs: the members to extract (bounded by the limits), a
// bounded list of the skipped ones, hashes of the skipped names, and counters.
type listSink struct {
	maxFileSize int64
	maxFiles    int
	maxTotal    int64

	seed maphash.Seed

	// Per table: the last table of the listing wins.
	table tableState

	tables int
	// tail is set when 7z reports data after the end of the archive.
	tail      bool
	anomalies []string
	// archiveType is the first "Type =" line before the first table: what 7z says
	// the archive is (an archive comment is printed after it, and can forge more).
	archiveType string
	// typeSeen says archiveType was read: an empty one is a Type line with no name,
	// not a line not seen yet.
	typeSeen bool
	// dataFailure is set when 7z reported a failure on the data of the archive
	// (as opposed to a structural anomaly): errors, a wrong password, a hint of
	// encryption, a failed check.
	dataFailure bool
	complete    bool
	summary     int
	hasSum      bool
}

type tableState struct {
	selected []string
	// dataEntries counts, by name, the selected members that carry data: a
	// failed run of 7z names a member once, whichever homonym failed, and says
	// nothing of an empty one.
	dataEntries   map[string]int
	selectedCount int
	selectedSize  int64
	skipped       skipList
	skippedHashes []uint64
	// unexamined counts the members left out as an anomaly (a name, a component or
	// a depth no file system takes): they are neither selected nor skipped, and
	// are never extracted nor tested, so nothing is known of their encryption.
	unexamined int
	// folders counts the folder entries of a zip that the listing shows empty: the
	// listing is the central directory, a local header can say more, so the headers
	// of the zip are walked (see walkZipFolders).
	folders int
	// imageType is set for a file system or a disk image (see imageFormats).
	imageType bool

	entries   int
	files     int
	totalSize int64
	// declared is the sizes the listing gives for the members within the size
	// limit, and packed what every member packs to, the ones over the limit
	// included (a solid block is listed on its first member). packedGiven says that
	// at least one member has a packed size: bzip2 gives none, Cab and Compound may give none.
	declared    int64
	packed      int64
	packedGiven bool
}

// skipList keeps the first datamodel.MaxListedSubfiles skipped members and the
// exact count of all of them.
type skipList struct {
	entries []datamodel.NotAnalyzedFile
	count   int
}

func (s *skipList) add(name string, size int64, reason datamodel.NotAnalyzedReason) {
	s.count++
	if len(s.entries) < datamodel.MaxListedSubfiles {
		s.entries = append(s.entries, datamodel.NotAnalyzedFile{FileName: truncateName(name), Size: max(size, 0), Reason: reason})
	}
}

// truncateName cuts name to datamodel.MaxListedNameLen bytes, on a rune
// boundary, ending with a marker.
func truncateName(name string) string {
	if len(name) <= datamodel.MaxListedNameLen {
		return name
	}
	cut := datamodel.MaxListedNameLen - len(truncationMarker)
	for cut > 0 && !utf8.RuneStart(name[cut]) {
		cut--
	}
	return name[:cut] + truncationMarker
}

func newListSink(maxFileSize int64, maxFiles int, maxTotal int64) *listSink {
	return &listSink{maxFileSize: maxFileSize, maxFiles: maxFiles, maxTotal: maxTotal, seed: maphash.MakeSeed()}
}

type listState int

const (
	beforeTable listState = iota
	afterTableHeader
	inTable
	afterTable
)

// splitLines splits on "\n" only: a member name may end with "\r", which
// bufio.ScanLines would remove.
func splitLines(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if i := bytes.IndexByte(data, '\n'); i >= 0 {
		return i + 1, data[:i], nil
	}
	if atEOF {
		return len(data), data, nil
	}
	return 0, nil, nil
}

// scan reads the listing line by line (a line is at most buffSize bytes) and
// feeds the sink. It never holds more than one line.
//
// An archive comment is printed before the real table and can contain a
// forged one: every header restarts the table, so the last one wins, and
// several tables are an anomaly. The number of entries read must match the
// summary line 7z prints under the table.
func (s *listSink) scan(r io.Reader) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), buffSize)
	sc.Split(splitLines)
	state := beforeTable
	for sc.Scan() {
		line := sc.Text()
		if line == szFileListHeader1 {
			s.startTable()
			state = afterTableHeader
			continue
		}
		switch state {
		case beforeTable:
			s.noteMeta(line)
		case afterTableHeader:
			if line != szFileListHeader2 {
				return fmt.Errorf("%w: line after the header", errBadListing)
			}
			state = inTable
		case inTable:
			if line == szFileListFooter {
				state = afterTable
				continue
			}
			if err := s.addLine(line); err != nil {
				return err
			}
		case afterTable:
			if !s.hasSum {
				if m := szSummaryLine.FindStringSubmatch(line); m != nil {
					s.hasSum = true
					s.summary = atoiOrNegative(m[1])
					continue
				}
			}
			s.noteMeta(line)
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("%w: %w", errBadListing, err)
	}
	s.complete = state == afterTable
	return nil
}

func atoiOrNegative(v string) int {
	n := 0
	for _, c := range v {
		n = n*10 + int(c-'0')
		if n > maxListedEntries*10 {
			return -1
		}
	}
	return n
}

func (s *listSink) startTable() {
	s.tables++
	if s.tables > 1 {
		s.anomalies = noteAnomaly(s.anomalies, "the listing holds several member tables")
	}
	s.table = tableState{imageType: imageFormat(s.archiveType)}
	s.hasSum = false
}

// noteMeta records what 7z says outside the member table: data after the end
// of the archive and warnings.
func (s *listSink) noteMeta(line string) {
	switch {
	case strings.HasPrefix(line, szTypePrefix) && !s.typeSeen && s.tables == 0:
		s.archiveType, s.typeSeen = strings.TrimPrefix(line, szTypePrefix), true
	case strings.HasPrefix(line, szTailSizePrefix):
		if v := strings.TrimSpace(strings.TrimPrefix(line, szTailSizePrefix)); v != "0" {
			s.tail = true
			s.anomalies = noteAnomaly(s.anomalies, "data after the end of the archive ("+v+" bytes)")
		}
	case strings.HasPrefix(line, szWarningsPrefix), strings.HasPrefix(line, szWarningsCount):
		s.anomalies = noteAnomaly(s.anomalies, "7z reported warnings")
	case strings.HasPrefix(line, szErrorsPrefix), strings.HasPrefix(line, szErrorsCount), strings.HasPrefix(line, szOpenErrorPrefix):
		s.anomalies = noteAnomaly(s.anomalies, "7z reported errors")
		s.dataFailure = true
	}
}

// deflateEmptyPacked is the packed size of an empty deflate stream (the fixed
// block "03 00"): two bytes cannot encode a literal. Only a zip is given it, and
// only when its headers confirm the method (walkZipFolders): the listing has no
// method column.
const deflateEmptyPacked = 2

const (
	zipType           = "zip"
	anomalyFolderData = "a folder entry holds data"
)

// imageFormats are the types 7-Zip reports (the Type line of its listing, exact
// names of 7-Zip 25.01, as `7zzs i` prints them) for the file systems and disk
// images, whose folders may have the size of their own records: that is not hidden
// content. Every other type, an unknown or an empty one included, is held to the
// rule that a folder holds nothing: a new format is covered, not let by.
var imageFormats = []string{
	"APFS", "APM", "CramFS", "Dmg", "Ext", "FAT", "GPT", "HFS", "Iso", "LP", "MBR",
	"NTFS", "QCOW", "Sparse", "SquashFS", "Udf", "VDI", "VHD", "VHDX", "VMDK", "wim",
}

// imageFormat tells whether a type is one of imageFormats.
func imageFormat(archiveType string) bool {
	return slices.Contains(imageFormats, archiveType)
}

// longComponent tells whether a path component of the name is longer than a file
// system takes (NAME_MAX). 7-Zip lists a backslash as a slash on Linux, so the
// names it prints are split on "/" only.
func longComponent(name string) bool {
	for part := range strings.SplitSeq(name, "/") {
		if len(part) > maxNameComponent {
			return true
		}
	}
	return false
}

func hasControl(name string) bool {
	return strings.ContainsFunc(name, unicode.IsControl)
}

func (s *listSink) addLine(line string) error {
	t := &s.table
	t.entries++
	if t.entries > maxListedEntries {
		return errTooManyEntries
	}
	fp, err := parse7ZFileListLine(line)
	if err != nil {
		return fmt.Errorf("%w: %w", errBadListing, err)
	}
	if fp.IsDirectory {
		// A folder holds no data. An entry that is flagged as a folder (a FAT host
		// in a zip, an attribute) and holds some is never extracted by 7z, while
		// other readers extract it as a file, and cut it at the packed size, not at
		// the size the headers declare: it is left out, so the archive is not proven
		// plain.
		if imageFormat(s.archiveType) {
			return nil
		}
		zip := s.archiveType == zipType
		switch {
		case fp.Name == "" || len(fp.Name) > maxMemberNameLen || longComponent(fp.Name):
			s.anomalies = noteAnomaly(s.anomalies, "a folder entry has a name no file system takes")
			t.unexamined++
		case fp.Size > 0 || (fp.CompressedSize > 0 && (!zip || fp.CompressedSize != deflateEmptyPacked)):
			s.anomalies = noteAnomaly(s.anomalies, anomalyFolderData)
			t.unexamined++
		case zip:
			t.folders++
		}
		return nil
	}
	t.files++
	// A size the listing does not give (flux formats: gzip, bzip2) is unknown,
	// never small: it weighs the largest a member may be.
	size := int64(fp.Size)
	if fp.Size < 0 {
		size = s.maxFileSize
	}
	// A blank column is unknown, not 0. The packed size of every member counts,
	// the ones over the size limit included: a solid block is listed on its first
	// member, which may be over the limit. A size counts as declared only within the
	// limit (the remaining budget, which the core gives as MaxFileSize), so that what
	// the bomb rule weighs is what would be extracted.
	if fp.CompressedSize >= 0 {
		t.packed = addClamped(t.packed, int64(fp.CompressedSize))
		t.packedGiven = true
	}
	if fp.Size >= 0 && int64(fp.Size) <= s.maxFileSize {
		t.declared = addClamped(t.declared, int64(fp.Size))
	}
	if size <= s.maxFileSize {
		t.totalSize = addClamped(t.totalSize, max(size, 0))
	}
	if len(fp.Name) > maxMemberNameLen {
		s.anomalies = noteAnomaly(s.anomalies, fmt.Sprintf("a member name is longer than %d bytes", maxMemberNameLen))
		t.unexamined++
		return nil
	}
	if longComponent(fp.Name) {
		// 7z lists it, the extraction cannot create it (NAME_MAX): left alone it
		// would fail and be retried for ever.
		s.anomalies = noteAnomaly(s.anomalies, fmt.Sprintf("a member name has a component longer than %d bytes", maxNameComponent))
		t.unexamined++
		return nil
	}
	if strings.Count(fp.Name, "/") >= maxMemberDepth {
		// Not extracted: a path of that depth only serves to create folders.
		s.anomalies = noteAnomaly(s.anomalies, fmt.Sprintf("a member path has %d folders or more", maxMemberDepth))
		t.unexamined++
		return nil
	}
	if hasControl(fp.Name) {
		s.anomalies = noteAnomaly(s.anomalies, "a member name contains a control character")
	}
	switch {
	case size > s.maxFileSize:
		t.skipped.add(fp.Name, int64(fp.Size), datamodel.NotAnalyzedExtractLimit)
		t.skippedHashes = append(t.skippedHashes, maphash.String(s.seed, fp.Name))
	case t.selectedCount >= s.maxFiles || t.selectedSize+max(size, 0) > s.maxTotal:
		t.skipped.add(fp.Name, int64(fp.Size), datamodel.NotAnalyzedExtractLimit)
		t.skippedHashes = append(t.skippedHashes, maphash.String(s.seed, fp.Name))
	default:
		t.selectedSize += max(size, 0)
		t.selectedCount++
		t.selected = append(t.selected, fp.Name)
		if size != 0 {
			if t.dataEntries == nil {
				t.dataEntries = map[string]int{}
			}
			t.dataEntries[fp.Name]++
		}
	}
	return nil
}

// finish runs the checks that need the whole listing: the entry count against
// 7z's summary, and skipped members sharing the name of a selected one (the
// extraction is by name, so the skipped one would be written too).
func (s *listSink) finish() {
	t := &s.table
	switch {
	case !s.hasSum:
		s.anomalies = noteAnomaly(s.anomalies, "the listing has no summary line")
	case s.summary != t.files:
		s.anomalies = noteAnomaly(s.anomalies, fmt.Sprintf("the listing holds %d files, 7z announced %d", t.files, s.summary))
	}
	if len(t.skippedHashes) == 0 || len(t.selected) == 0 {
		return
	}
	slices.Sort(t.skippedHashes)
	for _, name := range t.selected {
		if _, found := slices.BinarySearch(t.skippedHashes, maphash.String(s.seed, name)); found {
			s.anomalies = noteAnomaly(s.anomalies, "a skipped member has the name of a member to extract")
			return
		}
	}
}

// maxAnomalies bounds the anomalies kept for one archive: each kind is kept
// once, so an archive with a million booby-trapped members costs nothing more
// than one with a single one.
const maxAnomalies = 100

// noteAnomaly adds msg to list unless it is already there or the list is full.
func noteAnomaly(list []string, msg string) []string {
	if len(list) >= maxAnomalies || slices.Contains(list, msg) {
		return list
	}
	return append(list, msg)
}

// batchNames cuts names in groups of at most maxCount names and maxBytes
// bytes of arguments.
func batchNames(names []string, maxCount, maxBytes int) [][]string {
	var batches [][]string
	start, size := 0, 0
	for i, n := range names {
		if i > start && (i-start >= maxCount || size+len(n)+1 > maxBytes) {
			batches = append(batches, names[start:i])
			start, size = i, 0
		}
		size += len(n) + 1
	}
	if start < len(names) {
		batches = append(batches, names[start:])
	}
	return batches
}

// isBomb tells whether the members declare far more than the archive holds. What
// is weighed is what the listing gives: the sizes declared by the members within the
// size limit, over what every member packs to, capped at the size of the archive file
// (see packedForRatio). A bomb is more than zipBombThreshold declared, a packed size
// given by the listing, and a ratio over zipBombRatio; with no packed byte at all the
// ratio is infinite, which is a bomb. The file systems and the disk images (imageType,
// keyed on a type the archive chooses) are exempt: a sparse image of a few kilobytes
// declares gigabytes honestly. The type is the container's own choice, and some of
// those types are real compressors (wim, Dmg, SquashFS, CramFS, QCOW), so a bomb can
// be written in them: what they hold is bounded by the remaining budget of the
// extraction and its guard, and by nothing else. A listing that gives no packed size
// (bzip2, and Cab or Compound when they give none: MSI, .doc, .xls) has no ratio and
// is no bomb here: what a forged one declares is bounded by the failure of 7z and the
// guard of the extraction. A blank packed size is not 0.
func (t *tableState) isBomb(archiveSize int64) bool {
	switch {
	case t.declared <= zipBombThreshold, !t.packedGiven, t.imageType:
		return false
	}
	packed := t.packedForRatio(archiveSize)
	return packed == 0 || t.declared/packed > zipBombRatio
}

// weigh reads the size of the archive file at archivePath and says whether the
// table is a bomb for it, with the text of what it packs to. An archive file whose
// size cannot be read is an error: the clamp would be skipped, and a forged packed
// size could then hide a bomb.
func (t *tableState) weigh(archivePath string) (bomb bool, text string, err error) {
	size, err := fileSize(archivePath)
	if err != nil {
		return false, "", err
	}
	return t.isBomb(size), t.packedText(size), nil
}

// packedForRatio is what the members pack to, never more than the archive file
// holds: a forged entry that declares tens of gigabytes of packed bytes cannot be
// told apart by the listing, and would dilute the ratio of the honest ones.
func (t *tableState) packedForRatio(archiveSize int64) int64 {
	return min(t.packed, archiveSize)
}

// packedText says what the archive packs to and the ratio, for the message of a bomb.
func (t *tableState) packedText(archiveSize int64) string {
	packed := t.packedForRatio(archiveSize)
	if packed == 0 {
		return "no packed byte"
	}
	return fmt.Sprintf("packed: %d, ratio: %d", packed, t.declared/packed)
}

// addClamped is a + b, kept at the largest int64 instead of wrapping: the sizes of
// a hostile listing are not bounded by what an archive can hold.
func addClamped(a, b int64) int64 {
	if b > 0 && a > math.MaxInt64-b {
		return math.MaxInt64
	}
	return a + b
}
