package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"hash/maphash"
	"io"
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
	// maxMemberDepth is the number of path separators from which a member is an
	// anomaly: nothing legitimate is nested that deep.
	maxMemberDepth = 64

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
	complete  bool
	summary   int
	hasSum    bool
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

	entries         int
	files           int
	totalSize       int64
	totalCompressed int64
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
	s.table = tableState{}
	s.hasSum = false
}

// noteMeta records what 7z says outside the member table: data after the end
// of the archive and warnings.
func (s *listSink) noteMeta(line string) {
	switch {
	case strings.HasPrefix(line, szTailSizePrefix):
		if v := strings.TrimSpace(strings.TrimPrefix(line, szTailSizePrefix)); v != "0" {
			s.tail = true
			s.anomalies = noteAnomaly(s.anomalies, "data after the end of the archive ("+v+" bytes)")
		}
	case strings.HasPrefix(line, szWarningsPrefix), strings.HasPrefix(line, szWarningsCount):
		s.anomalies = noteAnomaly(s.anomalies, "7z reported warnings")
	case strings.HasPrefix(line, szErrorsPrefix), strings.HasPrefix(line, szErrorsCount), strings.HasPrefix(line, szOpenErrorPrefix):
		s.anomalies = noteAnomaly(s.anomalies, "7z reported errors")
	}
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
		return err
	}
	if fp.IsDirectory {
		return nil
	}
	t.files++
	// A size the listing does not give (flux formats: gzip, bzip2) is unknown,
	// never small: it weighs the largest a member may be.
	size := int64(fp.Size)
	if fp.Size < 0 {
		size = s.maxFileSize
	}
	if size <= s.maxFileSize {
		t.totalSize += max(size, 0)
		t.totalCompressed += int64(max(fp.CompressedSize, 0))
	}
	if len(fp.Name) > maxMemberNameLen {
		s.anomalies = noteAnomaly(s.anomalies, fmt.Sprintf("a member name is longer than %d bytes", maxMemberNameLen))
		return nil
	}
	if strings.Count(fp.Name, "/") >= maxMemberDepth {
		// Not extracted: a path of that depth only serves to create folders.
		s.anomalies = noteAnomaly(s.anomalies, fmt.Sprintf("a member path has %d folders or more", maxMemberDepth))
		return nil
	}
	if hasControl(fp.Name) {
		s.anomalies = noteAnomaly(s.anomalies, "a member name contains a control character")
	}
	switch {
	case size > s.maxFileSize:
		t.skipped.add(fp.Name, int64(fp.Size), datamodel.NotAnalyzedTooBig)
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
