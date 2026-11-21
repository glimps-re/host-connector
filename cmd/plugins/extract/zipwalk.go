package main

import (
	"bufio"
	"bytes"
	"compress/flate"
	"context"
	le "encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"slices"
	"time"
)

const (
	zipEOCDSignature       = 0x06054b50
	zip64LocatorSignature  = 0x07064b50
	zip64EOCDSignature     = 0x06064b50
	zipCentralSignature    = 0x02014b50
	zipLocalSignature      = 0x04034b50
	zipDescriptorSignature = 0x08074b50

	zipEOCDLen       = 22
	zipLocatorLen    = 20
	zip64EOCDLen     = 56
	zipCentralLen    = 46
	zipLocalLen      = 30
	zipMaxEOCDSearch = 1<<16 + zipEOCDLen

	zipFlagEncrypted  = 1
	zipFlagDescriptor = 1 << 3
	zipMethodStored   = 0
	zipMethodDeflate  = 8
	zipSaturated32    = 0xFFFFFFFF
	zipSaturated16    = 0xFFFF

	// zipHostFAT and the others are the hosts ("version made by", high byte) for
	// which 7-Zip reads a trailing backslash, or the attributes, as a folder.
	zipHostAmiga = 1
	zipHostFAT   = 0
	zipHostHPFS  = 6
	zipHostNTFS  = 11
	zipHostVFAT  = 14

	// maxEmptyDeflate is the most input read from a folder to find that its deflate
	// stream is empty: an empty stream is a few bytes.
	maxEmptyDeflate = 16
	// zipMaxLocalExtra is the largest extra field of a local header that carries
	// saturated sizes: a ZIP64 field holds 20 bytes, an honest header has no more
	// than a few.
	zipMaxLocalExtra = 64
	// zipWindow is the cache of the local headers: those of neighbours sit next to
	// each other, and a read per entry would cost seconds on a million of them.
	zipWindow = 8 << 10
	// zipMaxSigBlock bounds the APK Signing Block, and zipMaxSigPairs its pairs.
	zipMaxSigBlock = 1 << 20
	zipMaxSigPairs = 1 << 14
	// stampSize is the data of the source stamp that Google Play adds to a signed APK,
	// and stampMaxExtra the most extra field its local header may carry.
	stampSize     = 32
	stampMaxExtra = 8
	// zipCheckEvery is the number of entries between two checks of the deadline.
	zipCheckEvery = 1024
	// zipSigBlockMagic ends the APK Signing Block, kept between the last entry and
	// the central directory by the signing tools of Android.
	zipSigBlockMagic = "APK Sig Block 42"
)

// zipWalkDeadline bounds a walk: a zip whose walk is slower is hostile.
var zipWalkDeadline = 10 * time.Second

var (
	// errZipStructure says the headers of a zip are not what the listing of 7-Zip
	// says, or are not a plain succession of entries: the archive is an anomaly, not
	// a failure to retry.
	errZipStructure = errors.New("the zip headers do not match the listing")
	// errFolderData says a folder entry holds data in its local record.
	errFolderData = fmt.Errorf("%w: %s", errZipStructure, anomalyFolderData)
)

func zipAnomaly(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errZipStructure, fmt.Sprintf(format, args...))
}

// walkZipFolders walks the headers of the zip at path. 7-Zip lists the central
// directory, while unzip and the streaming readers read the local records one
// after the other: a record the directory does not list, or data behind a folder it
// shows empty, is seen by them and not by 7-Zip. entries and folders are the
// numbers of entries and of folder entries 7-Zip listed. The walk only adds
// refusals: nothing is decompressed beyond 16 bytes of a folder and no password is
// used. A name is only compared, ASCII case apart, with the name of the same entry in
// the other of the two places that hold it, and with the name of the stamp that
// Google Play adds to an APK. An error wrapping errZipStructure is an anomaly (the
// deadline of the walk included); any other is a failure to read, to retry.
func walkZipFolders(ctx context.Context, path string, entries, folders int) (found zipFindings, err error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return found, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	info, err := f.Stat()
	if err != nil {
		return found, err
	}
	return walkZip(ctx, f, info.Size(), entries, folders)
}

// zipFindings is what a walk that found no anomaly noticed besides.
type zipFindings struct {
	// controlNames says that a name holds a control character: 7-Zip lists it with
	// another name, so the names of its listing are not all the names of the zip.
	controlNames bool
}

type zipWalk struct {
	r       io.ReaderAt
	size    int64
	usize   uint64
	window  *windowReader
	name    []byte
	extra   []byte
	inflate io.ReadCloser
	// offsets are the local offsets of the entries of the directory, sorted once
	// the first pass is done.
	offsets []uint64
	cdOff   uint64
	cdSize  uint64
	total   uint64
	// controlNames is set when a name of the directory holds a control character.
	controlNames bool
	// scratch buffers, so that no entry allocates: a header is read into them.
	local    [zipLocalLen + zipSaturated16]byte
	desc     [24]byte
	extra64  [zipMaxLocalExtra]byte
	zeros    [32 << 10]byte
	unlisted [zipLocalLen]byte
	// stamped is set once the one source stamp allowed was seen.
	stamped bool
	// comment is the length of the comment of the entry last read.
	comment uint64
	// skipped is the number of records that skipUnlisted skipped on the walk that
	// holds: 7-Zip lists some of them as entries of their own.
	skipped uint64
}

// walkZip is walkZipFolders on a reader.
func walkZip(parent context.Context, r io.ReaderAt, size int64, entries, folders int) (zipFindings, error) {
	size = max(size, 0)
	w := &zipWalk{r: r, size: size, usize: uint64(size), window: &windowReader{r: r, buf: make([]byte, zipWindow)}}
	err := w.walk(parent, entries, folders)
	return zipFindings{controlNames: w.controlNames}, err
}

func (w *zipWalk) walk(parent context.Context, entries, folders int) error {
	ctx, cancel := context.WithTimeout(parent, zipWalkDeadline)
	defer cancel()
	if err := w.directory(); err != nil {
		return err
	}
	if entries < 0 || w.total > maxListed() {
		return zipAnomaly("%d entries in the directory, %d listed", w.total, entries)
	}
	w.name, w.extra = make([]byte, 0, zipSaturated16), make([]byte, 0, zipSaturated16)
	w.offsets = make([]uint64, 0, w.total)
	walked := 0
	err := w.eachCentral(ctx, func(e *centralEntry) error {
		w.offsets = append(w.offsets, e.localOffset)
		if e.folder {
			walked++
		}
		return nil
	})
	if err != nil {
		return w.verdict(parent, err)
	}
	if walked < folders {
		return zipAnomaly("%d folders in the directory, %d listed", walked, folders)
	}
	slices.Sort(w.offsets)
	for i := 1; i < len(w.offsets); i++ {
		if w.offsets[i] == w.offsets[i-1] {
			return zipAnomaly("two entries start at the same place")
		}
	}
	first := w.cdOff
	if len(w.offsets) > 0 {
		first = w.offsets[0]
	}
	pos, err := w.skipUnlisted(ctx, 0, first)
	if err != nil {
		return w.verdict(parent, err)
	}
	if pos != first {
		return zipAnomaly("data before the first entry")
	}
	stub := w.skipped > 0
	if err = w.eachCentral(ctx, func(e *centralEntry) error { return w.checkEntry(ctx, e) }); err != nil {
		return w.verdict(parent, err)
	}
	return w.listedAs(entries, stub)
}

// listedAs checks the count of entries that 7-Zip listed against what the walk
// found. With records before the first entry (what it calls a stub) it lists each
// record that the directory does not list as an entry of its own, those before the
// first entry, between entries and after the last included; without them it lists
// none (observed with 7-Zip 25.01). Any other difference is an anomaly: a listing
// that is not the directory.
func (w *zipWalk) listedAs(entries int, stub bool) error {
	want := w.total
	if stub {
		want += w.skipped
	}
	if entries < 0 || uint64(entries) != want {
		return zipAnomaly("%d entries in the directory and %d records it does not list, %d listed", w.total, w.skipped, entries)
	}
	return nil
}

// verdict turns the end of the deadline of the walk into an anomaly: the walk is
// slow because of the archive. The end of the context of the caller is not.
func (w *zipWalk) verdict(parent context.Context, err error) error {
	if errors.Is(err, context.DeadlineExceeded) && parent.Err() == nil {
		return zipAnomaly("the walk of the headers took more than %v", zipWalkDeadline)
	}
	return err
}

// structural turns a short read of the headers into an anomaly, and keeps any
// other failure.
func structural(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return zipAnomaly("headers cut short")
	}
	return err
}

// offset is v as an offset of the file: a value over the largest offset is
// capped, and then read as out of the file.
func offset(v uint64) int64 {
	if v > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(v)
}

// maxListed is the limit of listed entries, as an unsigned count.
func maxListed() uint64 {
	if maxListedEntries < 0 {
		return 0
	}
	return uint64(maxListedEntries)
}

func readAt(r io.ReaderAt, p []byte, off int64) error {
	if off < 0 {
		return zipAnomaly("offset out of the file")
	}
	n, err := r.ReadAt(p, off)
	if n == len(p) {
		return nil
	}
	if err == nil {
		err = io.ErrUnexpectedEOF
	}
	return structural(err)
}

// directory finds the end of the central directory, ZIP64 honoured, and keeps the
// number of entries and the place of the directory, checked to be in the file. The
// end of directory is the last record of the tail, and its comment must end exactly
// at the end of the file: a record after it, whose comment does not end the file, is
// a decoy placed there, and a second record whose comment also ends the file is a
// decoy hidden in the comment of the other. Readers do not agree on which they take,
// so both are anomalies. The end of directory of a zip stored in the zip (a fat jar)
// is data, followed by more data: it is not a candidate.
func (w *zipWalk) directory() error {
	tailLen := min(w.size, zipMaxEOCDSearch)
	if tailLen < zipEOCDLen {
		return zipAnomaly("no end of directory")
	}
	tail := make([]byte, tailLen)
	if err := readAt(w.r, tail, w.size-tailLen); err != nil {
		return err
	}
	// The end of directory is the last record of the tail, and its comment ends the
	// file: a signature after it is a decoy placed there (the comment of the decoy
	// ends one byte before the file does), and a second record whose comment ends
	// the file is a decoy in the comment. A zip stored in the zip has its own end of
	// directory before the real one, followed by more data: it is neither.
	at := -1
	for i := len(tail) - zipEOCDLen; i >= 0; i-- {
		if le.LittleEndian.Uint32(tail[i:]) != zipEOCDSignature {
			continue
		}
		exact := i+zipEOCDLen+int(le.LittleEndian.Uint16(tail[i+20:])) == len(tail)
		switch {
		case at < 0 && !exact:
			return zipAnomaly("a record that looks like an end of directory comes last, and its comment does not end the file")
		case at < 0:
			at = i
		case exact:
			return zipAnomaly("more than one end of directory")
		}
	}
	if at < 0 {
		return zipAnomaly("no end of directory")
	}
	e := tail[at:]
	if le.LittleEndian.Uint16(e[4:]) != 0 || le.LittleEndian.Uint16(e[6:]) != 0 {
		return zipAnomaly("a zip on several disks")
	}
	w.total, w.cdSize, w.cdOff = uint64(le.LittleEndian.Uint16(e[10:])), uint64(le.LittleEndian.Uint32(e[12:])), uint64(le.LittleEndian.Uint32(e[16:]))
	if w.total == zipSaturated16 || w.cdSize == zipSaturated32 || w.cdOff == zipSaturated32 {
		if err := w.zip64Directory(w.size - tailLen + int64(at)); err != nil {
			return err
		}
	}
	if w.cdOff > w.usize || w.cdSize > w.usize-w.cdOff {
		return zipAnomaly("the directory is out of the file")
	}
	return nil
}

func (w *zipWalk) zip64Directory(eocd int64) error {
	var loc [zipLocatorLen]byte
	if err := readAt(w.r, loc[:], eocd-zipLocatorLen); err != nil {
		return err
	}
	if le.LittleEndian.Uint32(loc[:]) != zip64LocatorSignature {
		return zipAnomaly("no ZIP64 locator")
	}
	off := le.LittleEndian.Uint64(loc[8:])
	if off > w.usize {
		return zipAnomaly("the ZIP64 record is out of the file")
	}
	var rec [zip64EOCDLen]byte
	if err := readAt(w.r, rec[:], offset(off)); err != nil {
		return err
	}
	if le.LittleEndian.Uint32(rec[:]) != zip64EOCDSignature {
		return zipAnomaly("no ZIP64 record")
	}
	w.total, w.cdSize, w.cdOff = le.LittleEndian.Uint64(rec[32:]), le.LittleEndian.Uint64(rec[40:]), le.LittleEndian.Uint64(rec[48:])
	return nil
}

// centralEntry is what the walk keeps of an entry of the directory.
type centralEntry struct {
	folder       bool
	flags        uint16
	method       uint16
	crc          uint32
	comp, uncomp uint64
	localOffset  uint64
}

// eachCentral reads the entries of the directory one after the other, and calls fn
// with each. The deadline is checked every zipCheckEvery entries. The entry given
// to fn is reused.
func (w *zipWalk) eachCentral(ctx context.Context, fn func(*centralEntry) error) error {
	br := bufio.NewReaderSize(io.NewSectionReader(w.r, offset(w.cdOff), offset(w.cdSize)), zipWindow)
	var hdr [zipCentralLen]byte
	var e centralEntry
	var used uint64
	for i := range w.total {
		if i%zipCheckEvery == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			return structural(err)
		}
		if err := w.central(br, hdr[:], &e); err != nil {
			return err
		}
		used += zipCentralLen + uint64(len(w.name)) + uint64(len(w.extra)) + w.comment
		if err := fn(&e); err != nil {
			return err
		}
	}
	if used != w.cdSize {
		return zipAnomaly("the entries fill %d bytes of a directory of %d", used, w.cdSize)
	}
	return nil
}

// central reads the entry whose fixed part is hdr, and the name, extra field and
// comment that follow it, into e.
func (w *zipWalk) central(br *bufio.Reader, hdr []byte, e *centralEntry) error {
	if le.LittleEndian.Uint32(hdr) != zipCentralSignature {
		return zipAnomaly("a bad entry in the directory")
	}
	madeBy := le.LittleEndian.Uint16(hdr[4:])
	e.flags, e.method = le.LittleEndian.Uint16(hdr[8:]), le.LittleEndian.Uint16(hdr[10:])
	e.crc = le.LittleEndian.Uint32(hdr[16:])
	e.comp, e.uncomp = uint64(le.LittleEndian.Uint32(hdr[20:])), uint64(le.LittleEndian.Uint32(hdr[24:]))
	nameLen, extraLen, commentLen := int(le.LittleEndian.Uint16(hdr[28:])), int(le.LittleEndian.Uint16(hdr[30:])), int(le.LittleEndian.Uint16(hdr[32:]))
	attrs := le.LittleEndian.Uint32(hdr[38:])
	e.localOffset = uint64(le.LittleEndian.Uint32(hdr[42:]))
	if nameLen == 0 {
		return zipAnomaly("an entry without a name")
	}
	w.name = w.name[:nameLen]
	if _, err := io.ReadFull(br, w.name); err != nil {
		return structural(err)
	}
	if hasControlBytes(w.name) {
		w.controlNames = true
	}
	e.folder = isFolderEntry(w.name, madeBy>>8, attrs)
	w.extra = w.extra[:extraLen]
	if _, err := io.ReadFull(br, w.extra); err != nil {
		return structural(err)
	}
	w.comment = uint64(le.LittleEndian.Uint16(hdr[32:]))
	if _, err := br.Discard(commentLen); err != nil {
		return structural(err)
	}
	if e.uncomp == zipSaturated32 || e.comp == zipSaturated32 || e.localOffset == zipSaturated32 {
		vals, ok := zip64Values(w.extra, e.uncomp == zipSaturated32, e.comp == zipSaturated32, e.localOffset == zipSaturated32)
		if !ok {
			return zipAnomaly("a ZIP64 entry without its extra field")
		}
		if e.uncomp == zipSaturated32 {
			e.uncomp = vals[0]
		}
		if e.comp == zipSaturated32 {
			e.comp = vals[1]
		}
		if e.localOffset == zipSaturated32 {
			e.localOffset = vals[2]
		}
	}
	return nil
}

// hasControlBytes tells whether a name holds a control character: 7-Zip prints it
// as an underscore in the listing of a zip and does not extract the member under
// the name it listed, so the name the listing gives is not the one a reader sees.
func hasControlBytes(name []byte) bool {
	return slices.ContainsFunc(name, func(b byte) bool { return b < 0x20 || b == 0x7f })
}

// isFolderEntry mirrors what 7-Zip takes for a folder (CItem::IsDir): a name that
// ends with a slash, the directory attribute, the Unix mode of a directory, and
// for the hosts that write paths with backslashes, a trailing backslash. The
// Amiga host sets a bit of its mode. A folder that this misses is caught by the
// count of folders against the listing of 7-Zip.
func isFolderEntry(name []byte, host uint16, attrs uint32) bool {
	last := name[len(name)-1]
	switch {
	case last == '/', attrs&0x10 != 0, (attrs>>16)&0xF000 == 0x4000:
		return true
	case last == '\\':
		return host == zipHostFAT || host == zipHostHPFS || host == zipHostNTFS || host == zipHostVFAT
	case host == zipHostAmiga:
		return (attrs>>16)&0o6000 == 0o4000
	}
	return false
}

// zip64Values reads, from the extra fields, the 64-bit values of the sizes and the
// offset that the 32-bit field saturates, in the order the format gives them.
func zip64Values(extra []byte, uncomp, comp, offset bool) (vals [3]uint64, ok bool) {
	for len(extra) >= 4 {
		id, size := le.LittleEndian.Uint16(extra), int(le.LittleEndian.Uint16(extra[2:]))
		if 4+size > len(extra) {
			return vals, false
		}
		if id != 1 {
			extra = extra[4+size:]
			continue
		}
		data := extra[4 : 4+size]
		for i, wanted := range [3]bool{uncomp, comp, offset} {
			if !wanted {
				continue
			}
			if len(data) < 8 {
				return vals, false
			}
			vals[i], data = le.LittleEndian.Uint64(data), data[8:]
		}
		return vals, true
	}
	return vals, false
}

// checkEntry checks the local record of an entry: it is where the offsets say, it
// is followed by the next record or by the directory and nothing else, and a
// folder holds nothing.
func (w *zipWalk) checkEntry(ctx context.Context, e *centralEntry) error {
	if e.localOffset > w.usize || w.usize-e.localOffset < zipLocalLen {
		return zipAnomaly("a local header is out of the file")
	}
	// The header and the name that the directory gives are read at once: for a
	// directory in another order than the file each read is a miss of the cache.
	record := w.local[:zipLocalLen+len(w.name)]
	if err := readAt(w.window, record, offset(e.localOffset)); err != nil {
		return err
	}
	hdr := record[:zipLocalLen]
	if le.LittleEndian.Uint32(hdr) != zipLocalSignature {
		return zipAnomaly("a bad local header")
	}
	flags, method := le.LittleEndian.Uint16(hdr[6:]), le.LittleEndian.Uint16(hdr[8:])
	comp, uncomp := uint64(le.LittleEndian.Uint32(hdr[18:])), uint64(le.LittleEndian.Uint32(hdr[22:]))
	nameLen, extraLen := uint64(le.LittleEndian.Uint16(hdr[26:])), uint64(le.LittleEndian.Uint16(hdr[28:]))
	extraAt := e.localOffset + zipLocalLen + nameLen
	dataAt := extraAt + extraLen
	if dataAt > w.usize {
		return zipAnomaly("a local header is out of the file")
	}
	if nameLen != uint64(len(w.name)) || !equalFoldASCII(record[zipLocalLen:], w.name) {
		return zipAnomaly("the name of a local header is not the one of the directory")
	}
	if method != e.method || flags&zipFlagEncrypted != e.flags&zipFlagEncrypted {
		return zipAnomaly("the method or the encryption of a local header is not the one of the directory")
	}
	descriptor := flags&zipFlagDescriptor != 0
	if (!descriptor || e.folder) && (comp == zipSaturated32 || uncomp == zipSaturated32) {
		var err error
		if comp, uncomp, err = w.localZip64(extraAt, extraLen, comp, uncomp); err != nil {
			return err
		}
	}
	if !descriptor && (comp != e.comp || uncomp != e.uncomp) {
		return zipAnomaly("the sizes of a local header are not the ones of the directory")
	}
	end := dataAt + e.comp
	if end < dataAt || end > w.usize {
		return zipAnomaly("an entry ends out of the file")
	}
	ends := [4]uint64{end}
	n := 1
	if descriptor {
		var err error
		if n, err = w.afterDescriptor(&ends, end, e); err != nil {
			return err
		}
		if n == 0 {
			return zipAnomaly("a data descriptor that is not the one of the directory")
		}
	}
	if err := w.contiguous(ctx, e.localOffset, ends[:n]); err != nil {
		return err
	}
	if !e.folder {
		return nil
	}
	return w.checkFolder(e, flags, method, comp, uncomp, dataAt)
}

// localZip64 reads the sizes a local header saturates from its extra field. Only
// its first zipMaxLocalExtra bytes are read: the ZIP64 field comes first, and what
// follows it (alignment padding of an APK, times) is of no use here.
func (w *zipWalk) localZip64(at, length, comp, uncomp uint64) (uint64, uint64, error) {
	extra := w.extra64[:min(length, zipMaxLocalExtra)]
	if err := readAt(w.window, extra, offset(at)); err != nil {
		return 0, 0, err
	}
	vals, ok := zip64Values(extra, uncomp == zipSaturated32, comp == zipSaturated32, false)
	if !ok {
		return 0, 0, zipAnomaly("a ZIP64 local header without its extra field in its first %d bytes", zipMaxLocalExtra)
	}
	if uncomp == zipSaturated32 {
		uncomp = vals[0]
	}
	if comp == zipSaturated32 {
		comp = vals[1]
	}
	return comp, uncomp, nil
}

// afterDescriptor gives, in ends, where an entry flagged with a data descriptor
// can end: the descriptor follows its data, and is 12, 16, 20 or 24 bytes (with or
// without the signature, with sizes of 4 or 8 bytes). Each form whose fields are
// the ones of the directory is a candidate, since a descriptor of 8-byte sizes read
// as one of 4 matches too when the sizes are small. It returns their number, 0 when
// there is none; a failure to read is an error, not an anomaly.
func (w *zipWalk) afterDescriptor(ends *[4]uint64, end uint64, e *centralEntry) (int, error) {
	buf := &w.desc
	n, err := w.r.ReadAt(buf[:], offset(end))
	if err != nil && !errors.Is(err, io.EOF) {
		return 0, err
	}
	got := buf[:n]
	count := 0
	for _, sig := range [2]bool{true, false} {
		body := got
		head := 0
		if sig {
			if len(body) < 4 || le.LittleEndian.Uint32(body) != zipDescriptorSignature {
				continue
			}
			body, head = body[4:], 4
		}
		for _, wide := range [2]bool{false, true} {
			size := 12
			if wide {
				size = 20
			}
			if len(body) < size || le.LittleEndian.Uint32(body) != e.crc {
				continue
			}
			var c, u uint64
			if wide {
				c, u = le.LittleEndian.Uint64(body[4:]), le.LittleEndian.Uint64(body[12:])
			} else {
				c, u = uint64(le.LittleEndian.Uint32(body[4:])), uint64(le.LittleEndian.Uint32(body[8:]))
			}
			if c == e.comp && u == e.uncomp {
				ends[count] = end + uint64(head+size)
				count++
			}
		}
	}
	return count, nil
}

// contiguous requires that the record that starts at start and ends at one of ends is
// followed by the next record, or, for the last one, by the directory: a gap is
// room for a record that the directory does not list. The signing block of an APK
// is the one thing allowed between the last record and the directory.
func (w *zipWalk) contiguous(ctx context.Context, start uint64, ends []uint64) error {
	i, found := slices.BinarySearch(w.offsets, start)
	if !found {
		return zipAnomaly("an entry is not where the directory says")
	}
	last := i+1 == len(w.offsets)
	next := w.cdOff
	if !last {
		next = w.offsets[i+1]
	}
	for _, end := range ends {
		if end > next {
			continue
		}
		skipped, stamped := w.skipped, w.stamped
		end, err := w.skipUnlisted(ctx, end, next)
		if err != nil {
			return err
		}
		if end == next {
			return nil
		}
		// A gap of zeros holds no record: a record starts with a signature, and a
		// reader stops at zeros.
		if last {
			ok, err := w.signingBlock(ctx, end)
			if err != nil {
				return err
			}
			if ok {
				return nil
			}
		}
		zeros, err := w.onlyZeros(ctx, end, next)
		if err != nil {
			return err
		}
		if zeros {
			return nil
		}
		w.skipped, w.stamped = skipped, stamped
	}
	return zipAnomaly("unused space after an entry")
}

// onlyZeros tells whether the bytes from from to to are all zeros. They are read
// in a block of a fixed size, within the deadline of the walk.
func (w *zipWalk) onlyZeros(ctx context.Context, from, to uint64) (bool, error) {
	for from < to {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		chunk := w.zeros[:min(uint64(len(w.zeros)), to-from)]
		if err := readAt(w.r, chunk, offset(from)); err != nil {
			return false, ioOnly(err)
		}
		for _, b := range chunk {
			if b != 0 {
				return false, nil
			}
		}
		from += uint64(len(chunk))
	}
	return true, nil
}

// signingBlock tells whether the space between end and the directory is zeros and
// then one APK Signing Block that ends at the directory: [size][pairs][size][magic],
// the sizes equal and the block at most zipMaxSigBlock, the first dword not a
// signature of a zip record, the pairs ([length][id][value]) filling the block with
// nothing left over, and no local signature inside. A failure to read is an error.
func (w *zipWalk) signingBlock(ctx context.Context, end uint64) (bool, error) {
	if w.cdOff < end+32 {
		return false, nil
	}
	var tail [24]byte
	if err := readAt(w.r, tail[:], offset(w.cdOff-24)); err != nil {
		return false, ioOnly(err)
	}
	size := le.LittleEndian.Uint64(tail[:8])
	if string(tail[8:]) != zipSigBlockMagic || size < 24 || size > zipMaxSigBlock || size+8 > w.cdOff-end {
		return false, nil
	}
	start := w.cdOff - size - 8
	var head [8]byte
	if err := readAt(w.r, head[:], offset(start)); err != nil {
		return false, ioOnly(err)
	}
	if le.LittleEndian.Uint64(head[:]) != size || isZipSignature(le.LittleEndian.Uint32(head[:])) {
		return false, nil
	}
	zeros, err := w.onlyZeros(ctx, end, start)
	if err != nil || !zeros {
		return false, err
	}
	// Each pair ends inside the block, so that the chain ends exactly at its end.
	pos, stop := start+8, w.cdOff-24
	for count := 0; pos < stop; count++ {
		var pair [12]byte
		if count >= zipMaxSigPairs || stop-pos < uint64(len(pair)) {
			return false, nil
		}
		if err := readAt(w.r, pair[:], offset(pos)); err != nil {
			return false, ioOnly(err)
		}
		length := le.LittleEndian.Uint64(pair[:8])
		if length < 4 || length > stop-pos-8 {
			return false, nil
		}
		pos += 8 + length
	}
	return w.noLocalSignature(ctx, start, w.cdOff)
}

// noLocalSignature tells whether the bytes from from to to hold no signature of a
// local record, read in a block of a fixed size.
func (w *zipWalk) noLocalSignature(ctx context.Context, from, to uint64) (bool, error) {
	signature := le.LittleEndian.AppendUint32(nil, zipLocalSignature)
	carry := 0
	for from < to {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		room := w.zeros[carry:]
		chunk := room[:min(uint64(len(room)), to-from)]
		if err := readAt(w.r, chunk, offset(from)); err != nil {
			return false, ioOnly(err)
		}
		window := w.zeros[:carry+len(chunk)]
		if bytes.Contains(window, signature) {
			return false, nil
		}
		from += uint64(len(chunk))
		carry = min(len(signature)-1, len(window))
		copy(w.zeros[:carry], window[len(window)-carry:])
	}
	return true, nil
}

// ioOnly keeps an error of reading and drops a short read: a block cut short by
// the end of the file is not a block, not a failure of the medium.
func ioOnly(err error) error {
	if errors.Is(err, errZipStructure) {
		return nil
	}
	return err
}

// isZipSignature tells whether a dword is the signature of a record of a zip.
func isZipSignature(v uint32) bool {
	switch v {
	case zipLocalSignature, zipCentralSignature, zipEOCDSignature, zip64EOCDSignature, zip64LocatorSignature, zipDescriptorSignature:
		return true
	}
	return false
}

// checkFolder checks that a folder entry holds nothing: stored with no byte, or a
// deflate stream that ends within 16 bytes with no output and fills what the
// directory gives it (the sizes the headers declare do not count: a reader that
// inflates to the end of the stream does not read them). Another method is an
// anomaly.
func (w *zipWalk) checkFolder(e *centralEntry, flags, method uint16, comp, uncomp, dataAt uint64) error {
	if flags&zipFlagEncrypted != 0 || method != e.method {
		return errFolderData
	}
	switch method {
	case zipMethodStored:
		if flags&zipFlagDescriptor == 0 && comp == 0 && uncomp == 0 && e.comp == 0 && e.uncomp == 0 {
			return nil
		}
	case zipMethodDeflate:
		if e.uncomp != 0 || e.comp > maxEmptyDeflate || (flags&zipFlagDescriptor == 0 && (comp != e.comp || uncomp != 0)) {
			return errFolderData
		}
		ok, err := w.emptyDeflateStream(dataAt, e.comp)
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
	}
	return errFolderData
}

// emptyDeflateStream tells whether the deflate stream at off, of the length the
// directory gives, ends with no output and uses all of it.
func (w *zipWalk) emptyDeflateStream(off, length uint64) (bool, error) {
	var buf [maxEmptyDeflate]byte
	n, err := w.r.ReadAt(buf[:min(length, maxEmptyDeflate)], offset(off))
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	return w.endsEmpty(buf[:n])
}

// endsEmpty tells whether data is exactly one deflate stream, with no output.
func (w *zipWalk) endsEmpty(data []byte) (bool, error) {
	src := bytes.NewReader(data)
	if w.inflate == nil {
		w.inflate = flate.NewReader(src)
	} else {
		resetter, ok := w.inflate.(flate.Resetter)
		if !ok {
			return false, errors.New("the deflate reader cannot be reused")
		}
		if err := resetter.Reset(src, nil); err != nil {
			return false, err
		}
	}
	var out [1]byte
	ended := false
	for range maxEmptyDeflate + 1 {
		got, err := w.inflate.Read(out[:])
		if got > 0 {
			break
		}
		if err != nil {
			ended = errors.Is(err, io.EOF)
			break
		}
	}
	return ended && src.Len() == 0, nil
}

// windowReader serves the reads that fall in the last block it read, so that
// local headers that sit next to each other cost one read. A read that does not
// follow the last block (the directory lists the entries in another order than the
// file does) reads what it needs and no more: a whole block per header would make a
// million of them a gigabytes of copying.
type windowReader struct {
	r    io.ReaderAt
	buf  []byte
	off  int64
	n    int
	next int64 // where the last read ended
}

func (w *windowReader) ReadAt(p []byte, off int64) (int, error) {
	if off >= w.off && off-w.off+int64(len(p)) <= int64(w.n) {
		w.next = off + int64(len(p))
		return copy(p, w.buf[off-w.off:w.n]), nil
	}
	forward := off >= w.next && off-w.next < int64(len(w.buf))
	if len(p) > len(w.buf) || !forward {
		w.next = off + int64(len(p))
		return w.r.ReadAt(p, off)
	}
	n, err := w.r.ReadAt(w.buf, off)
	w.off, w.n = off, n
	w.next = off + int64(n)
	if n < len(p) {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return copy(p, w.buf[:n]), err
	}
	return copy(p, w.buf[:len(p)]), nil
}

// equalFoldASCII compares two names with the ASCII letters folded and nothing else:
// Office writes customXML locally and customXml in the directory, while a folding of
// all Unicode would open look-alike mismatches.
func equalFoldASCII(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] && lowerASCII(a[i]) != lowerASCII(b[i]) {
			return false
		}
	}
	return true
}

func lowerASCII(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + 'a' - 'A'
	}
	return b
}

// stampName is the name of the record that Google Play adds to a signed APK.
const stampName = "stamp-cert-sha256"

// skipUnlisted skips, from from, the local records that the directory does not list
// and that carry nothing: a record that signing tools leave (stored, sizes 0, no
// descriptor, no encryption, a name and an extra field of any length, made of zero
// bytes), and at most one source stamp of Google Play (the name stampName, stored,
// 32 bytes, an extra field of at most 8 bytes). Only the name of the stamp is read:
// its 32 bytes and its extra field are not inspected, which leaves 40 bytes of
// room, the price of accepting honest APKs. It returns where the next byte that is
// not such a record is, never past to, and counts the records it skipped in
// w.skipped. Each record is read in full, within the deadline.
func (w *zipWalk) skipUnlisted(ctx context.Context, from, to uint64) (uint64, error) {
	pos := from
	for pos < to && to-pos >= zipLocalLen {
		if err := ctx.Err(); err != nil {
			return pos, err
		}
		hdr := w.unlisted[:]
		if err := readAt(w.window, hdr, offset(pos)); err != nil {
			return pos, ioOnly(err)
		}
		if le.LittleEndian.Uint32(hdr) != zipLocalSignature {
			return pos, nil
		}
		flags, method := le.LittleEndian.Uint16(hdr[6:]), le.LittleEndian.Uint16(hdr[8:])
		comp, uncomp := le.LittleEndian.Uint32(hdr[18:]), le.LittleEndian.Uint32(hdr[22:])
		nameLen, extraLen := uint64(le.LittleEndian.Uint16(hdr[26:])), uint64(le.LittleEndian.Uint16(hdr[28:]))
		if flags&(zipFlagEncrypted|zipFlagDescriptor) != 0 || method != zipMethodStored || comp != uncomp {
			return pos, nil
		}
		body := pos + zipLocalLen
		var end uint64
		switch {
		case comp == 0:
			end = body + nameLen + extraLen
			if end > to {
				return pos, nil
			}
			zeros, err := w.onlyZeros(ctx, body, end)
			if err != nil || !zeros {
				return pos, err
			}
		case comp == stampSize && nameLen == uint64(len(stampName)) && extraLen <= stampMaxExtra && !w.stamped:
			end = body + nameLen + extraLen + stampSize
			if end > to {
				return pos, nil
			}
			var got [len(stampName)]byte
			if err := readAt(w.window, got[:], offset(body)); err != nil {
				return pos, ioOnly(err)
			}
			if string(got[:]) != stampName {
				return pos, nil
			}
			w.stamped = true
		default:
			return pos, nil
		}
		w.skipped++
		pos = end
	}
	return pos, nil
}
