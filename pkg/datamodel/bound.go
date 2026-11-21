package datamodel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	// MaxReportSize bounds the JSON encoding of a Report, whatever the archive
	// it describes holds.
	MaxReportSize = 4 << 20
	// MaxReportMalwares bounds the malware names of a report.
	MaxReportMalwares = 64
	// MaxReportMaliciousFiles bounds the malicious extracted files of a report,
	// all levels together.
	MaxReportMaliciousFiles = MaxListedSubfiles
	// MaxReportNodeMalwares bounds the malware names of the malicious extracted
	// files, all of them together.
	MaxReportNodeMalwares = 4 * MaxReportMalwares

	// truncationMark ends a text that was cut.
	truncationMark = "…[truncated]"
	// shrinkRounds bounds the measurements made to fit a report.
	shrinkRounds = 24
	// shrinkSlack is kept under the limit by each cut, so that one is enough.
	shrinkSlack = 0.9
)

// Bound makes the report fit its limits, without touching what the caller
// shares with it. Every list is cut to its maximum (the counter of the files not
// analyzed keeps the exact number), every text to MaxListedNameLen bytes, the
// malware names to a budget across the whole report. If the encoding is still
// over MaxReportSize, the content is cut in this order: the names of the
// malwares, the files in error, the malicious files, and last the files not
// analyzed, which attest what passed without analysis.
func (r *Report) Bound() {
	r.Filename = CutText(r.Filename, MaxListedNameLen)
	r.SHA256 = CutText(r.SHA256, MaxListedNameLen)
	r.QuarantineLocation = CutText(r.QuarantineLocation, MaxListedNameLen)
	r.MitigationID = CutText(r.MitigationID, MaxListedNameLen)
	r.GMalwareURL = CutText(r.GMalwareURL, MaxListedNameLen)
	r.MovedTo = CutText(r.MovedTo, MaxListedNameLen)
	r.MoveConflictOf = CutText(r.MoveConflictOf, MaxListedNameLen)
	r.FileType = CutText(r.FileType, MaxListedNameLen)
	r.Error = CutText(r.Error, MaxListedNameLen)
	r.Malwares = boundNames(r.Malwares, MaxReportMalwares)

	r.NotAnalyzedExtractedCount = min(max(r.NotAnalyzedExtractedCount, len(r.NotAnalyzedExtractedFiles)), MaxFileCount)
	r.NotAnalyzedExtractedFiles = boundNotAnalyzed(r.NotAnalyzedExtractedFiles)
	r.ErrorExtractedFiles = boundErrors(r.ErrorExtractedFiles)
	fileBudget, nameBudget := MaxReportMaliciousFiles, MaxReportNodeMalwares
	r.MaliciousExtractedFiles = boundExtracted(r.MaliciousExtractedFiles, &fileBudget, &nameBudget)

	if r.encodedSize() > MaxReportSize {
		r.shrinkToFit()
	}
}

// boundNames returns at most limit names of at most MaxListedNameLen bytes, in a
// new slice.
func boundNames(names []string, limit int) []string {
	if len(names) == 0 || limit <= 0 {
		return nil
	}
	out := make([]string, min(len(names), limit))
	for i := range out {
		out[i] = CutText(names[i], MaxListedNameLen)
	}
	return out
}

func boundNotAnalyzed(list []NotAnalyzedFile) []NotAnalyzedFile {
	if len(list) == 0 {
		return nil
	}
	out := make([]NotAnalyzedFile, min(len(list), MaxListedSubfiles))
	copy(out, list)
	for i := range out {
		out[i].FileName = CutText(out[i].FileName, MaxListedNameLen)
	}
	return out
}

// MaxFileCount bounds every count of files a report carries, whoever wrote it: a
// plugin can set the count of the files not analyzed, or the value of
// MoreErrorsKey. It fits an int of 32 bits, but two of them do not (their sum is
// 2^31, one more than the largest int32): two counts are added with AddCount,
// never with +. A count is exact only below it.
const MaxFileCount = 1 << 30

// clampCount brings a count into [0, MaxFileCount].
func clampCount(n int) int {
	return min(max(n, 0), MaxFileCount)
}

// AddCount is the sum of two counts of files, each between 0 and MaxFileCount (a
// count out of that range is brought back into it), and at most MaxFileCount: it
// stops there instead of wrapping around, whatever the size of an int.
func AddCount(a, b int) int {
	a, b = clampCount(a), clampCount(b)
	if a >= MaxFileCount-b {
		return MaxFileCount
	}
	return a + b
}

// MoreErrorsText is the value of MoreErrorsKey for n failed files not listed: n,
// in decimal digits (n is kept between 0 and MaxFileCount), then a text.
// ParseMoreErrors reads it back.
func MoreErrorsText(n int) string {
	return strconv.Itoa(clampCount(n)) + " more failed file(s) not listed"
}

// ParseMoreErrors is the count in a value made by MoreErrorsText: decimal digits
// (ASCII only, leading zeros allowed) then a space and anything. A value that does
// not have that shape has no count (0), and a count over MaxFileCount, however
// many digits it has, is read as MaxFileCount. ParseMoreErrors(MoreErrorsText(n))
// is n for n up to MaxFileCount. It does not depend on the size of an int: the
// digits are read as 64 bits.
func ParseMoreErrors(value string) int {
	digits, _, found := strings.Cut(value, " ")
	if !found || digits == "" {
		return 0
	}
	for _, c := range digits {
		if c < '0' || c > '9' {
			return 0
		}
	}
	n, err := strconv.ParseUint(digits, 10, 64)
	if errors.Is(err, strconv.ErrRange) || n > MaxFileCount {
		return MaxFileCount
	}
	if err != nil {
		return 0
	}
	return int(n)
}

// orderedErrorKeys is the keys of errs but MoreErrorsKey, sorted.
func orderedErrorKeys(errs map[string]string) []string {
	keys := make([]string, 0, len(errs))
	for k := range errs {
		if k != MoreErrorsKey {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

// addMoreErrors sets in out, which it changes, the sentinel of the failed files
// not listed: the count src holds plus dropped, the number of entries the caller
// left out, whether src had the sentinel or not; and nothing when there is
// neither. The entries listed and the count are then the number of failed files,
// whatever the cuts.
func addMoreErrors(out, src map[string]string, dropped int) {
	more, had := src[MoreErrorsKey]
	if !had && dropped == 0 {
		return
	}
	out[MoreErrorsKey] = MoreErrorsText(AddCount(ParseMoreErrors(more), dropped))
}

// failureCount is the number of failed files a map of errors stands for: the
// entries listed and the count of those not listed.
func failureCount(errs map[string]string) int {
	return AddCount(ListedErrors(errs), ParseMoreErrors(errs[MoreErrorsKey]))
}

// boundErrors returns the first MaxListedSubfiles entries by name, in a new map,
// and the sentinel MoreErrorsKey, one more, when there is one or when entries are
// left out: what is left out is added to its count. A map made by the scanner,
// which caps the entries the same way, goes through unchanged. The names are cut
// to MaxListedNameLen bytes, and stay distinct once cut: two names that share
// their first bytes would otherwise be one entry, and an error line and a failed
// file of the count would be lost.
func boundErrors(errs map[string]string) map[string]string {
	if len(errs) == 0 {
		return nil
	}
	keys := orderedErrorKeys(errs)
	kept := min(len(keys), MaxListedSubfiles)
	out := make(map[string]string, kept+1)
	resume := map[string]int{}
	for _, k := range keys[:kept] {
		out[UniqueKey(k, out, resume)] = CutText(errs[k], MaxListedNameLen)
	}
	addMoreErrors(out, errs, len(keys)-kept)
	return out
}

// MoreErrorsKey is the key, in a map of failed files, of the count of those that
// are not listed.
const MoreErrorsKey = "…[more failed files]"

const (
	// keyHashBytes is the length of the hash of a cut key, which tells apart two
	// names that share their beginning; 64 bits make a collision on purpose a
	// matter of 2^32 attempts, and the counter below covers it anyway.
	keyHashBytes = 8
	// keyHashLen is what the hash adds to a key: "-" and its hex digits.
	keyHashLen = 1 + 2*keyHashBytes
	// counterMark introduces the counter that tells apart keys that are still
	// the same.
	counterMark = "~"
)

// countDigits is the room kept for the counter of a key: a counter goes up to the
// number of keys of a map, which is at most MaxListedSubfiles + 1 (the keys and
// the sentinel), so it has len("1001") digits.
const countDigits = 4

// maxCounter is the largest counter that fits the room kept for it.
const maxCounter = 9999

// maxCounterTries bounds the counters tried for one name. A map holds at most
// MaxListedSubfiles + 1 keys, so among that many counters, plus one, one is free.
const maxCounterTries = MaxListedSubfiles + 2

// uniqueKey is UniqueKey with the keys already taken given as a test.
func uniqueKey(name string, taken func(string) bool, resume map[string]int) string {
	valid := utf8.ValidString(name)
	if valid && len(name) <= MaxListedNameLen && name != MoreErrorsKey && !taken(name) {
		return name
	}
	// A name that is not UTF-8 is written by encoding/json with U+FFFD in place of
	// its invalid bytes: two names that differ only there would become the same
	// key of a JSON object. It is kept readable, with the replacement made here,
	// and told apart by the hash of its raw bytes.
	readable := name
	if !valid {
		readable = strings.ToValidUTF8(name, string(utf8.RuneError))
	}
	sum := sha256.Sum256([]byte(name))
	base := CutText(readable, MaxListedNameLen-keyHashLen-len(counterMark)-countDigits) + "-" + hex.EncodeToString(sum[:keyHashBytes])
	if !taken(base) {
		return base
	}
	n := 2
	if resume != nil {
		n = max(resume[base], 2)
	}
	for range maxCounterTries {
		key := base + counterMark + strconv.Itoa(n)
		if !taken(key) {
			if resume != nil {
				resume[base] = n + 1
			}
			return key
		}
		n++
	}
	n = min(n, maxCounter)
	if resume != nil {
		resume[base] = n
	}
	return base + counterMark + strconv.Itoa(n)
}

// UniqueKey is the key under which a failed file is listed, so that no two share
// one. It is the name itself when that is valid UTF-8, at most MaxListedNameLen
// bytes, not MoreErrorsKey and not in taken. Otherwise it is the readable
// beginning of the name (invalid bytes become U+FFFD), "-", a hash of the whole
// name, and, if that is taken too (a collision someone searched for), "~" and a
// counter: it always is valid UTF-8 and at most MaxListedNameLen bytes. taken is
// the map of the keys given so far, at most MaxListedSubfiles + 1 of them; the
// key is not added to it. resume, if not nil, remembers the next counter of each
// base, so that many names forced onto one key cost one step each and not one
// pass over the ones before. The search for a free counter stops after
// maxCounterTries steps: past it, which only happens if taken holds more keys
// than allowed, the next counter is returned without being checked, so the key is
// valid and within the limit but not guaranteed unique.
func UniqueKey(name string, taken map[string]string, resume map[string]int) string {
	return uniqueKey(name, func(key string) bool { _, used := taken[key]; return used }, resume)
}

// boundExtracted returns the malicious files sorted by name and cut to the
// budgets of files and of malware names left, for the whole tree. The caller's
// slice is not changed.
func boundExtracted(files []ExtractedFile, fileBudget, nameBudget *int) []ExtractedFile {
	if len(files) == 0 || *fileBudget <= 0 {
		return nil
	}
	sorted := make([]ExtractedFile, len(files))
	copy(sorted, files)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].FileName < sorted[j].FileName })
	sorted = sorted[:min(len(sorted), *fileBudget)]
	*fileBudget -= len(sorted)
	for i := range sorted {
		f := &sorted[i]
		f.FileName = CutText(f.FileName, MaxListedNameLen)
		f.SHA256 = CutText(f.SHA256, MaxListedNameLen)
		f.GMalwareURL = CutText(f.GMalwareURL, MaxListedNameLen)
		f.Malwares = boundNames(f.Malwares, min(MaxReportMalwares, max(*nameBudget, 0)))
		*nameBudget -= len(f.Malwares)
		f.ExtractedFiles = boundExtracted(f.ExtractedFiles, fileBudget, nameBudget)
	}
	return sorted
}

// countingWriter counts what is written to it and keeps none of it.
type countingWriter struct{ n int }

func (w *countingWriter) Write(p []byte) (int, error) {
	w.n += len(p)
	return len(p), nil
}

// encodedSize is the size of the JSON encoding of r; an encoding that fails
// counts as over the limit. Nothing is kept, but json.Encoder builds the whole
// encoding before writing it: the memory used is that of the report, which the
// caps applied before keep to a few tens of MiB at worst.
func (r *Report) encodedSize() int {
	var w countingWriter
	if err := json.NewEncoder(&w).Encode(r); err != nil {
		return MaxReportSize + 1
	}
	return w.n
}

// shrinkToFit cuts the content, one kind after the other, in proportion to what
// is over the limit, until the encoding fits.
func (r *Report) shrinkToFit() {
	stages := []func(keep float64) bool{
		func(keep float64) bool { return shrinkNodeNames(r.MaliciousExtractedFiles, keep) },
		func(keep float64) bool {
			n := len(r.Malwares)
			r.Malwares = r.Malwares[:min(n, max(int(float64(n)*keep), 1))]
			return len(r.Malwares) < n
		},
		func(keep float64) bool {
			n := ListedErrors(r.ErrorExtractedFiles)
			r.ErrorExtractedFiles = shrinkErrors(r.ErrorExtractedFiles, keep)
			return ListedErrors(r.ErrorExtractedFiles) < n
		},
		func(keep float64) bool {
			n := len(r.MaliciousExtractedFiles)
			r.MaliciousExtractedFiles = r.MaliciousExtractedFiles[:int(float64(n)*keep)]
			return len(r.MaliciousExtractedFiles) < n
		},
		func(keep float64) bool {
			n := len(r.NotAnalyzedExtractedFiles)
			r.NotAnalyzedExtractedFiles = r.NotAnalyzedExtractedFiles[:int(float64(n)*keep)]
			return len(r.NotAnalyzedExtractedFiles) < n
		},
	}
	for range shrinkRounds {
		size := r.encodedSize()
		if size <= MaxReportSize {
			return
		}
		keep := float64(MaxReportSize) / float64(size) * shrinkSlack
		for _, stage := range stages {
			if stage(keep) {
				break
			}
		}
	}
	if r.encodedSize() > MaxReportSize {
		total := failureCount(r.ErrorExtractedFiles)
		r.Malwares, r.ErrorExtractedFiles, r.MaliciousExtractedFiles, r.NotAnalyzedExtractedFiles = nil, nil, nil, nil
		if total > 0 {
			r.ErrorExtractedFiles = map[string]string{MoreErrorsKey: MoreErrorsText(total)}
		}
	}
}

// shrinkNodeNames keeps the first part of the malware names of every node, and
// tells whether it removed any.
func shrinkNodeNames(files []ExtractedFile, keep float64) (changed bool) {
	for i := range files {
		f := &files[i]
		n := len(f.Malwares)
		f.Malwares = f.Malwares[:int(float64(n)*keep)]
		changed = changed || len(f.Malwares) < n
		if shrinkNodeNames(f.ExtractedFiles, keep) {
			changed = true
		}
	}
	return changed
}

// shrinkErrors keeps the first entries by name.
func shrinkErrors(errs map[string]string, keep float64) map[string]string {
	if len(errs) == 0 {
		return errs
	}
	keys := orderedErrorKeys(errs)
	kept := min(len(keys), int(float64(len(keys))*keep))
	out := make(map[string]string, kept+1)
	for _, k := range keys[:kept] {
		out[k] = errs[k]
	}
	addMoreErrors(out, errs, len(keys)-kept)
	return out
}

// ListedErrors is the number of entries of errs that are failed files: all but
// the sentinel MoreErrorsKey.
func ListedErrors(errs map[string]string) int {
	if _, ok := errs[MoreErrorsKey]; ok {
		return len(errs) - 1
	}
	return len(errs)
}

// CutText shortens s to at most n bytes, except that the result is never shorter
// than the mark that tells it was cut, and without splitting a character. A text
// that fits is returned as it is.
func CutText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:max(n-len(truncationMark), 0)], "") + truncationMark
}
