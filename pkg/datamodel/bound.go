package datamodel

import (
	"encoding/json"
	"sort"
	"strings"
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
	r.Filename = cutText(r.Filename, MaxListedNameLen)
	r.SHA256 = cutText(r.SHA256, MaxListedNameLen)
	r.QuarantineLocation = cutText(r.QuarantineLocation, MaxListedNameLen)
	r.MitigationID = cutText(r.MitigationID, MaxListedNameLen)
	r.GMalwareURL = cutText(r.GMalwareURL, MaxListedNameLen)
	r.MovedTo = cutText(r.MovedTo, MaxListedNameLen)
	r.MoveConflictOf = cutText(r.MoveConflictOf, MaxListedNameLen)
	r.FileType = cutText(r.FileType, MaxListedNameLen)
	r.Error = cutText(r.Error, MaxListedNameLen)
	r.Malwares = boundNames(r.Malwares, MaxReportMalwares)

	r.NotAnalyzedExtractedCount = max(r.NotAnalyzedExtractedCount, len(r.NotAnalyzedExtractedFiles))
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
		out[i] = cutText(names[i], MaxListedNameLen)
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
		out[i].FileName = cutText(out[i].FileName, MaxListedNameLen)
	}
	return out
}

// boundErrors returns the first MaxListedSubfiles entries by name, cut, in a new
// map.
func boundErrors(errs map[string]string) map[string]string {
	if len(errs) == 0 {
		return nil
	}
	keys := make([]string, 0, len(errs))
	for k := range errs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make(map[string]string, min(len(keys), MaxListedSubfiles))
	for _, k := range keys[:min(len(keys), MaxListedSubfiles)] {
		out[cutText(k, MaxListedNameLen)] = cutText(errs[k], MaxListedNameLen)
	}
	return out
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
		f.FileName = cutText(f.FileName, MaxListedNameLen)
		f.SHA256 = cutText(f.SHA256, MaxListedNameLen)
		f.GMalwareURL = cutText(f.GMalwareURL, MaxListedNameLen)
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
			n := len(r.ErrorExtractedFiles)
			r.ErrorExtractedFiles = shrinkErrors(r.ErrorExtractedFiles, keep)
			return len(r.ErrorExtractedFiles) < n
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
		r.Malwares, r.ErrorExtractedFiles, r.MaliciousExtractedFiles, r.NotAnalyzedExtractedFiles = nil, nil, nil, nil
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
	keys := make([]string, 0, len(errs))
	for k := range errs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	kept := make(map[string]string, len(keys))
	for _, k := range keys[:min(len(keys), int(float64(len(keys))*keep))] {
		kept[k] = errs[k]
	}
	return kept
}

func cutText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n-len(truncationMark)], "") + truncationMark
}
