//go:build linux

package harness

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	hcquarantine "github.com/glimps-re/host-connector/pkg/quarantine"
	"github.com/glimps-re/host-connector/test/internal/fakes/gmalware"
)

// maxReportSize bounds the report the checker reads; a larger one is a
// violation, not a truncated read that hides what follows.
const maxReportSize = 64 << 20

// Expectations are what a scenario declares to the checker: the not-analyzed
// reasons it expects (empty and too-big need no declaration, they are checked
// against the file), the largest file the analysis accepts, and the members of
// the archives it delivers. The sizes the checker holds a member to are the ones
// the report declares for it.
type Expectations struct {
	maxFileSize int64
	reasons     map[datamodel.NotAnalyzedReason]bool
	archives    map[string][][]byte
	released    map[releasedFile]bool
	// QuarantineOff tells that the quarantine action is off in the run: a
	// detection report in OUTPUT then names no container.
	QuarantineOff bool
	flagged       map[string]bool
	lostByCrash   map[string]bool
}

// Allow declares that files may be delivered with these not-analyzed reasons.
func (e *Expectations) Allow(reasons ...datamodel.NotAnalyzedReason) {
	if e.reasons == nil {
		e.reasons = map[datamodel.NotAnalyzedReason]bool{}
	}
	for _, r := range reasons {
		e.reasons[r] = true
	}
}

// Flag declares contents that a plugin treats as malware without the service
// (a forbidden path or type): they count as malware for the checker, as the
// ones the test programmed in the fake service. It only adds to that set.
func (e *Expectations) Flag(contents ...[]byte) {
	for _, c := range contents {
		e.FlagSHA256(gmalware.SHA256Hex(c))
	}
}

// FlagSHA256 is Flag for a content known by its SHA256 only.
func (e *Expectations) FlagSHA256(sum string) {
	if e.flagged == nil {
		e.flagged = map[string]bool{}
	}
	e.flagged[sum] = true
}

// CrashLost declares contents whose session report a crash of the connector
// lost, which the connector documents (the spool of a crashed run is not
// recovered): they may be in OUTPUT with no report, but only if the service
// analyzed them clean, with no analysis error.
func (e *Expectations) CrashLost(contents ...[]byte) {
	if e.lostByCrash == nil {
		e.lostByCrash = map[string]bool{}
	}
	for _, c := range contents {
		e.lostByCrash[gmalware.SHA256Hex(c)] = true
	}
}

// releasedFile is what an operator restores: one file, known by its location
// in INPUT and its content. A release never covers the same content elsewhere.
type releasedFile struct {
	location, sha256 string
}

func released(location, sum string) releasedFile {
	return releasedFile{location: filepath.Clean(location), sha256: strings.ToLower(sum)}
}

// Release declares that an operator restored this malware, found at location
// in INPUT, from the quarantine: the connector then delivers it on purpose at
// the same place below OUTPUT, with the restored mark, and the detection it made
// earlier stays in the reports. The same content anywhere else is not covered.
func (e *Expectations) Release(location string, content []byte) {
	e.ReleaseSHA256(location, gmalware.SHA256Hex(content))
}

// ReleaseSHA256 is Release for a content known by its SHA256 only.
func (e *Expectations) ReleaseSHA256(location, sum string) {
	if e.released == nil {
		e.released = map[releasedFile]bool{}
	}
	e.released[released(location, sum)] = true
}

// Archive declares the members of an archive the scenario delivers: the
// checker does not extract archives, it trusts the contents the scenario built.
func (e *Expectations) Archive(content []byte, members ...[]byte) {
	if e.archives == nil {
		e.archives = map[string][][]byte{}
	}
	e.archives[gmalware.SHA256Hex(content)] = members
}

// checkSpec is what the checker looks at: the folders of the run and the
// expectations.
type checkSpec struct {
	input, output, reports, quarantine string
	Expectations
}

// outputViolations checks the invariant of the connector on OUTPUT: every file
// there is in a session report and was either analyzed by the service with a
// clean verdict or carries a not-analyzed reason that the file justifies;
// nothing the test programmed as malware, nothing in error, nothing that is not
// a regular file. Whatever else is left there (a staging folder, a temporary
// file) is flagged on purpose. Archives are not extracted: their members are
// the ones the scenario declared, and the service must have seen one. It returns
// one line per violation.
func outputViolations(spec checkSpec, gm *gmalware.GMalware) (violations []string) {
	reports, errs := ReadSessionReports(spec.reports)
	violations = append(violations, errs...)
	files, problems := listEntries(spec.output)
	violations = append(violations, problems...)
	deliveries := map[releasedFile]int{}
	for _, path := range files {
		rel, relErr := filepath.Rel(spec.output, path)
		if relErr != nil {
			rel = path
		}
		sum, size, err := fileDigest(path)
		if err != nil {
			violations = append(violations, rel+": "+err.Error())
			continue
		}
		if isLockReport(filepath.Base(path)) {
			if spec.programmedMalware(sum, gm) {
				violations = append(violations, rel+": programmed as malware")
			}
			violations = append(violations, lockReportViolations(rel, path, size, spec, gm, reports)...)
			continue
		}
		source, isReleased := spec.releasedSource(rel, path, sum, reports[sum])
		if isReleased {
			deliveries[released(source, sum)]++
		}
		violations = append(violations, fileViolations(rel, path, sum, size, reports[sum], source, isReleased, spec, gm)...)
	}
	for f, n := range deliveries {
		if n > 1 {
			violations = append(violations, fmt.Sprintf("the released file %s (%s) is in OUTPUT %d times: a release delivers one file once", f.location, f.sha256[:12], n))
		}
	}
	return violations
}

// releasedSource is the location in INPUT of the released file delivered at
// path (rel below OUTPUT), if it is one. The connector keeps the tree of INPUT,
// except when the place is taken: it then delivers under a conflict name, and
// only the report that moved it (moved-to) tells where the file came from.
func (spec checkSpec) releasedSource(rel, path, sum string, entries []datamodel.Report) (string, bool) {
	if source := filepath.Join(spec.input, rel); spec.released[released(source, sum)] {
		return source, true
	}
	for _, e := range entries {
		if e.MovedTo != "" && filepath.Clean(e.MovedTo) == filepath.Clean(path) && spec.released[released(e.Filename, sum)] {
			return e.Filename, true
		}
	}
	return "", false
}

// listEntries returns the regular files below dir; what is neither a regular
// file nor a folder (a link, a device) is a problem, because the connector
// delivers regular files only.
func listEntries(dir string) (files, problems []string) {
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		switch {
		case d.IsDir():
		case d.Type().IsRegular():
			files = append(files, path)
		default:
			problems = append(problems, relOr(dir, path)+": not a regular file")
		}
		return nil
	})
	if err != nil {
		problems = append(problems, "walking "+dir+": "+err.Error())
	}
	return files, problems
}

func relOr(dir, path string) string {
	if rel, err := filepath.Rel(dir, path); err == nil {
		return rel
	}
	return path
}

// isLockReport tells the name of the detection report the connector leaves
// where it would have moved a malicious file. A user file that has such a name
// is held to the same checks, so it is flagged unless it is a genuine detection
// report: that is deliberate.
func isLockReport(name string) bool {
	return strings.Contains(name, "-lockreport") && filepath.Ext(name) == ".json"
}

// lockReportViolations checks that a lock report is exactly the report of a
// detection of a file the test programmed as malware (or of a declared archive with such a member), whose copy is in the
// quarantine; a file that hides behind that name is a violation.
func lockReportViolations(rel, path string, size int64, spec checkSpec, gm *gmalware.GMalware, reports map[string][]datamodel.Report) []string {
	quarantineDir := spec.quarantine
	if size > maxReportSize {
		return []string{rel + ": lock report larger than a report can be"}
	}
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return []string{rel + ": " + err.Error()}
	}
	defer func() { _ = f.Close() }()
	dec := json.NewDecoder(io.LimitReader(f, maxReportSize))
	dec.DisallowUnknownFields()
	var r datamodel.Report
	if err = dec.Decode(&r); err != nil {
		return []string{fmt.Sprintf("%s: lock report is not a report: %v", rel, err)}
	}
	if _, err = dec.Token(); !errors.Is(err, io.EOF) {
		return []string{rel + ": lock report followed by more data"}
	}
	var violations []string
	if !r.Malicious {
		violations = append(violations, rel+": lock report of a file that is not malicious")
	}
	if !spec.programmedMalware(r.SHA256, gm) {
		violations = append(violations, rel+": lock report of a file the test did not program as malware")
	}
	if quarantineDir == "" || !isSHA256(r.SHA256) {
		return append(violations, rel+": lock report with no verifiable SHA256")
	}
	if spec.QuarantineOff && r.MitigationID == "" {
		return violations
	}
	id := hcquarantine.ComputeCacheID(r.Filename, r.SHA256)
	if r.MitigationID == "" || r.MitigationID != id {
		violations = append(violations, rel+": the mitigation ID of the lock report is not the one of its file")
	}
	if _, err = os.Stat(filepath.Join(quarantineDir, id+".lock")); err != nil && (!spec.released[released(r.Filename, r.SHA256)] || !restoredIn(r.Filename, reports[r.SHA256])) {
		violations = append(violations, rel+": the file of the lock report is not in the quarantine")
	}
	return violations
}

func isSHA256(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == sha256.Size
}

// programmedMalware tells whether the content is malware for the test: it was
// programmed in the service or flagged for a plugin, or it is a declared archive
// with a member that was.
func (e *Expectations) programmedMalware(sha string, gm *gmalware.GMalware) bool {
	if e.isMalware(sha, gm) {
		return true
	}
	for _, m := range e.archives[sha] {
		if e.isMalware(gmalware.SHA256Hex(m), gm) {
			return true
		}
	}
	return false
}

// isMalware tells whether the content itself, not an archive around it, was
// programmed in the service or flagged for a plugin.
func (e *Expectations) isMalware(sha string, gm *gmalware.GMalware) bool {
	return gm.Programmed(sha) || e.flagged[sha]
}

// reasonAllowed tells whether a file of that size may be delivered with that
// not-analyzed reason: empty and too-big are checked against the size, the
// others must have been declared by the scenario.
func (e *Expectations) reasonAllowed(reason datamodel.NotAnalyzedReason, size int64) bool {
	switch reason {
	case datamodel.NotAnalyzedEmpty:
		return size == 0
	case datamodel.NotAnalyzedTooBig:
		return e.maxFileSize > 0 && size > e.maxFileSize
	case datamodel.NotAnalyzedEncrypted, datamodel.NotAnalyzedExtractLimit, datamodel.NotAnalyzedExtractError,
		datamodel.NotAnalyzedPolicySkipped, datamodel.NotAnalyzedSkippedPath, datamodel.NotAnalyzedSkippedType,
		datamodel.NotAnalyzedSymlink, datamodel.NotAnalyzedRestored, datamodel.NotAnalyzedAnalysisError:
		return e.reasons[reason]
	default:
		return false
	}
}

// RestoredEntry tells whether a report entry says the file was restored.
func RestoredEntry(e datamodel.Report) bool {
	return e.HasBeenRestored || e.NotAnalyzedReason == datamodel.NotAnalyzedRestored
}

// restoredIn tells whether the reports hold a restored entry of the file at
// location: the restore of that file really happened.
func restoredIn(location string, entries []datamodel.Report) bool {
	return slices.ContainsFunc(entries, func(e datamodel.Report) bool { return restoredAt(location, "", e) })
}

// restoredAt tells whether a report entry says that the file at location was
// restored and, when delivered is set, delivered there: a restored entry of the
// same content elsewhere does not count, nor one that moved the file to another
// place in OUTPUT.
func restoredAt(location, delivered string, e datamodel.Report) bool {
	if !RestoredEntry(e) || filepath.Clean(e.Filename) != filepath.Clean(location) {
		return false
	}
	return delivered == "" || e.MovedTo == "" || filepath.Clean(e.MovedTo) == filepath.Clean(delivered)
}

// fileViolations judges a delivered file by its reports. A malicious file, or
// a report that says so, is always a violation. A report in error is not, when
// a later attempt (a rescan after an outage) gave the file a valid report too:
// one valid report is enough.
func fileViolations(rel, path, sum string, size int64, entries []datamodel.Report, source string, isReleased bool, spec checkSpec, gm *gmalware.GMalware) (violations []string) {
	if !isReleased && spec.programmedMalware(sum, gm) {
		violations = append(violations, rel+": programmed as malware")
	}
	if len(entries) == 0 {
		if v, analyzed := gm.Given(sum); spec.lostByCrash[sum] && analyzed && !v.Malware && v.AnalysisError == "" && len(violations) == 0 {
			return nil
		}
		return append(violations, rel+": in no session report")
	}
	var problems []string
	valid := false
	for _, e := range entries {
		// The restored entry of this file is the only one excused from the
		// detection; the others are the earlier detection, which stays in the
		// reports, or other files of the same content.
		if isReleased && !restoredAt(source, path, e) {
			continue
		}
		ok, bad, issues := entryViolations(rel, sum, size, e, isReleased, spec, gm)
		valid = valid || ok
		violations = append(violations, bad...)
		problems = append(problems, issues...)
	}
	if isReleased && !valid && len(violations) == 0 && len(problems) == 0 {
		problems = append(problems, rel+": a restored malware delivered without a restored entry in the reports")
	}
	if !valid {
		violations = append(violations, problems...)
	}
	return violations
}

// entryViolations judges one report entry: whether it validates the delivery,
// the violations it brings, and the problems that a valid entry elsewhere
// cancels.
func entryViolations(rel, sum string, size int64, e datamodel.Report, isReleased bool, spec checkSpec, gm *gmalware.GMalware) (valid bool, violations, problems []string) {
	if e.Malicious || len(e.MaliciousExtractedFiles) > 0 {
		violations = append(violations, rel+": reported malicious")
	}
	for _, sub := range e.NotAnalyzedExtractedFiles {
		if !spec.reasonAllowed(sub.Reason, sub.Size) {
			violations = append(violations, fmt.Sprintf("%s: member %q delivered not analyzed for %q", rel, sub.FileName, sub.Reason))
		}
	}
	switch {
	case e.Error != "":
		problems = append(problems, rel+": reported in error: "+e.Error)
	case isReleased && (e.NotAnalyzedReason == "" || e.NotAnalyzedReason == datamodel.NotAnalyzedRestored):
		// The entry that says an operator restored the malware: it is held to the
		// same checks as any delivery, except for the detection itself.
		valid = true
	case e.NotAnalyzedReason != "":
		if !spec.reasonAllowed(e.NotAnalyzedReason, size) {
			violations = append(violations, fmt.Sprintf("%s: delivered not analyzed for %q, which nothing justifies", rel, e.NotAnalyzedReason))
		} else {
			valid = true
		}
	case e.TotalExtractedFile > 0:
		ok, bad, issues := archiveViolations(rel, sum, e, spec, gm)
		valid, violations, problems = ok, append(violations, bad...), append(problems, issues...)
	case len(e.NotAnalyzedExtractedFiles) > 0:
		// An archive whose every member was left out: the reasons of its members,
		// checked above, are what justifies it.
		valid = true
	default:
		v, ok := gm.Given(sum)
		switch {
		case !ok:
			problems = append(problems, rel+": never analyzed and no not-analyzed reason")
		case v.Malware:
			violations = append(violations, rel+": the service said malware")
		default:
			valid = true
		}
	}
	return valid && len(violations) == 0, violations, problems
}

// archiveViolations holds an archive to its declared members: none programmed
// as malware, at least one seen by the service unless every member is listed
// not analyzed, none failed.
func archiveViolations(rel, sum string, e datamodel.Report, spec checkSpec, gm *gmalware.GMalware) (valid bool, violations, problems []string) {
	members, declared := spec.archives[sum]
	if !declared {
		return false, []string{rel + ": archive whose members the scenario did not declare"}, nil
	}
	seen := false
	for _, m := range members {
		memberSum := gmalware.SHA256Hex(m)
		if spec.isMalware(memberSum, gm) {
			violations = append(violations, rel+": a member is programmed as malware")
		}
		if _, ok := gm.Given(memberSum); ok {
			seen = true
		}
	}
	if !seen && e.NotAnalyzedExtractedCount < e.TotalExtractedFile {
		problems = append(problems, rel+": no member was ever analyzed")
	}
	if len(e.ErrorExtractedFiles) > 0 {
		problems = append(problems, rel+": members in error")
	}
	return seen && len(e.ErrorExtractedFiles) == 0, violations, problems
}

// fileDigest returns the SHA256 and the size of a file.
func fileDigest(path string) (sum string, size int64, err error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	size, err = io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), size, nil
}

// ReadSessionReports gathers the JSON session reports found below dir,
// by SHA256 of the file they describe.
func ReadSessionReports(dir string) (bySHA map[string][]datamodel.Report, problems []string) {
	bySHA = map[string][]datamodel.Report{}
	files, problems := listEntries(dir)
	for _, path := range files {
		name := filepath.Base(path)
		if !strings.HasPrefix(name, datamodel.SessionReportPrefix) || filepath.Ext(name) != ".json" {
			continue
		}
		reports, err := decodeReports(path)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: unreadable report: %v", name, err))
			continue
		}
		for _, r := range reports {
			bySHA[r.SHA256] = append(bySHA[r.SHA256], r)
		}
	}
	return bySHA, problems
}

func decodeReports(path string) ([]datamodel.Report, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var reports []datamodel.Report
	if err = json.NewDecoder(io.LimitReader(f, maxReportSize)).Decode(&reports); err != nil {
		return nil, err
	}
	return reports, nil
}
