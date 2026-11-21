//go:build linux

package test

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
	"strings"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	hcquarantine "github.com/glimps-re/host-connector/pkg/quarantine"
)

// maxReportSize bounds the report the checker reads.
const maxReportSize = 64 << 20

// expectations are what a scenario declares to the checker: the not-analyzed
// reasons it expects (empty and too-big need no declaration, they are checked
// against the file), the largest file the analysis accepts, and the members of
// the archives it delivers.
type expectations struct {
	maxFileSize int64
	reasons     map[datamodel.NotAnalyzedReason]bool
	archives    map[string][][]byte
}

// allow declares that files may be delivered with these not-analyzed reasons.
func (e *expectations) allow(reasons ...datamodel.NotAnalyzedReason) {
	if e.reasons == nil {
		e.reasons = map[datamodel.NotAnalyzedReason]bool{}
	}
	for _, r := range reasons {
		e.reasons[r] = true
	}
}

// archive declares the members of an archive the scenario delivers: the
// checker does not extract archives, it trusts the contents the scenario built.
func (e *expectations) archive(content []byte, members ...[]byte) {
	if e.archives == nil {
		e.archives = map[string][][]byte{}
	}
	e.archives[sha256Hex(content)] = members
}

// checkSpec is what the checker looks at: the folders of the run and the
// expectations.
type checkSpec struct {
	output, reports, quarantine string
	expectations
}

// outputViolations checks the invariant of the connector on OUTPUT: every file
// there is in a session report and was either analyzed by the service with a
// clean verdict or carries a not-analyzed reason that the file justifies;
// nothing the test programmed as malware, nothing in error, nothing that is not
// a regular file. Whatever else is left there (a staging folder, a temporary
// file) is flagged on purpose. Archives are not extracted: their members are
// the ones the scenario declared, and the service must have seen one. It returns
// one line per violation.
func outputViolations(spec checkSpec, gm *gmalware) (violations []string) {
	reports, errs := readSessionReports(spec.reports)
	violations = append(violations, errs...)
	files, problems := listEntries(spec.output)
	violations = append(violations, problems...)
	for _, path := range files {
		rel, relErr := filepath.Rel(spec.output, path)
		if relErr != nil {
			rel = path
		}
		if isLockReport(filepath.Base(path)) {
			violations = append(violations, lockReportViolations(rel, path, spec.quarantine, gm)...)
			continue
		}
		sum, size, err := fileDigest(path)
		if err != nil {
			violations = append(violations, rel+": "+err.Error())
			continue
		}
		violations = append(violations, fileViolations(rel, sum, size, reports[sum], spec, gm)...)
	}
	return violations
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
// where it would have moved a malicious file.
func isLockReport(name string) bool {
	return strings.Contains(name, "-lockreport") && filepath.Ext(name) == ".json"
}

// lockReportViolations checks that a lock report is exactly the report of a
// detection of a file the test programmed as malware, whose copy is in the
// quarantine; a file that hides behind that name is a violation.
func lockReportViolations(rel, path, quarantineDir string, gm *gmalware) []string {
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
	if !gm.Programmed(r.SHA256) {
		violations = append(violations, rel+": lock report of a file the test did not program as malware")
	}
	if quarantineDir == "" || !isSHA256(r.SHA256) {
		return append(violations, rel+": lock report with no verifiable SHA256")
	}
	id := hcquarantine.ComputeCacheID(r.Filename, r.SHA256)
	if r.MitigationID == "" || r.MitigationID != id {
		violations = append(violations, rel+": the mitigation ID of the lock report is not the one of its file")
	}
	if _, err = os.Stat(filepath.Join(quarantineDir, id+".lock")); err != nil {
		violations = append(violations, rel+": the file of the lock report is not in the quarantine")
	}
	return violations
}

func isSHA256(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == sha256.Size
}

// reasonAllowed tells whether a file of that size may be delivered with that
// not-analyzed reason: empty and too-big are checked against the size, the
// others must have been declared by the scenario.
func (e *expectations) reasonAllowed(reason datamodel.NotAnalyzedReason, size int64) bool {
	switch reason {
	case datamodel.NotAnalyzedEmpty:
		return size == 0
	case datamodel.NotAnalyzedTooBig:
		return size > e.maxFileSize
	case datamodel.NotAnalyzedEncrypted, datamodel.NotAnalyzedExtractLimit, datamodel.NotAnalyzedExtractError,
		datamodel.NotAnalyzedPolicySkipped, datamodel.NotAnalyzedRestored:
		return e.reasons[reason]
	default:
		return false
	}
}

// fileViolations judges a delivered file by its reports. A malicious file, or
// a report that says so, is always a violation. A report in error is not, when
// a later attempt (a rescan after an outage) gave the file a valid report too:
// one valid report is enough.
func fileViolations(rel, sum string, size int64, entries []datamodel.Report, spec checkSpec, gm *gmalware) (violations []string) {
	if gm.Programmed(sum) {
		violations = append(violations, rel+": programmed as malware")
	}
	if len(entries) == 0 {
		return append(violations, rel+": in no session report")
	}
	var problems []string
	valid := false
	for _, e := range entries {
		ok, bad, issues := entryViolations(rel, sum, size, e, spec, gm)
		valid = valid || ok
		violations = append(violations, bad...)
		problems = append(problems, issues...)
	}
	if !valid {
		violations = append(violations, problems...)
	}
	return violations
}

// entryViolations judges one report entry: whether it validates the delivery,
// the violations it brings, and the problems that a valid entry elsewhere
// cancels.
func entryViolations(rel, sum string, size int64, e datamodel.Report, spec checkSpec, gm *gmalware) (valid bool, violations, problems []string) {
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
	case e.NotAnalyzedReason != "":
		if !spec.reasonAllowed(e.NotAnalyzedReason, size) {
			violations = append(violations, fmt.Sprintf("%s: delivered not analyzed for %q, which nothing justifies", rel, e.NotAnalyzedReason))
		} else {
			valid = true
		}
	case e.TotalExtractedFile > 0:
		ok, bad, issues := archiveViolations(rel, sum, e, spec, gm)
		valid, violations, problems = ok, append(violations, bad...), append(problems, issues...)
	default:
		v, ok := gm.Given(sum)
		switch {
		case !ok:
			problems = append(problems, rel+": never analyzed and no not-analyzed reason")
		case v.malware:
			violations = append(violations, rel+": the service said malware")
		default:
			valid = true
		}
	}
	return valid && len(violations) == 0, violations, problems
}

// archiveViolations holds an archive to its declared members: none programmed
// as malware, at least one seen by the service, none failed.
func archiveViolations(rel, sum string, e datamodel.Report, spec checkSpec, gm *gmalware) (valid bool, violations, problems []string) {
	members, declared := spec.archives[sum]
	if !declared {
		return false, []string{rel + ": archive whose members the scenario did not declare"}, nil
	}
	seen := false
	for _, m := range members {
		memberSum := sha256Hex(m)
		if gm.Programmed(memberSum) {
			violations = append(violations, rel+": a member is programmed as malware")
		}
		if _, ok := gm.Given(memberSum); ok {
			seen = true
		}
	}
	if !seen {
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

// readSessionReports gathers the JSON session reports found below dir,
// by SHA256 of the file they describe.
func readSessionReports(dir string) (bySHA map[string][]datamodel.Report, problems []string) {
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
