package scanner

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
)

type anomalyRun struct {
	*extractorFixture
	attempts atomic.Int32
	done     *outcomes
	mu       sync.Mutex
	reports  []*datamodel.Report
}

func (r *anomalyRun) reportList() []*datamodel.Report {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*datamodel.Report(nil), r.reports...)
}

// scanAnomaly deposits an archive under the policy and returns once its
// processing ended.
func scanAnomaly(t *testing.T, policy string, extract plugins.ExtractFile) (run *anomalyRun, archive string) {
	t.Helper()
	return scanAnomalyWith(t, Unanalyzable{ExtractError: policy}, extract)
}

func scanAnomalyWith(t *testing.T, policy Unanalyzable, extract plugins.ExtractFile) (run *anomalyRun, archive string) {
	t.Helper()
	noOpenInputs(t)
	run = &anomalyRun{done: &outcomes{}}
	run.extractorFixture = newExtractorFixture(t, func(src, out string, l plugins.ExtractLimits) (plugins.Extraction, error) {
		run.attempts.Add(1)
		return extract(src, out, l)
	}, func(c *Config) {
		c.Unanalyzable = policy
		c.OnFileDone = run.done.add
	})
	run.conn.RegisterOnReport(func(r *datamodel.Report) {
		run.mu.Lock()
		run.reports = append(run.reports, r)
		run.mu.Unlock()
	})
	archive = run.deposit(t, "a.zip")
	if err := run.conn.ScanFile(t.Context(), archive); err != nil {
		t.Fatalf("ScanFile() error = %v", err)
	}
	t.Cleanup(func() { run.conn.Close(context.WithoutCancel(t.Context())) })
	waitUntil(t, "the processing to end", func() bool { return len(run.done.get()) == 1 })
	return run, archive
}

func anomalyBy(cause error) plugins.ExtractFile {
	return func(string, string, plugins.ExtractLimits) (plugins.Extraction, error) {
		return plugins.Extraction{}, fmt.Errorf("7z: %w: %w", plugins.ErrArchiveAnomaly, cause)
	}
}

func TestExtractError_anAnomalyIsDefinitiveUnderTheDefaultPolicy(t *testing.T) {
	trailing := func(_, outputDir string, _ plugins.ExtractLimits) (plugins.Extraction, error) {
		p := filepath.Join(outputDir, "member.txt")
		if err := os.WriteFile(p, []byte("m"), 0o600); err != nil {
			return plugins.Extraction{}, err
		}
		return plugins.Extraction{
			Files:        []string{p},
			Skipped:      []datamodel.NotAnalyzedFile{{FileName: "a.zip", Reason: datamodel.NotAnalyzedExtractError}},
			SkippedCount: 1,
		}, nil
	}
	tests := []struct {
		name    string
		extract plugins.ExtractFile
	}{
		{"truncated archive", anomalyBy(errors.New("unexpected end of archive"))},
		{"twin members", anomalyBy(errors.New("two members with one name"))},
		{"data after the end", trailing},
	}
	for _, tt := range tests {
		for _, policy := range []string{"", PolicyError} {
			t.Run(tt.name+"/policy "+policy, func(t *testing.T) {
				run, archive := scanAnomaly(t, policy, tt.extract)
				if got := run.attempts.Load(); got != 1 {
					t.Errorf("extraction attempts = %d, want 1", got)
				}
				if out := run.done.get(); out[0].Kind != OutcomeFinal {
					t.Errorf("outcome = %v, want OutcomeFinal", out[0].Kind)
				}
				reports := run.reportList()
				if len(reports) != 1 || reports[0].Error == "" {
					t.Fatalf("reports = %+v, want one with the error", reports)
				}
				if got := reports[0].Error; got != errExtractAnomaly.Error() {
					t.Errorf("report error = %q, want the fixed text %q", got, errExtractAnomaly.Error())
				}
				if run.submitted.Load() != 0 {
					t.Error("a damaged archive must not be submitted as a plain file")
				}
				run.assertLeftInPlace(t, archive)
			})
		}
	}
}

func TestExtractError_aTransientFailureIsRetriedWhateverThePolicy(t *testing.T) {
	tests := []struct {
		name    string
		extract plugins.ExtractFile
	}{
		{"7z killed", func(string, string, plugins.ExtractLimits) (plugins.Extraction, error) {
			return plugins.Extraction{}, errors.New("signal: killed")
		}},
		{"timeout", func(string, string, plugins.ExtractLimits) (plugins.Extraction, error) {
			return plugins.Extraction{}, fmt.Errorf("7z exceeded the time allowed: %w", context.DeadlineExceeded)
		}},
		{"anomaly joined with a timeout", func(string, string, plugins.ExtractLimits) (plugins.Extraction, error) {
			return plugins.Extraction{}, errors.Join(plugins.ErrArchiveAnomaly, context.DeadlineExceeded)
		}},
		{"anomaly joined with a cancellation", func(string, string, plugins.ExtractLimits) (plugins.Extraction, error) {
			return plugins.Extraction{}, errors.Join(plugins.ErrArchiveAnomaly, context.Canceled)
		}},
		{"error of a third party extractor", func(string, string, plugins.ExtractLimits) (plugins.Extraction, error) {
			return plugins.Extraction{}, errors.New("extract-error: corrupted")
		}},
	}
	for _, tt := range tests {
		for _, policy := range []string{PolicyError, PolicyAsFile} {
			t.Run(tt.name+"/"+policy, func(t *testing.T) {
				run, archive := scanAnomaly(t, policy, tt.extract)
				if out := run.done.get(); out[0].Kind != OutcomeRetry {
					t.Errorf("outcome = %v, want OutcomeRetry", out[0].Kind)
				}
				if reports := run.reportList(); len(reports) != 0 {
					t.Errorf("reports = %+v, a retry says nothing yet", reports)
				}
				if run.submitted.Load() != 0 {
					t.Error("an archive whose extraction failed for a transient reason must never be submitted as a plain file")
				}
				run.assertLeftInPlace(t, archive)
			})
		}
	}
}

func TestExtractError_asFileAnalyzesTheArchiveAsAPlainFileAndMovesIt(t *testing.T) {
	run, archive := scanAnomaly(t, PolicyAsFile, func(_, outputDir string, _ plugins.ExtractLimits) (plugins.Extraction, error) {
		partial := filepath.Join(outputDir, "partial.txt")
		if err := os.WriteFile(partial, []byte("extracted before the failure"), 0o600); err != nil {
			return plugins.Extraction{}, err
		}
		return plugins.Extraction{}, fmt.Errorf("7z: %w", plugins.ErrArchiveAnomaly)
	})
	if got := run.submitted.Load(); got != 1 {
		t.Errorf("submissions = %d, want the archive once, as a plain file", got)
	}
	if got := run.attempts.Load(); got != 1 {
		t.Errorf("extraction attempts = %d, want 1", got)
	}
	if out := run.done.get(); out[0].Kind != OutcomeFinal {
		t.Errorf("outcome = %v, want OutcomeFinal", out[0].Kind)
	}
	if _, err := os.Stat(archive); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the archive must have been moved: %v", err)
	}
	if _, err := os.Stat(filepath.Join(run.dst, "a.zip")); err != nil {
		t.Errorf("the archive is not in OUTPUT: %v", err)
	}
	reports := run.reportList()
	if len(reports) != 1 {
		t.Fatalf("reports = %d, want 1", len(reports))
	}
	if r := reports[0]; r.NotAnalyzedReason != datamodel.NotAnalyzedExtractError || r.Error != "" || r.Malicious {
		t.Errorf("report = %+v, want a clean file marked extract-error without error", r)
	}
	waitUntil(t, "what was extracted to be discarded", func() bool {
		entries, err := os.ReadDir(run.conn.work.extractDir())
		return err == nil && len(entries) == 0
	})
}

func TestExtractError_asFileLetsAMaliciousVerdictWin(t *testing.T) {
	noOpenInputs(t)
	f := newExtractorFixture(t, anomalyBy(errors.New("data error")), func(c *Config) {
		c.Unanalyzable = Unanalyzable{ExtractError: PolicyAsFile}
		c.Actions = Actions{Move: true, Deleted: true}
	})
	var reportMu sync.Mutex
	var reports []*datamodel.Report
	f.conn.RegisterOnReport(func(r *datamodel.Report) {
		reportMu.Lock()
		reports = append(reports, r)
		reportMu.Unlock()
	})
	submitter := archiveCleanSubmitter()
	submitter.WaitForFileMock = func(context.Context, string, gdetect.WaitForOptions) (gdetect.Result, error) {
		return gdetect.Result{Malware: true, Malwares: []string{"evil"}}, nil
	}
	echoReader(submitter)
	f.conn.submitter = submitter
	archive := f.deposit(t, "a.zip")
	if err := f.conn.ScanFile(t.Context(), archive); err != nil {
		t.Fatal(err)
	}
	f.conn.Close(t.Context())
	reportMu.Lock()
	defer reportMu.Unlock()
	if len(reports) != 1 {
		t.Fatalf("reports = %d, want 1", len(reports))
	}
	if r := reports[0]; !r.Malicious || r.NotAnalyzedReason == datamodel.NotAnalyzedExtractError {
		t.Errorf("report = %+v, want malware and no extract-error mark", r)
	}
	if _, err := os.Stat(filepath.Join(f.dst, "a.zip")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a detected archive must not be delivered: %v", err)
	}
}

func TestExtractError_asFileNeverAppliesToAnUnavailableExtractor(t *testing.T) {
	run, archive := scanAnomaly(t, PolicyAsFile, func(string, string, plugins.ExtractLimits) (plugins.Extraction, error) {
		return plugins.Extraction{}, fmt.Errorf("fork/exec 7zzs: %w", plugins.ErrExtractorUnavailable)
	})
	if run.submitted.Load() != 0 {
		t.Error("an archive that could not be extracted because the extractor is down must not be submitted")
	}
	if out := run.done.get(); out[0].Kind != OutcomeResource {
		t.Errorf("outcome = %v, want OutcomeResource", out[0].Kind)
	}
	if events, ok := EventHandler.(*recordingEventHandler); !ok || events.errors == 0 {
		t.Error("the alert about the extractor was not raised")
	}
	run.assertLeftInPlace(t, archive)
}

func TestExtractError_asFileKeepsAnAnomalyMemberAsAFileOfItsArchive(t *testing.T) {
	inner := realZip(t)
	nested := func(policy string) (*anomalyRun, string) {
		var calls atomic.Int32
		return scanAnomaly(t, policy, func(_, outputDir string, _ plugins.ExtractLimits) (plugins.Extraction, error) {
			if calls.Add(1) > 1 {
				return plugins.Extraction{}, fmt.Errorf("7z: %w", plugins.ErrArchiveAnomaly)
			}
			var files []string
			for name, content := range map[string][]byte{"inner.zip": inner, "plain.txt": []byte("plain member")} {
				p := filepath.Join(outputDir, name)
				if err := os.WriteFile(p, content, 0o600); err != nil {
					return plugins.Extraction{}, err
				}
				files = append(files, p)
			}
			return plugins.Extraction{Size: uint64(len(inner)) + 12, Files: files}, nil
		})
	}
	t.Run("as_file", func(t *testing.T) {
		run, _ := nested(PolicyAsFile)
		reports := run.reportList()
		if len(reports) != 1 {
			t.Fatalf("reports = %d, want 1", len(reports))
		}
		r := reports[0]
		if len(r.NotAnalyzedExtractedFiles) != 1 || r.NotAnalyzedExtractedFiles[0].FileName != "inner.zip" || r.NotAnalyzedExtractedFiles[0].Reason != datamodel.NotAnalyzedExtractError {
			t.Errorf("NotAnalyzedExtractedFiles = %+v, want inner.zip listed as extract-error", r.NotAnalyzedExtractedFiles)
		}
		if run.submitted.Load() != 2 {
			t.Errorf("submissions = %d, want the two members", run.submitted.Load())
		}
	})
	t.Run("error", func(t *testing.T) {
		run, archive := nested(PolicyError)
		reports := run.reportList()
		if len(reports) != 1 || reports[0].ErrorExtractedFiles["inner.zip"] == "" {
			t.Fatalf("reports = %+v, want the failed member inner.zip listed", reports)
		}
		if out := run.done.get(); out[0].Kind != OutcomeFinal {
			t.Errorf("outcome = %v, want OutcomeFinal: the anomaly of the member is definitive", out[0].Kind)
		}
		if _, err := os.Stat(archive); err != nil {
			t.Errorf("the archive must stay in INPUT: %v", err)
		}
	})
}

func possibleAnomaly(string, string, plugins.ExtractLimits) (plugins.Extraction, error) {
	return plugins.Extraction{}, fmt.Errorf("7z: %w: %w: unexpected end", plugins.ErrArchiveAnomaly, plugins.ErrEncryptionPossible)
}

// An anomaly that an encryption may hide in is never a plain file: the policy of
// the encrypted files decides, under as_file, and the report says that the archive
// may be damaged rather than encrypted.
func TestExtractError_asFileFollowsTheEncryptedPolicyWhenEncryptionIsPossible(t *testing.T) {
	t.Run("error: left in INPUT, definitively, with a report", func(t *testing.T) {
		run, archive := scanAnomalyWith(t, Unanalyzable{Encrypted: PolicyError, ExtractError: PolicyAsFile}, possibleAnomaly)
		if run.submitted.Load() != 1 {
			t.Errorf("submissions = %d, want the container once: a malicious verdict wins whatever the policy", run.submitted.Load())
		}
		if out := run.done.get(); out[0].Kind != OutcomeFinal {
			t.Errorf("outcome = %v, want OutcomeFinal", out[0].Kind)
		}
		reports := run.reportList()
		if len(reports) != 1 || reports[0].Error != errEncryptedOrDamaged.Error() {
			t.Fatalf("reports = %+v, want one with the error %q", reports, errEncryptedOrDamaged.Error())
		}
		run.assertLeftInPlace(t, archive)
	})
	t.Run("pass: delivered marked encrypted", func(t *testing.T) {
		run, _ := scanAnomalyWith(t, Unanalyzable{Encrypted: PolicyPass, ExtractError: PolicyAsFile}, possibleAnomaly)
		reports := run.reportList()
		if len(reports) != 1 || reports[0].NotAnalyzedReason != datamodel.NotAnalyzedEncrypted || reports[0].Error != "" {
			t.Fatalf("reports = %+v, want one marked encrypted without error", reports)
		}
		if _, err := os.Stat(filepath.Join(run.dst, "a.zip")); err != nil {
			t.Errorf("the archive is not in OUTPUT: %v", err)
		}
	})
	t.Run("mitigate: malware encrypted, not delivered", func(t *testing.T) {
		run, _ := scanAnomalyWith(t, Unanalyzable{Encrypted: PolicyMitigate, ExtractError: PolicyAsFile}, possibleAnomaly)
		reports := run.reportList()
		if len(reports) != 1 || !reports[0].Malicious || reports[0].MalwareReason != datamodel.Encrypted {
			t.Fatalf("reports = %+v, want malware with the reason encrypted", reports)
		}
		if _, err := os.Stat(filepath.Join(run.dst, "a.zip")); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("a mitigated archive must not be delivered: %v", err)
		}
	})
	t.Run("the error policy keeps it definitive whatever encrypted says", func(t *testing.T) {
		run, archive := scanAnomalyWith(t, Unanalyzable{Encrypted: PolicyPass, ExtractError: PolicyError}, possibleAnomaly)
		reports := run.reportList()
		if len(reports) != 1 || reports[0].Error != errExtractAnomaly.Error() || run.submitted.Load() != 0 {
			t.Fatalf("reports = %+v, submissions %d, want the fixed definitive error and nothing submitted", reports, run.submitted.Load())
		}
		run.assertLeftInPlace(t, archive)
	})
}

// ErrEncryptionPossible alone says the archive is damaged too.
func TestExtractError_encryptionPossibleAloneIsHandledAsAnAnomaly(t *testing.T) {
	run, archive := scanAnomalyWith(t, Unanalyzable{Encrypted: PolicyError, ExtractError: PolicyError}, func(string, string, plugins.ExtractLimits) (plugins.Extraction, error) {
		return plugins.Extraction{}, plugins.ErrEncryptionPossible
	})
	if out := run.done.get(); out[0].Kind != OutcomeFinal {
		t.Errorf("outcome = %v, want OutcomeFinal", out[0].Kind)
	}
	run.assertLeftInPlace(t, archive)
}

// What an extractor reports with a nil error (an extract-error entry) is a safety
// net: the archive is treated as damaged with an encryption possible, never as a
// plain file.
func TestExtractError_anExtractErrorEntryWithoutAnErrorIsNeverAPlainFile(t *testing.T) {
	entry := func(_, outputDir string, _ plugins.ExtractLimits) (plugins.Extraction, error) {
		p := filepath.Join(outputDir, "member.txt")
		if err := os.WriteFile(p, []byte("m"), 0o600); err != nil {
			return plugins.Extraction{}, err
		}
		return plugins.Extraction{
			Files:        []string{p},
			Skipped:      []datamodel.NotAnalyzedFile{{FileName: "a.zip", Reason: datamodel.NotAnalyzedExtractError}},
			SkippedCount: 1,
		}, nil
	}
	t.Run("encrypted error", func(t *testing.T) {
		run, archive := scanAnomalyWith(t, Unanalyzable{Encrypted: PolicyError, ExtractError: PolicyAsFile}, entry)
		reports := run.reportList()
		if len(reports) != 1 || reports[0].Error != errEncryptedOrDamaged.Error() || reports[0].NotAnalyzedReason == datamodel.NotAnalyzedExtractError {
			t.Fatalf("reports = %+v, want the failure of the encrypted policy", reports)
		}
		run.assertLeftInPlace(t, archive)
	})
	t.Run("encrypted pass", func(t *testing.T) {
		run, _ := scanAnomalyWith(t, Unanalyzable{Encrypted: PolicyPass, ExtractError: PolicyAsFile}, entry)
		reports := run.reportList()
		if len(reports) != 1 || reports[0].NotAnalyzedReason != datamodel.NotAnalyzedEncrypted {
			t.Fatalf("reports = %+v, want the archive marked encrypted, never extract-error", reports)
		}
	})
}

// An archive over max_file_size under as_file is a file too big: the policy of the
// files too big decides, and it is reported too-big.
func TestAnalyzeFile_asFileOverMaxFileSizeFollowsTooBig(t *testing.T) {
	in := fileToAnalyze{filename: "f", location: "/in/f", sha256: "sha", size: 500, extractError: true}
	tests := []struct {
		policy string
		check  func(t *testing.T, r datamodel.Result)
	}{
		{PolicyError, func(t *testing.T, r datamodel.Result) {
			if !errors.Is(r.Error, errFileTooBig) || r.NotAnalyzedReason != "" {
				t.Errorf("result = %+v, want errFileTooBig", r)
			}
		}},
		{PolicyPass, func(t *testing.T, r datamodel.Result) {
			if r.Error != nil || r.NotAnalyzedReason != datamodel.NotAnalyzedTooBig {
				t.Errorf("result = %+v, want passed marked too-big, not extract-error", r)
			}
		}},
		{PolicyMitigate, func(t *testing.T, r datamodel.Result) {
			if !r.Malware || r.MalwareReason != datamodel.TooBig {
				t.Errorf("result = %+v, want malware too-big", r)
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.policy, func(t *testing.T) {
			c := policyConnector(t, Unanalyzable{TooBig: tt.policy, ExtractError: PolicyAsFile}, 100, cleanSubmitter())
			tt.check(t, c.analyzeFile(in))
		})
	}
}

func refusedAsNotAnArchive(string, string, plugins.ExtractLimits) (plugins.Extraction, error) {
	return plugins.Extraction{}, plugins.ErrUnsupportedFormat
}

// An extractor that refuses a file typed as an archive does not make it a plain
// file: it is an anomaly with the encryption possible.
func TestExtractError_aFileTypedAsAnArchiveThatTheExtractorRefusesIsNotAPlainFile(t *testing.T) {
	t.Run("default: definitive, in INPUT", func(t *testing.T) {
		run, archive := scanAnomalyWith(t, Unanalyzable{}, refusedAsNotAnArchive)
		reports := run.reportList()
		if len(reports) != 1 || reports[0].Error != errExtractAnomaly.Error() || run.submitted.Load() != 0 {
			t.Fatalf("reports = %+v, submissions %d, want the fixed definitive error and nothing submitted", reports, run.submitted.Load())
		}
		if out := run.done.get(); out[0].Kind != OutcomeFinal {
			t.Errorf("outcome = %v, want OutcomeFinal", out[0].Kind)
		}
		run.assertLeftInPlace(t, archive)
	})
	t.Run("as_file with encrypted pass: delivered marked encrypted", func(t *testing.T) {
		run, _ := scanAnomalyWith(t, Unanalyzable{Encrypted: PolicyPass, ExtractError: PolicyAsFile}, refusedAsNotAnArchive)
		reports := run.reportList()
		if len(reports) != 1 || reports[0].NotAnalyzedReason != datamodel.NotAnalyzedEncrypted {
			t.Fatalf("reports = %+v, want the archive marked encrypted", reports)
		}
	})
	t.Run("as_file with encrypted error: kept in INPUT", func(t *testing.T) {
		run, archive := scanAnomalyWith(t, Unanalyzable{ExtractError: PolicyAsFile}, refusedAsNotAnArchive)
		reports := run.reportList()
		if len(reports) != 1 || reports[0].Error != errEncryptedOrDamaged.Error() {
			t.Fatalf("reports = %+v, want the failure of the encrypted policy", reports)
		}
		run.assertLeftInPlace(t, archive)
	})
}

// A file that is not typed as an archive stays a plain file when it is refused.
func TestExtractError_aFileNotTypedAsAnArchiveStaysAPlainFileWhenRefused(t *testing.T) {
	noOpenInputs(t)
	run := &anomalyRun{done: &outcomes{}}
	run.extractorFixture = newExtractorFixture(t, refusedAsNotAnArchive, func(c *Config) { c.OnFileDone = run.done.add })
	t.Cleanup(func() { run.conn.Close(context.WithoutCancel(t.Context())) })
	path := filepath.Join(run.src, "notes.bin")
	if err := os.WriteFile(path, append([]byte{0x00, 0x01, 0x02}, make([]byte, 200)...), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run.conn.ScanFile(t.Context(), path); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "the processing to end", func() bool { return len(run.done.get()) == 1 })
	if run.submitted.Load() != 1 {
		t.Errorf("submissions = %d, want the file once, as a plain file", run.submitted.Load())
	}
	if _, err := os.Stat(filepath.Join(run.dst, "notes.bin")); err != nil {
		t.Errorf("the file is not in OUTPUT: %v", err)
	}
}

// The rule is the same for a member that is a sub-archive.
func TestExtractError_aMemberTypedAsAnArchiveThatTheExtractorRefusesFollowsThePolicies(t *testing.T) {
	inner := realZip(t)
	nested := func(policy Unanalyzable) *anomalyRun {
		var calls atomic.Int32
		run, _ := scanAnomalyWith(t, policy, func(_, outputDir string, _ plugins.ExtractLimits) (plugins.Extraction, error) {
			if calls.Add(1) > 1 {
				return plugins.Extraction{}, plugins.ErrUnsupportedFormat
			}
			p := filepath.Join(outputDir, "inner.zip")
			if err := os.WriteFile(p, inner, 0o600); err != nil {
				return plugins.Extraction{}, err
			}
			return plugins.Extraction{Size: uint64(len(inner)), Files: []string{p}}, nil
		})
		return run
	}
	t.Run("default: the member is in error, the archive definitive", func(t *testing.T) {
		run := nested(Unanalyzable{})
		reports := run.reportList()
		if len(reports) != 1 || reports[0].ErrorExtractedFiles["inner.zip"] == "" {
			t.Fatalf("reports = %+v, want inner.zip listed in error", reports)
		}
		if out := run.done.get(); out[0].Kind != OutcomeFinal {
			t.Errorf("outcome = %v, want OutcomeFinal", out[0].Kind)
		}
	})
	t.Run("as_file with encrypted pass: the member is passed marked encrypted", func(t *testing.T) {
		run := nested(Unanalyzable{Encrypted: PolicyPass, ExtractError: PolicyAsFile})
		reports := run.reportList()
		if len(reports) != 1 || len(reports[0].NotAnalyzedExtractedFiles) != 1 || reports[0].NotAnalyzedExtractedFiles[0].Reason != datamodel.NotAnalyzedEncrypted {
			t.Fatalf("reports = %+v, want inner.zip listed as not analyzed, encrypted", reports)
		}
	})
}

// The type is read once, before the extractor reads the file: bytes rewritten
// while it works do not make the file a plain file after its refusal.
func TestExtractError_theTypeIsReadBeforeTheExtractorNotAfterItsRefusal(t *testing.T) {
	run, archive := scanAnomalyWith(t, Unanalyzable{}, func(location, _ string, _ plugins.ExtractLimits) (plugins.Extraction, error) {
		if err := os.WriteFile(location, []byte("now plain text, no signature at all"), 0o600); err != nil {
			return plugins.Extraction{}, err
		}
		return plugins.Extraction{}, plugins.ErrUnsupportedFormat
	})
	if reports := run.reportList(); len(reports) != 1 || reports[0].Error != errExtractAnomaly.Error() || run.submitted.Load() != 0 {
		t.Fatalf("reports = %+v, submissions %d, want the definitive anomaly and nothing submitted", reports, run.submitted.Load())
	}
	run.assertLeftInPlace(t, archive)
}

// A type that cannot be read counts as an archive when the extractor refuses the
// file: it is never a plain file.
func TestExtractError_aTypeThatCannotBeReadIsNeverAPlainFile(t *testing.T) {
	prev := readProbe
	readProbe = func(io.ReaderAt, []byte) (int, error) { return 0, errors.New("injected read error") }
	t.Cleanup(func() { readProbe = prev })
	run, archive := scanAnomalyWith(t, Unanalyzable{}, refusedAsNotAnArchive)
	if reports := run.reportList(); len(reports) != 1 || reports[0].Error != errExtractAnomaly.Error() || run.submitted.Load() != 0 {
		t.Fatalf("reports = %+v, submissions %d, want the definitive anomaly and nothing submitted", reports, run.submitted.Load())
	}
	run.assertLeftInPlace(t, archive)
}

// Without the extract plugin the built-in extractor refuses what it does not know
// how to open: a valid tar named like data is typed as an archive all the same,
// and its refusal is a failure, not a plain file.
func TestExtractError_theBuiltInExtractorRefusingATypedArchiveIsAnAnomaly(t *testing.T) {
	noOpenInputs(t)
	run := &anomalyRun{done: &outcomes{}}
	prev := ExtractFile
	run.extractorFixture = newExtractorFixture(t, refusedAsNotAnArchive, func(c *Config) { c.OnFileDone = run.done.add })
	ExtractFile = prev
	t.Cleanup(func() { run.conn.Close(context.WithoutCancel(t.Context())) })
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	body := []byte("a member of the tar")
	if err := tw.WriteHeader(&tar.Header{Name: "a.txt", Mode: 0o600, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	ExtractFile = func(string, string, plugins.ExtractLimits) (plugins.Extraction, error) {
		return plugins.Extraction{}, fmt.Errorf("%w: unknown type", plugins.ErrUnsupportedFormat)
	}
	path := filepath.Join(run.src, "data.dat")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run.conn.ScanFile(t.Context(), path); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "the processing to end", func() bool { return len(run.done.get()) == 1 })
	if run.submitted.Load() != 0 {
		t.Error("a typed archive that the extractor refuses was submitted as a plain file")
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("the file must stay in INPUT: %v", err)
	}
}
