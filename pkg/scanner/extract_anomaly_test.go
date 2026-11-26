package scanner

import (
	"archive/tar"
	"archive/zip"
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

	"github.com/gabriel-vasile/mimetype"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	gdetectMock "github.com/glimps-re/go-gdetect/pkg/gdetect/mock"
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

// docxBytes is a zip typed as a word document by its first entries.
func docxBytes(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, name := range []string{"[Content_Types].xml", "_rels/.rels", "word/document.xml"} {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write([]byte("<x/>")); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if got := mimetype.Detect(buf.Bytes()).String(); got != "application/vnd.openxmlformats-officedocument.wordprocessingml.document" {
		t.Fatalf("the sample is typed %s, not as a document", got)
	}
	return buf.Bytes()
}

type familyRun struct {
	*anomalyRun
	checks, extractions atomic.Int32
}

// scanDocument deposits a document and returns once its processing ended; check
// is what the extractor answers to the check of the file.
func scanDocument(t *testing.T, policy Unanalyzable, check func() error) (*familyRun, string) {
	t.Helper()
	return scanDocumentExtraction(t, policy, func() (plugins.Extraction, error) { return plugins.Extraction{}, check() })
}

// scanDocumentExtraction is scanDocument with the whole answer of the extractor.
func scanDocumentExtraction(t *testing.T, policy Unanalyzable, check func() (plugins.Extraction, error), tweak ...func(*Connector)) (*familyRun, string) {
	t.Helper()
	noOpenInputs(t)
	run := &familyRun{anomalyRun: &anomalyRun{done: &outcomes{}}}
	run.extractorFixture = newExtractorFixture(t, func(string, string, plugins.ExtractLimits) (plugins.Extraction, error) {
		return plugins.Extraction{}, errors.New("unexpected extraction")
	}, func(c *Config) {
		c.Unanalyzable = policy
		c.OnFileDone = run.done.add
	})
	ExtractFile = func(_, _ string, limits plugins.ExtractLimits) (plugins.Extraction, error) {
		if !limits.CheckOnly {
			run.extractions.Add(1)
			return plugins.Extraction{}, errors.New("a document must never be extracted")
		}
		run.checks.Add(1)
		return check()
	}
	run.conn.RegisterOnReport(func(r *datamodel.Report) {
		run.mu.Lock()
		run.reports = append(run.reports, r)
		run.mu.Unlock()
	})
	for _, f := range tweak {
		f(run.conn)
	}
	path := filepath.Join(run.src, "report.docx")
	if err := os.WriteFile(path, docxBytes(t), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run.conn.ScanFile(t.Context(), path); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { run.conn.Close(context.WithoutCancel(t.Context())) })
	waitUntil(t, "the processing to end", func() bool { return len(run.done.get()) == 1 })
	return run, path
}

func TestZipFamily_aDocumentIsCheckedOnceAndSubmittedWholeWhenNothingIsWrong(t *testing.T) {
	run, _ := scanDocument(t, Unanalyzable{}, func() error { return nil })
	if run.checks.Load() != 1 || run.extractions.Load() != 0 {
		t.Errorf("checks %d, extractions %d, want one check and no extraction", run.checks.Load(), run.extractions.Load())
	}
	if run.submitted.Load() != 1 {
		t.Errorf("submissions = %d, want the file once, whole", run.submitted.Load())
	}
	if _, err := os.Stat(filepath.Join(run.dst, "report.docx")); err != nil {
		t.Errorf("the document is not in OUTPUT: %v", err)
	}
	if reports := run.reportList(); len(reports) != 1 || reports[0].NotAnalyzedReason != "" || reports[0].Error != "" {
		t.Errorf("reports = %+v, want an ordinary one", reports)
	}
}

func TestZipFamily_whatTheCheckFindsFollowsThePolicies(t *testing.T) {
	encrypted := func() error { return fmt.Errorf("7z: %w", plugins.ErrEncrypted) }
	damaged := func() error {
		return fmt.Errorf("7z: %w: %w", plugins.ErrArchiveAnomaly, plugins.ErrEncryptionPossible)
	}
	structural := func() error { return fmt.Errorf("7z: %w", plugins.ErrArchiveAnomaly) }
	notAnArchive := func() error { return plugins.ErrUnsupportedFormat }
	tests := []struct {
		name   string
		policy Unanalyzable
		check  func() error
		want   string // "kept", "encrypted", "extract-error" or "mitigated"
	}{
		{"encrypted, default", Unanalyzable{}, encrypted, "kept"},
		{"encrypted, pass", Unanalyzable{Encrypted: PolicyPass}, encrypted, "encrypted"},
		{"encrypted, mitigate", Unanalyzable{Encrypted: PolicyMitigate}, encrypted, "mitigated"},
		{"damaged, default", Unanalyzable{Encrypted: PolicyPass}, damaged, "kept"},
		{"damaged, as_file and encrypted pass", Unanalyzable{Encrypted: PolicyPass, ExtractError: PolicyAsFile}, damaged, "encrypted"},
		{"damaged, as_file and encrypted error", Unanalyzable{ExtractError: PolicyAsFile}, damaged, "kept"},
		{"structural, default", Unanalyzable{}, structural, "kept"},
		{"structural, as_file", Unanalyzable{ExtractError: PolicyAsFile}, structural, "extract-error"},
		{"not an archive although typed as a zip, default", Unanalyzable{Encrypted: PolicyPass}, notAnArchive, "kept"},
		{"not an archive although typed as a zip, as_file and encrypted pass", Unanalyzable{Encrypted: PolicyPass, ExtractError: PolicyAsFile}, notAnArchive, "encrypted"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			run, path := scanDocument(t, tt.policy, tt.check)
			reports := run.reportList()
			if len(reports) != 1 {
				t.Fatalf("reports = %+v, want one", reports)
			}
			r := reports[0]
			_, delivered := os.Stat(filepath.Join(run.dst, "report.docx"))
			switch tt.want {
			case "kept":
				if r.Error == "" || delivered == nil {
					t.Errorf("report %+v, delivered %v, want the failure and nothing delivered", r, delivered == nil)
				}
				if _, err := os.Stat(path); err != nil {
					t.Errorf("the document must stay in INPUT: %v", err)
				}
			case "encrypted", "extract-error":
				want := datamodel.NotAnalyzedEncrypted
				if tt.want == "extract-error" {
					want = datamodel.NotAnalyzedExtractError
				}
				if r.NotAnalyzedReason != want || delivered != nil {
					t.Errorf("report %+v, delivered %v, want the document delivered marked %s", r, delivered == nil, want)
				}
			case "mitigated":
				if !r.Malicious || r.MalwareReason != datamodel.Encrypted || delivered == nil {
					t.Errorf("report %+v, want malware encrypted and nothing delivered", r)
				}
			}
			if run.extractions.Load() != 0 {
				t.Error("a document was extracted")
			}
		})
	}
}

// An extractor that is down, a host failure or a timeout is a retry: the document
// is never submitted unchecked.
func TestZipFamily_aCheckThatCouldNotRunIsRetriedAndTheDocumentIsNeverSubmittedUnchecked(t *testing.T) {
	for name, cause := range map[string]error{
		"extractor unavailable": fmt.Errorf("7z: %w", plugins.ErrExtractorUnavailable),
		"timeout":               fmt.Errorf("7z: %w", context.DeadlineExceeded),
		"host failure":          errors.New("the output folder cannot be used"),
	} {
		t.Run(name, func(t *testing.T) {
			run, path := scanDocument(t, Unanalyzable{Encrypted: PolicyPass, ExtractError: PolicyAsFile}, func() error { return cause })
			if run.submitted.Load() != 0 {
				t.Error("the document was submitted although it could not be checked")
			}
			if out := run.done.get(); out[0].Kind == OutcomeFinal {
				t.Errorf("outcome = %v, want a retry", out[0].Kind)
			}
			if _, err := os.Stat(path); err != nil {
				t.Errorf("the document must stay in INPUT: %v", err)
			}
		})
	}
}

// The default extractor reports nothing of a check and writes nothing.
func TestDefaultExtractor_aCheckOnlyReportsNothing(t *testing.T) {
	out := t.TempDir()
	ex, err := ExtractFile(filepath.Join(t.TempDir(), "absent.docx"), out, plugins.ExtractLimits{CheckOnly: true})
	if err != nil || ex.Size != 0 || len(ex.Files) != 0 || len(ex.Skipped) != 0 {
		t.Errorf("ExtractFile(CheckOnly) = %+v, %v, want an empty extraction", ex, err)
	}
	if entries, readErr := os.ReadDir(out); readErr != nil || len(entries) != 0 {
		t.Errorf("the output folder holds %v (%v), want nothing", entries, readErr)
	}
}

// A file whose type cannot be read is sent to the extractor, which tells what it is,
// and handled by what it says: it is never taken for a plain file on the strength of a failed
// read.
func TestZipFamily_aTypeThatCannotBeReadIsCheckedByTheExtractor(t *testing.T) {
	prev := readProbe
	readProbe = func(io.ReaderAt, []byte) (int, error) { return 0, errors.New("injected read error") }
	t.Cleanup(func() { readProbe = prev })
	run, path := scanDocument(t, Unanalyzable{}, func() error { return fmt.Errorf("7z: %w", plugins.ErrEncrypted) })
	if got := run.checks.Load() + run.extractions.Load(); got != 1 {
		t.Errorf("the extractor was asked %d times, want once: a type that cannot be read is not a reason to skip it", got)
	}
	if _, err := os.Stat(filepath.Join(run.dst, "report.docx")); err == nil {
		t.Error("the file was delivered although the check found it encrypted")
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("the file must stay in INPUT: %v", err)
	}
}

// detectType types a file from what it read, and never from bytes read before a
// failure.
func TestDetectType_readResults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "doc.docx")
	if err := os.WriteFile(path, docxBytes(t), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if e := file.Close(); e != nil {
			t.Error(e)
		}
	})
	boom := errors.New("input/output error")
	tests := []struct {
		name     string
		n        int
		err      error
		wantType bool
		wantErr  bool
	}{
		{"bytes and the end of the file", 100, io.EOF, true, false},
		{"bytes and an error", 100, boom, false, true},
		{"nothing and the end of the file", 0, io.EOF, false, false},
		{"nothing and an error", 0, boom, false, true},
	}
	c := policyConnector(t, Unanalyzable{}, 100, cleanSubmitter())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prev := readProbe
			readProbe = func(r io.ReaderAt, p []byte) (int, error) {
				if tt.n > 0 {
					n, _ := r.ReadAt(p, 0)
					return min(n, tt.n), tt.err
				}
				return 0, tt.err
			}
			t.Cleanup(func() { readProbe = prev })
			mtype, typeErr := c.detectType(fileToAnalyze{input: &inputFD{f: file}})
			if (mtype != nil) != tt.wantType || (typeErr != nil) != tt.wantErr {
				t.Errorf("detectType() = %v, %v, want type %t, error %t", mtype, typeErr, tt.wantType, tt.wantErr)
			}
		})
	}
}

// What a file is typed as at the dispatch is what it is handled as: bytes rewritten
// through the descriptor afterwards, before the extractor is asked, change nothing.
func TestTyping_bytesRewrittenAfterTheDispatchDoNotMakeAPlainFile(t *testing.T) {
	rewriteAfterFirstProbe := func(path string) func(io.ReaderAt, []byte) (int, error) {
		reads := 0
		return func(r io.ReaderAt, p []byte) (int, error) {
			n, err := r.ReadAt(p, 0)
			reads++
			if reads == 1 {
				if e := os.WriteFile(path, []byte("now plain text with no signature at all"), 0o600); e != nil {
					panic(e)
				}
			}
			return n, err
		}
	}
	t.Run("a document is still checked", func(t *testing.T) {
		prev := readProbe
		t.Cleanup(func() { readProbe = prev })
		noOpenInputs(t)
		run := &familyRun{anomalyRun: &anomalyRun{done: &outcomes{}}}
		run.extractorFixture = newExtractorFixture(t, func(string, string, plugins.ExtractLimits) (plugins.Extraction, error) {
			return plugins.Extraction{}, errors.New("unexpected")
		}, func(c *Config) { c.OnFileDone = run.done.add })
		ExtractFile = func(_, _ string, limits plugins.ExtractLimits) (plugins.Extraction, error) {
			if limits.CheckOnly {
				run.checks.Add(1)
				return plugins.Extraction{}, fmt.Errorf("7z: %w", plugins.ErrEncrypted)
			}
			run.extractions.Add(1)
			return plugins.Extraction{}, errors.New("a document must never be extracted")
		}
		path := filepath.Join(run.src, "report.docx")
		if err := os.WriteFile(path, docxBytes(t), 0o600); err != nil {
			t.Fatal(err)
		}
		readProbe = rewriteAfterFirstProbe(path)
		if err := run.conn.ScanFile(t.Context(), path); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { run.conn.Close(context.WithoutCancel(t.Context())) })
		waitUntil(t, "the processing to end", func() bool { return len(run.done.get()) == 1 })
		if run.checks.Load() != 1 {
			t.Errorf("checks = %d, want the document checked once although its bytes changed", run.checks.Load())
		}
		if _, err := os.Stat(filepath.Join(run.dst, "report.docx")); err == nil {
			t.Error("the document was delivered")
		}
	})
	t.Run("an archive refused by the extractor is still damaged", func(t *testing.T) {
		prev := readProbe
		t.Cleanup(func() { readProbe = prev })
		noOpenInputs(t)
		run := &anomalyRun{done: &outcomes{}}
		run.extractorFixture = newExtractorFixture(t, refusedAsNotAnArchive, func(c *Config) { c.OnFileDone = run.done.add })
		run.conn.RegisterOnReport(func(r *datamodel.Report) {
			run.mu.Lock()
			run.reports = append(run.reports, r)
			run.mu.Unlock()
		})
		path := run.deposit(t, "a.zip")
		readProbe = rewriteAfterFirstProbe(path)
		if err := run.conn.ScanFile(t.Context(), path); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { run.conn.Close(context.WithoutCancel(t.Context())) })
		waitUntil(t, "the processing to end", func() bool { return len(run.done.get()) == 1 })
		if run.submitted.Load() != 0 {
			t.Error("the archive was submitted as a plain file")
		}
		run.assertLeftInPlace(t, path)
	})
}

// With the extraction off nothing reads the type of a file: it would be a read
// for nothing.
func TestDispatch_theTypeIsNotReadWhenTheExtractionIsOff(t *testing.T) {
	noOpenInputs(t)
	var probes atomic.Int32
	prev := readProbe
	readProbe = func(r io.ReaderAt, p []byte) (int, error) {
		probes.Add(1)
		return r.ReadAt(p, 0)
	}
	t.Cleanup(func() { readProbe = prev })
	run := &anomalyRun{done: &outcomes{}}
	run.extractorFixture = newExtractorFixture(t, refusedAsNotAnArchive, func(c *Config) {
		c.Extract = false
		c.OnFileDone = run.done.add
	})
	t.Cleanup(func() { run.conn.Close(context.WithoutCancel(t.Context())) })
	path := run.deposit(t, "a.zip")
	if err := run.conn.ScanFile(t.Context(), path); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "the processing to end", func() bool { return len(run.done.get()) == 1 })
	if probes.Load() != 0 {
		t.Errorf("the type was read %d times with the extraction off", probes.Load())
	}
}

// A file past the limits of the extraction whose type could not be read is left
// out like an archive, not submitted as a plain file; one that is typed as
// something else is a plain file.
func TestRecursiveExtract_aTypeThatCouldNotBeReadIsLeftOutByTheLimits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "member.bin")
	if err := os.WriteFile(path, []byte("whatever it is"), 0o600); err != nil {
		t.Fatal(err)
	}
	text := mimetype.Detect([]byte("plain text"))
	tests := []struct {
		name string
		file fileToAnalyze
		want bool
	}{
		{"type unreadable", fileToAnalyze{location: path, typeRead: true, typeErr: true}, true},
		{"typed as text", fileToAnalyze{location: path, typeRead: true, mtype: text}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewConnector(Config{Extract: true, WorkDir: t.TempDir(), RecursiveExtractMaxDepth: 1, ExtractMinThreshold: 1}, nil, cleanSubmitter())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { c.Close(context.WithoutCancel(t.Context())) })
			c.analysisChan = make(chan fileToAnalyze, 1)
			var size int64
			var files int
			if err = c.recursiveExtract(tt.file, 1, &size, &files, logger); err != nil {
				t.Fatalf("recursiveExtract() error = %v", err)
			}
			got := <-c.analysisChan
			if got.limitSkipped != tt.want {
				t.Errorf("limitSkipped = %t, want %t", got.limitSkipped, tt.want)
			}
		})
	}
}

// The check of a document is held to what is left of the budget of the extraction,
// not to the whole of it.
func TestCheckZipFamily_isHeldToWhatIsLeftOfTheBudget(t *testing.T) {
	var got plugins.ExtractLimits
	prev := ExtractFile
	ExtractFile = func(_, _ string, limits plugins.ExtractLimits) (plugins.Extraction, error) {
		got = limits
		return plugins.Extraction{}, nil
	}
	t.Cleanup(func() { ExtractFile = prev })
	path := filepath.Join(t.TempDir(), "doc.docx")
	if err := os.WriteFile(path, docxBytes(t), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := NewConnector(Config{Extract: true, WorkDir: t.TempDir(), RecursiveExtractMaxDepth: 3, ExtractMinThreshold: 1, RecursiveExtractMaxFiles: 100, RecursiveExtractMaxSize: 1000}, nil, cleanSubmitter())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(context.WithoutCancel(t.Context())) })
	c.analysisChan = make(chan fileToAnalyze, 1)
	size, files := int64(400), 30
	file := fileToAnalyze{location: path, zipFamily: true, typeRead: true}
	if err = c.recursiveExtract(file, 1, &size, &files, logger); err != nil {
		t.Fatalf("recursiveExtract() error = %v", err)
	}
	if !got.CheckOnly || got.MaxFiles != 70 || got.MaxTotalSize != 600 {
		t.Errorf("limits = %+v, want a check with 70 files and 600 bytes left", got)
	}
	if size != 400 || files != 30 {
		t.Errorf("totals = %d bytes, %d files: a check extracts nothing and uses no budget", size, files)
	}
}

// A document that finds no budget left is not left out: the extractor is asked
// with a budget of nothing, every member being over it, and the document goes on
// as a plain file with its members listed as unchecked. Past the limits (a
// negative remainder: the totals may pass them by what the last archive held) the
// budget is clamped to nothing, as it is with exactly nothing left.
func TestCheckZipFamily_noBudgetLeftAsksForAListingWithABudgetOfNothing(t *testing.T) {
	tests := []struct {
		name      string
		files     int
		size      int64
		wantFiles int
		wantSize  int64
	}{
		{name: "budget left", files: 30, size: 400, wantFiles: 70, wantSize: 600},
		{name: "no file left", files: 100, size: 400, wantSize: 600},
		{name: "files over the limit", files: 130, size: 400},
		{name: "no byte left", files: 30, size: 1000, wantFiles: 70},
		{name: "bytes over the limit", files: 30, size: 1500},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var asked plugins.ExtractLimits
			prev := ExtractFile
			ExtractFile = func(_, _ string, limits plugins.ExtractLimits) (plugins.Extraction, error) {
				asked = limits
				if limits.MaxFiles == 0 || limits.MaxTotalSize == 0 {
					// What the extractor does with a budget of nothing: every member is over it.
					return plugins.Extraction{Skipped: []datamodel.NotAnalyzedFile{{FileName: "m", Reason: datamodel.NotAnalyzedExtractLimit}}, SkippedCount: 1}, nil
				}
				return plugins.Extraction{}, nil
			}
			t.Cleanup(func() { ExtractFile = prev })
			got := checkedDocument(t, tt.files, tt.size)
			if !asked.CheckOnly || asked.MaxFiles != tt.wantFiles || asked.MaxTotalSize != tt.wantSize {
				t.Errorf("limits = %+v, want a check with %d files and %d bytes", asked, tt.wantFiles, tt.wantSize)
			}
			if got.limitSkipped {
				t.Error("a document is never limitSkipped: it is analyzed whole")
			}
			if wantUnchecked := tt.wantFiles == 0 || tt.wantSize == 0; (got.uncheckedCount == 1) != wantUnchecked {
				t.Errorf("uncheckedCount = %d, want unchecked members: %t", got.uncheckedCount, wantUnchecked)
			}
		})
	}
}

// A check that cannot hold every member to the budget does not test the document:
// it goes on whole as a plain file, its members listed as unchecked.
func TestCheckZipFamily_membersLeftOutByTheBudgetAreUncheckedNotAPolicyCase(t *testing.T) {
	prev := ExtractFile
	ExtractFile = func(string, string, plugins.ExtractLimits) (plugins.Extraction, error) {
		return plugins.Extraction{SkippedCount: 3}, nil
	}
	t.Cleanup(func() { ExtractFile = prev })
	got := checkedDocument(t, 0, 0)
	if got.limitSkipped || got.uncheckedCount != 3 || len(got.uncheckedMembers) != 0 {
		t.Errorf("limitSkipped = %t, uncheckedCount = %d, listed = %d, want a plain file with 3 unchecked members", got.limitSkipped, got.uncheckedCount, len(got.uncheckedMembers))
	}
}

// checkedDocument runs the check of a docx with the totals given, against a
// budget of 100 files and 1000 bytes, and returns what was sent to the analysis.
func checkedDocument(t *testing.T, files int, size int64) fileToAnalyze {
	t.Helper()
	path := filepath.Join(t.TempDir(), "doc.docx")
	if err := os.WriteFile(path, docxBytes(t), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := NewConnector(Config{Extract: true, WorkDir: t.TempDir(), RecursiveExtractMaxDepth: 3, ExtractMinThreshold: 1, RecursiveExtractMaxFiles: 100, RecursiveExtractMaxSize: 1000}, nil, cleanSubmitter())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(context.WithoutCancel(t.Context())) })
	c.analysisChan = make(chan fileToAnalyze, 1)
	file := fileToAnalyze{location: path, zipFamily: true, typeRead: true}
	if err = c.recursiveExtract(file, 1, &size, &files, logger); err != nil {
		t.Fatalf("recursiveExtract() error = %v", err)
	}
	return <-c.analysisChan
}

// The check of a document uses what the extractor says was left out, by its count
// or by its list: either is enough.
func TestCheckZipFamily_theListOfMembersLeftOutIsEnoughToLeaveThemUnchecked(t *testing.T) {
	prev := ExtractFile
	member := datamodel.NotAnalyzedFile{FileName: "a", Reason: datamodel.NotAnalyzedExtractLimit}
	ExtractFile = func(string, string, plugins.ExtractLimits) (plugins.Extraction, error) {
		return plugins.Extraction{Skipped: []datamodel.NotAnalyzedFile{member}}, nil
	}
	t.Cleanup(func() { ExtractFile = prev })
	got := checkedDocument(t, 0, 0)
	if got.limitSkipped || got.uncheckedCount != 1 || len(got.uncheckedMembers) != 1 || got.uncheckedMembers[0] != member {
		t.Errorf("file = %+v, want a plain file with its member unchecked", got)
	}
}

// A document over the check limits is analyzed whole, as a plain file: no policy
// applies to its members, and its members are listed as not analyzed.
func TestZipFamily_aDocumentOverTheBudgetIsAnalyzedWholeWhateverThePolicy(t *testing.T) {
	overBudget := func() (plugins.Extraction, error) {
		return plugins.Extraction{
			Skipped:      []datamodel.NotAnalyzedFile{{FileName: "a.xml", Reason: datamodel.NotAnalyzedExtractLimit}, {FileName: "b.xml", Size: 5, Reason: datamodel.NotAnalyzedExtractLimit}},
			SkippedCount: 2,
		}, nil
	}
	for name, policy := range map[string]Unanalyzable{
		"default":               {},
		"error":                 {TooBig: PolicyError, Encrypted: PolicyError},
		"mitigate":              {TooBig: PolicyMitigate, Encrypted: PolicyMitigate},
		"pass":                  {TooBig: PolicyPass, Encrypted: PolicyPass},
		"too_big mitigate only": {TooBig: PolicyMitigate, Encrypted: PolicyPass},
	} {
		t.Run(name, func(t *testing.T) {
			run, _ := scanDocumentExtraction(t, policy, overBudget)
			reports := run.reportList()
			if len(reports) != 1 {
				t.Fatalf("reports = %+v, want one", reports)
			}
			r := reports[0]
			if _, err := os.Stat(filepath.Join(run.dst, "report.docx")); err != nil {
				t.Errorf("the document is not in OUTPUT: %v", err)
			}
			if r.Error != "" || r.Malicious || r.NotAnalyzedReason != "" {
				t.Errorf("report %+v, want an analyzed document", r)
			}
			if r.NotAnalyzedExtractedCount != 2 || len(r.NotAnalyzedExtractedFiles) != 2 || r.NotAnalyzedExtractedFiles[0].Reason != datamodel.NotAnalyzedExtractLimit {
				t.Errorf("not analyzed members = %d %+v, want the 2 members, extract-limit", r.NotAnalyzedExtractedCount, r.NotAnalyzedExtractedFiles)
			}
			if r.FilteredVolume != 0 {
				t.Errorf("filtered volume = %d, want nothing: the document was analyzed whole", r.FilteredVolume)
			}
			if run.submitted.Load() != 1 || run.extractions.Load() != 0 {
				t.Errorf("submissions = %d, extractions = %d, want the document submitted once, never extracted", run.submitted.Load(), run.extractions.Load())
			}
		})
	}
}

// What the analysis says of the document still decides: a detection quarantines
// it, an analysis error follows analysis_error, the members are listed only for a
// document that goes through.
func TestZipFamily_aDocumentOverTheBudgetStillFollowsItsVerdict(t *testing.T) {
	overBudget := func() (plugins.Extraction, error) { return plugins.Extraction{SkippedCount: 2}, nil }
	tests := []struct {
		name          string
		verdict       gdetect.Result
		wantMalicious bool
		wantError     bool
	}{
		{"a detection", gdetect.Result{Malware: true, Malwares: []string{"m"}}, true, false},
		{"an analysis error", gdetect.Result{Error: "engine failed"}, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			run, _ := scanDocumentExtraction(t, Unanalyzable{}, overBudget, func(c *Connector) {
				c.submitter = echoReader(&gdetectMock.MockGDetectSubmitter{
					ExtractExpertViewURLMock: func(*gdetect.Result) (string, error) { return "", nil },
					WaitForFileMock: func(context.Context, string, gdetect.WaitForOptions) (gdetect.Result, error) {
						return tt.verdict, nil
					},
				})
			})
			reports := run.reportList()
			if len(reports) != 1 {
				t.Fatalf("reports = %+v, want one", reports)
			}
			r := reports[0]
			if _, err := os.Stat(filepath.Join(run.dst, "report.docx")); err == nil {
				t.Error("the document must not be delivered")
			}
			if r.Malicious != tt.wantMalicious || (r.Error != "") != tt.wantError {
				t.Errorf("report %+v, want malicious %t, error %t", r, tt.wantMalicious, tt.wantError)
			}
			if r.NotAnalyzedExtractedCount != 0 {
				t.Errorf("a document that is not delivered lists %d unchecked members, want none", r.NotAnalyzedExtractedCount)
			}
		})
	}
}
