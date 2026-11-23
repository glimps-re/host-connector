//go:build linux

package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	gdetectMock "github.com/glimps-re/go-gdetect/pkg/gdetect/mock"
	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
	"github.com/glimps-re/host-connector/pkg/quarantine"
	"github.com/glimps-re/host-connector/pkg/scanner"
)

type t17Capture struct {
	src    scanner.Source
	result datamodel.Result
	report datamodel.Report
}

type t17Run struct {
	in, out, qdir string
	captures      []t17Capture
	submitted     []string
	scanErr       error
}

// maybe is for the cases where the contract allows the pipeline to stop before
// the actions (a definitive error: the archive stays in INPUT).
func (r *t17Run) maybe(name string) (t17Capture, bool) {
	for _, c := range r.captures {
		if filepath.Base(c.src.Path) == name {
			return c, true
		}
	}
	return t17Capture{}, false
}

func (r *t17Run) one(t *testing.T, name string) t17Capture {
	t.Helper()
	var got []t17Capture
	for _, c := range r.captures {
		if filepath.Base(c.src.Path) == name {
			got = append(got, c)
		}
	}
	if len(got) != 1 {
		t.Fatalf("the actions ran %d time(s) for %s, want once", len(got), name)
	}
	return got[0]
}

func (r *t17Run) exists(dir, name string) bool {
	_, err := os.Lstat(filepath.Join(dir, name))
	return err == nil
}

func (r *t17Run) quarantined(t *testing.T) int {
	t.Helper()
	locks, err := filepath.Glob(filepath.Join(r.qdir, "*.lock"))
	if err != nil {
		t.Fatal(err)
	}
	return len(locks)
}

func (r *t17Run) submissionsOf(name string) int {
	n := 0
	for _, s := range r.submitted {
		if s == name {
			n++
		}
	}
	return n
}

type t17Setup struct {
	policy      scanner.Unanalyzable
	name        string
	content     []byte
	maxFileSize int64
	maxFiles    int
	maxTotal    int64
	malwareFor  string // base name of the submitted file the service calls malware
}

// runT17 runs the real pipeline with the real extraction plugin and the real
// 7-Zip on one deposited archive.
func runT17(t *testing.T, s t17Setup) *t17Run {
	t.Helper()
	plugin := realPlugin(t)
	plugin.sze.config = extractorConfig{DefaultPasswords: []string{"infected"}}
	root := t.TempDir()
	r := &t17Run{in: filepath.Join(root, "in"), out: filepath.Join(root, "out"), qdir: t.TempDir()}
	for _, d := range []string{r.in, r.out} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	q, err := quarantine.NewQuarantineHandler(t.Context(), quarantine.Config{Location: r.qdir, LockPassword: "infected"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if e := q.Close(); e != nil {
			t.Errorf("Close() error = %v", e)
		}
	})
	prev := scanner.ExtractFile
	t.Cleanup(func() { scanner.ExtractFile = prev })
	scanner.ExtractFile = plugin.ExtractFile

	var mu sync.Mutex
	record := func(name, sum string) gdetect.Result {
		mu.Lock()
		r.submitted = append(r.submitted, filepath.Base(name))
		mu.Unlock()
		res := gdetect.Result{SHA256: sum, Done: true}
		if s.malwareFor != "" && filepath.Base(name) == s.malwareFor {
			res.Malware, res.Malwares = true, []string{"evil"}
		}
		return res
	}
	type pending struct {
		rd   io.Reader
		opts gdetect.SubmitOptions
	}
	subs := map[string]pending{}
	submitter := &gdetectMock.MockGDetectSubmitter{
		ExtractExpertViewURLMock: func(*gdetect.Result) (string, error) { return "", nil },
		WaitForFileMock: func(_ context.Context, path string, _ gdetect.WaitForOptions) (gdetect.Result, error) {
			b, e := os.ReadFile(filepath.Clean(path))
			if e != nil {
				return gdetect.Result{}, e
			}
			sum := sha256.Sum256(b)
			return record(path, hex.EncodeToString(sum[:])), nil
		},
		GetResultBySHA256Mock: func(context.Context, string) (gdetect.Result, error) {
			return gdetect.Result{}, gdetect.HTTPError{Code: http.StatusNotFound}
		},
		SubmitReaderMock: func(_ context.Context, rd io.Reader, opts gdetect.SubmitOptions) (string, error) {
			mu.Lock()
			defer mu.Unlock()
			id := fmt.Sprintf("uuid-%d", len(subs))
			subs[id] = pending{rd, opts}
			return id, nil
		},
		GetResultByUUIDWithWaitMock: func(_ context.Context, id string, _ int) (gdetect.Result, error) {
			mu.Lock()
			sub := subs[id]
			mu.Unlock()
			h := sha256.New()
			if _, e := io.Copy(h, sub.rd); e != nil {
				return gdetect.Result{}, e
			}
			return record(sub.opts.Filename, hex.EncodeToString(h.Sum(nil))), nil
		},
	}
	maxFileSize := s.maxFileSize
	if maxFileSize == 0 {
		maxFileSize = 1 << 20
	}
	maxFiles := s.maxFiles
	if maxFiles == 0 {
		maxFiles = 100
	}
	maxTotal := s.maxTotal
	if maxTotal == 0 {
		maxTotal = 1 << 30
	}
	capture := &scanner.MockAction{HandleMock: func(_ context.Context, src scanner.Source, res datamodel.Result, rep *datamodel.Report) error {
		mu.Lock()
		defer mu.Unlock()
		r.captures = append(r.captures, t17Capture{src, res, *rep})
		return nil
	}}
	c, err := scanner.NewConnector(scanner.Config{
		Roots: []string{r.in}, WorkDir: t.TempDir(), Workers: 2, ExtractWorkers: 1,
		Extract: true, ExtractMinThreshold: 1, MaxFileSize: maxFileSize,
		RecursiveExtractMaxDepth: 3, RecursiveExtractMaxSize: maxTotal, RecursiveExtractMaxFiles: maxFiles,
		Unanalyzable: s.policy,
		Actions:      scanner.Actions{Move: true, Quarantine: true},
		MoveFrom:     r.in, MoveTo: r.out, MoveMode: scanner.MoveModeCopy,
		CustomActions: []scanner.Action{capture},
	}, q, submitter)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Start(); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(r.in, s.name)
	if err = os.WriteFile(p, s.content, 0o600); err != nil {
		t.Fatal(err)
	}
	r.scanErr = c.ScanFile(t.Context(), p)
	c.Close(t.Context())
	return r
}

func t17Fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(fixture(t, filepath.Join("t17a", name)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func t17Zip(t *testing.T, members map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for n, c := range members {
		w, err := zw.Create(n)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write(c); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

var t17Policies = []string{scanner.PolicyError, scanner.PolicyPass, scanner.PolicyMitigate}

// An archive that 7-Zip cannot open without a password follows the encrypted
// policy: never analyzed as a plain file and delivered as clean.
func TestT17a_realEncryptedArchivesFollowTheEncryptedPolicy(t *testing.T) {
	for _, fx := range []string{"enc_zipcrypto.zip", "enc_aes.zip", "enc_headers.7z", "enc_content.7z", "mixed.zip"} {
		for _, policy := range t17Policies {
			t.Run(fx+"/"+policy, func(t *testing.T) {
				r := runT17(t, t17Setup{policy: scanner.Unanalyzable{Encrypted: policy}, name: fx, content: t17Fixture(t, fx)})
				got, ran := r.maybe(fx)
				if policy == scanner.PolicyError && !ran {
					if !r.exists(r.in, fx) || r.exists(r.out, fx) || r.quarantined(t) != 0 {
						t.Error("an encrypted archive under error must stay in INPUT")
					}
					return
				}
				if !ran {
					t.Fatalf("the actions never ran for %s under %s: the archive is neither delivered, marked nor quarantined", fx, policy)
				}
				if got.src.TooBig {
					t.Error("Source.TooBig = true for an archive under max_file_size")
				}
				res := got.result
				switch policy {
				case scanner.PolicyError:
					if res.Error == nil || res.Malware || res.NotAnalyzedReason != "" {
						t.Errorf("result = error %v malware %v reason %q, want an error only", res.Error, res.Malware, res.NotAnalyzedReason)
					}
					if got.report.Error == "" {
						t.Error("Report.Error is empty: the failure must be visible")
					}
					if !r.exists(r.in, fx) || r.exists(r.out, fx) || r.quarantined(t) != 0 {
						t.Error("an encrypted archive under error must stay in INPUT")
					}
				case scanner.PolicyPass:
					if res.Error != nil || res.Malware || res.NotAnalyzedReason != datamodel.NotAnalyzedEncrypted {
						t.Errorf("result = error %v malware %v reason %q, want pass marked encrypted", res.Error, res.Malware, res.NotAnalyzedReason)
					}
					if got.report.NotAnalyzedReason != datamodel.NotAnalyzedEncrypted {
						t.Errorf("Report.NotAnalyzedReason = %q", got.report.NotAnalyzedReason)
					}
					if !r.exists(r.out, fx) || r.quarantined(t) != 0 {
						t.Error("pass: the archive must be delivered to OUTPUT")
					}
				case scanner.PolicyMitigate:
					if res.Error != nil || !res.Malware || res.MalwareReason != datamodel.Encrypted {
						t.Errorf("result = error %v malware %v reason %q, want mitigated as encrypted", res.Error, res.Malware, res.MalwareReason)
					}
					if r.quarantined(t) != 1 || r.exists(r.out, fx) {
						t.Error("mitigate: the archive must be quarantined, not delivered")
					}
				}
				if res.Error == nil && !res.Malware && res.NotAnalyzedReason == "" {
					t.Errorf("an encrypted archive ended as clean: %+v", res)
				}
			})
		}
	}
}

// A verdict of the service on the encrypted container wins over the policy.
func TestT17a_realEncryptedArchiveMaliciousVerdictWins(t *testing.T) {
	for _, policy := range t17Policies {
		t.Run(policy, func(t *testing.T) {
			r := runT17(t, t17Setup{policy: scanner.Unanalyzable{Encrypted: policy}, name: "enc.zip", content: t17Fixture(t, "enc_zipcrypto.zip"), malwareFor: "enc.zip"})
			got := r.one(t, "enc.zip")
			if !got.result.Malware || got.result.MalwareReason != datamodel.MalwareDetected || got.result.Error != nil {
				t.Errorf("result = %+v, want the detection whatever the policy", got.result)
			}
			if r.quarantined(t) != 1 || r.exists(r.out, "enc.zip") {
				t.Error("a detected container must be quarantined")
			}
		})
	}
}

// An encrypted archive over max_file_size is not submitted, same policy, and
// the pipeline's decision sets Source.TooBig.
func TestT17a_realEncryptedArchiveOverMaxFileSizeIsNotSubmitted(t *testing.T) {
	content := t17Fixture(t, "enc_zipcrypto.zip")
	for _, policy := range t17Policies {
		t.Run(policy, func(t *testing.T) {
			r := runT17(t, t17Setup{policy: scanner.Unanalyzable{Encrypted: policy, TooBig: scanner.PolicyError}, name: "enc.zip", content: content, maxFileSize: int64(len(content)) - 1})
			got := r.one(t, "enc.zip")
			if len(r.submitted) != 0 {
				t.Errorf("submitted %v: a file over max_file_size is never submitted", r.submitted)
			}
			if !got.src.TooBig {
				t.Error("Source.TooBig = false: an encrypted archive over the limit is not analyzed")
			}
			switch policy {
			case scanner.PolicyError:
				if got.result.Error == nil || !r.exists(r.in, "enc.zip") {
					t.Errorf("error: result %+v, want a failure and the archive in INPUT", got.result)
				}
			case scanner.PolicyPass:
				if got.result.NotAnalyzedReason != datamodel.NotAnalyzedEncrypted || !r.exists(r.out, "enc.zip") {
					t.Errorf("pass: reason %q, want encrypted and delivered", got.result.NotAnalyzedReason)
				}
			case scanner.PolicyMitigate:
				if !got.result.Malware || got.result.MalwareReason != datamodel.Encrypted || r.quarantined(t) != 1 {
					t.Errorf("mitigate: %+v, want quarantined as encrypted", got.result)
				}
			}
		})
	}
}

// An encrypted archive nested in a plain zip: the member follows the policy,
// the other members are analyzed.
func TestT17a_realEncryptedArchiveNestedInAPlainZip(t *testing.T) {
	for _, policy := range t17Policies {
		t.Run(policy, func(t *testing.T) {
			r := runT17(t, t17Setup{policy: scanner.Unanalyzable{Encrypted: policy}, name: "n.zip", content: t17Fixture(t, "nested_in_plain.zip")})
			got := r.one(t, "n.zip")
			res := got.result
			if r.submissionsOf("p.txt") != 1 {
				t.Errorf("submitted %v, want the plain member p.txt analyzed once", r.submitted)
			}
			switch policy {
			case scanner.PolicyError:
				if res.Error == nil || !r.exists(r.in, "n.zip") || r.exists(r.out, "n.zip") || r.quarantined(t) != 0 {
					t.Errorf("error: %+v, want a failure and the archive left in INPUT", res)
				}
				if got.report.Error == "" {
					t.Error("Report.Error is empty")
				}
			case scanner.PolicyPass:
				if res.Error != nil || res.Malware || res.NotAnalyzedSubfilesCount != 1 || len(res.NotAnalyzedSubfiles) != 1 {
					t.Fatalf("pass: %+v, want exactly one not-analyzed member", res)
				}
				m := res.NotAnalyzedSubfiles[0]
				if m.Reason != datamodel.NotAnalyzedEncrypted || !strings.Contains(m.FileName, "inner.zip") {
					t.Errorf("member = %+v, want inner.zip encrypted", m)
				}
				if got.report.NotAnalyzedExtractedCount != 1 || len(got.report.NotAnalyzedExtractedFiles) != 1 {
					t.Errorf("report lists %d (count %d), want 1", len(got.report.NotAnalyzedExtractedFiles), got.report.NotAnalyzedExtractedCount)
				}
				if !r.exists(r.out, "n.zip") {
					t.Error("pass: the archive must be delivered")
				}
			case scanner.PolicyMitigate:
				if !res.Malware || r.quarantined(t) != 1 || r.exists(r.out, "n.zip") {
					t.Fatalf("mitigate: %+v, want the archive quarantined", res)
				}
				found := false
				for name, sub := range res.MaliciousSubfiles {
					found = found || (strings.Contains(name, "inner.zip") && sub.MalwareReason == datamodel.Encrypted)
				}
				if !found {
					t.Errorf("MaliciousSubfiles = %v, want inner.zip as encrypted", res.MaliciousSubfiles)
				}
			}
		})
	}
}

// A password the plugin knows opens the archive normally.
func TestT17a_realKnownPasswordIsExtractedNormally(t *testing.T) {
	for _, policy := range t17Policies {
		t.Run(policy, func(t *testing.T) {
			r := runT17(t, t17Setup{policy: scanner.Unanalyzable{Encrypted: policy, TooBig: policy}, name: "k.zip", content: t17Fixture(t, "known_password.zip")})
			got := r.one(t, "k.zip")
			if got.result.Error != nil || got.result.Malware || got.result.NotAnalyzedReason != "" || got.result.NotAnalyzedSubfilesCount != 0 || got.src.TooBig {
				t.Errorf("result = %+v, want a clean archive", got.result)
			}
			if r.submissionsOf("a.txt") != 1 || !r.exists(r.out, "k.zip") {
				t.Errorf("submitted %v, delivered %v, want the member analyzed and the archive delivered", r.submitted, r.exists(r.out, "k.zip"))
			}
		})
	}
}

// Members the plugin leaves out (over max_file_size, over the number of files,
// over the total size) follow too_big, with exact counts.
func TestT17a_realMembersLeftOutFollowTooBig(t *testing.T) {
	zeros := bytes.Repeat([]byte{0}, 5000)
	manyTiny := func(n int) map[string][]byte {
		m := make(map[string][]byte, n)
		for i := range n {
			m[fmt.Sprintf("m%04d.txt", i)] = []byte("tiny")
		}
		return m
	}
	tests := []struct {
		name        string
		members     map[string][]byte
		maxFileSize int64
		maxFiles    int
		maxTotal    int64
		wantSkipped int
		wantListed  int
		wantSubmit  int
	}{
		{"members over max_file_size", map[string][]byte{"s1.txt": []byte("one"), "s2.txt": []byte("two"), "big1.bin": zeros, "big2.bin": zeros, "big3.bin": zeros}, 1000, 0, 0, 3, 3, 2},
		{"more members than the count limit", manyTiny(10), 0, 4, 0, 6, 6, 4},
		{"over the total size", map[string][]byte{"a.bin": bytes.Repeat([]byte("a"), 300), "b.bin": bytes.Repeat([]byte("b"), 300), "c.bin": bytes.Repeat([]byte("c"), 300)}, 0, 0, 400, 2, 2, 1},
		{"1500 members for a budget of 10", manyTiny(1500), 0, 10, 0, 1490, datamodel.MaxListedSubfiles, 10},
	}
	for _, tt := range tests {
		for _, policy := range t17Policies {
			t.Run(tt.name+"/"+policy, func(t *testing.T) {
				content := t17Zip(t, tt.members)
				maxFileSize := tt.maxFileSize
				if maxFileSize == 0 {
					maxFileSize = 1 << 20
				}
				if int64(len(content)) > maxFileSize {
					t.Fatalf("test archive is %d bytes, must stay under max_file_size %d", len(content), maxFileSize)
				}
				r := runT17(t, t17Setup{policy: scanner.Unanalyzable{TooBig: policy}, name: "a.zip", content: content, maxFileSize: tt.maxFileSize, maxFiles: tt.maxFiles, maxTotal: tt.maxTotal})
				got, ran := r.maybe("a.zip")
				if policy == scanner.PolicyError && !ran {
					if !r.exists(r.in, "a.zip") || r.exists(r.out, "a.zip") || r.quarantined(t) != 0 {
						t.Error("error: the archive must stay in INPUT")
					}
					return
				}
				if !ran {
					t.Fatalf("the actions never ran under %s", policy)
				}
				res := got.result
				if got.src.TooBig {
					t.Error("Source.TooBig = true for an extracted archive")
				}
				if res.Error == nil && !res.Malware && res.NotAnalyzedSubfilesCount != tt.wantSkipped {
					t.Errorf("NotAnalyzedSubfilesCount = %d, want the exact %d", res.NotAnalyzedSubfilesCount, tt.wantSkipped)
				}
				switch policy {
				case scanner.PolicyError:
					if res.Error == nil || !r.exists(r.in, "a.zip") || r.exists(r.out, "a.zip") || r.quarantined(t) != 0 {
						t.Errorf("error: %+v, want a failure and the archive left in INPUT", res)
					}
					if got.report.Error == "" {
						t.Error("Report.Error is empty")
					}
				case scanner.PolicyPass:
					if res.Error != nil || res.Malware {
						t.Fatalf("pass: %+v", res)
					}
					if len(res.NotAnalyzedSubfiles) != tt.wantListed {
						t.Errorf("listed %d, want %d", len(res.NotAnalyzedSubfiles), tt.wantListed)
					}
					for _, f := range res.NotAnalyzedSubfiles {
						if f.Reason != datamodel.NotAnalyzedExtractLimit && f.Reason != datamodel.NotAnalyzedTooBig {
							t.Errorf("member %+v: reason must be extract-limit or too-big", f)
						}
					}
					if got.report.NotAnalyzedExtractedCount != tt.wantSkipped || len(got.report.NotAnalyzedExtractedFiles) != tt.wantListed {
						t.Errorf("report: %d listed, count %d; want %d, %d", len(got.report.NotAnalyzedExtractedFiles), got.report.NotAnalyzedExtractedCount, tt.wantListed, tt.wantSkipped)
					}
					if !r.exists(r.out, "a.zip") {
						t.Error("pass: the archive must be delivered")
					}
					if n := len(r.submitted); n != tt.wantSubmit {
						t.Errorf("%d member(s) analyzed (%v), want %d", n, r.submitted, tt.wantSubmit)
					}
				case scanner.PolicyMitigate:
					if !res.Malware || res.Error != nil || r.quarantined(t) != 1 || r.exists(r.out, "a.zip") {
						t.Errorf("mitigate: %+v, want the archive quarantined", res)
					}
				}
			})
		}
	}
}

// Whatever the encryption (ZipCrypto, AES, 7z with encrypted headers or only
// encrypted content), the real plugin tells ErrEncrypted, never a generic
// extraction error: the core's encrypted policy depends on it.
func TestT17a_realPluginReportsEncryptedArchives(t *testing.T) {
	for _, fx := range []string{"enc_zipcrypto.zip", "enc_aes.zip", "enc_headers.7z", "enc_content.7z", "mixed.zip"} {
		t.Run(fx, func(t *testing.T) {
			plugin := realPlugin(t)
			plugin.sze.config = extractorConfig{DefaultPasswords: []string{"infected"}}
			_, err := plugin.ExtractFile(fixture(t, filepath.Join("t17a", fx)), t.TempDir(), openLimits)
			if !errors.Is(err, plugins.ErrEncrypted) {
				t.Errorf("ExtractFile() error = %v, want plugins.ErrEncrypted", err)
			}
		})
	}
}
