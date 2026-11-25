//go:build linux

package main

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gabriel-vasile/mimetype"
	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
	"github.com/glimps-re/host-connector/pkg/scanner"
)

// packageZip is a zip laid out as a document or a package: its first entries are
// the ones the connector types it from.
func packageZip(t *testing.T, kind string) []byte {
	t.Helper()
	entries := map[string][]string{
		"docx": {"[Content_Types].xml", "_rels/.rels", "word/document.xml"},
		"xlsx": {"[Content_Types].xml", "_rels/.rels", "xl/workbook.xml"},
		"pptx": {"[Content_Types].xml", "_rels/.rels", "ppt/presentation.xml"},
		"jar":  {"META-INF/MANIFEST.MF", "com/example/Main.class"},
		"apk":  {"AndroidManifest.xml", "classes.dex", "res/layout/main.xml"},
		"epub": {"mimetype", "META-INF/container.xml", "content.opf"},
		"odt":  {"mimetype", "content.xml", "META-INF/manifest.xml"},
	}[kind]
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, name := range entries {
		content := "plain content of " + name
		switch name {
		case "mimetype":
			content = map[string]string{"epub": "application/epub+zip", "odt": "application/vnd.oasis.opendocument.text"}[kind]
		case "[Content_Types].xml":
			content = `<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>`
		}
		w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// withEncryptedMember adds a member encrypted with an unknown password to a zip,
// after its first entries: the 7-Zip update keeps them where they are.
func withEncryptedMember(t *testing.T, zipBytes []byte, method string) []byte {
	t.Helper()
	return withMemberPassword(t, zipBytes, method, "wrong-pw-1")
}

func withMemberPassword(t *testing.T, zipBytes []byte, method, password string) []byte {
	t.Helper()
	plugin := realPlugin(t)
	dir := t.TempDir()
	archive := filepath.Join(dir, "p.zip")
	if err := os.WriteFile(archive, zipBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(secret, []byte("an encrypted member"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := runCmd(t.Context(), plugin.sze.sevenZipPath, "a", "-tzip", "-mem="+method, "-p"+password, archive, secret); err != nil {
		t.Fatalf("cannot add the member: %v %s", err, out)
	}
	b, err := os.ReadFile(filepath.Clean(archive))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// typedAs checks what the connector types a file as: the family is the one the
// test means, and it is not one of the types to extract.
func typedAs(t *testing.T, content []byte, want string) {
	t.Helper()
	got := mimetype.Detect(content).String()
	if want != "" && got != want {
		t.Fatalf("the sample is typed %s, want %s", got, want)
	}
	if got == "application/zip" {
		t.Fatalf("the sample is typed as a plain zip: it does not test the zip family")
	}
}

var familyTypes = map[string]string{
	"docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
	"xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
	"pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
	"jar":  "application/java-archive",
	"apk":  "application/vnd.android.package-archive",
	"epub": "application/epub+zip",
	"odt":  "application/vnd.oasis.opendocument.text",
}

// An encrypted member of a zip-family file does not escape the policy of the
// encrypted files because the file is typed as a document.
func TestZipFamily_anEncryptedMemberOfAZipFamilyFileFollowsTheEncryptedPolicy(t *testing.T) {
	for _, kind := range []string{"docx", "jar", "apk"} {
		for _, method := range []string{"AES256", "ZipCrypto"} {
			name := "doc." + kind
			content := func(t *testing.T) []byte {
				b := withEncryptedMember(t, packageZip(t, kind), method)
				typedAs(t, b, familyTypes[kind])
				return b
			}
			t.Run(kind+"/"+method+"/default", func(t *testing.T) {
				r := runPipeline(t, pipelineSetup{name: name, content: content(t)})
				notDelivered(t, r, name)
				if r.submissionsOf("secret.txt") != 0 {
					t.Error("a member was extracted and submitted: the file is only checked")
				}
			})
			if kind != "docx" {
				continue // the policies are the same whatever the family: one kind is enough
			}
			t.Run(kind+"/"+method+"/pass", func(t *testing.T) {
				r := runPipeline(t, pipelineSetup{policy: scanner.Unanalyzable{Encrypted: scanner.PolicyPass}, name: name, content: content(t)})
				got := r.one(t, name)
				if got.result.NotAnalyzedReason != datamodel.NotAnalyzedEncrypted || got.report.NotAnalyzedReason != datamodel.NotAnalyzedEncrypted {
					t.Errorf("reason = %q, want the file submitted whole and marked encrypted", got.result.NotAnalyzedReason)
				}
				if r.submissionsOf(name) != 1 || r.submissionsOf("secret.txt") != 0 {
					t.Errorf("submitted %v, want the file once, whole", r.submitted)
				}
			})
			t.Run(kind+"/"+method+"/mitigate", func(t *testing.T) {
				r := runPipeline(t, pipelineSetup{policy: scanner.Unanalyzable{Encrypted: scanner.PolicyMitigate}, name: name, content: content(t)})
				got := r.one(t, name)
				if !got.result.Malware || got.result.MalwareReason != datamodel.Encrypted {
					t.Errorf("result = %+v, want malware encrypted", got.result)
				}
			})
		}
	}
}

// Legitimate documents and packages are submitted whole, as before: no extraction,
// no new mark.
func TestZipFamily_legitimateZipFamilyFilesAreUnchanged(t *testing.T) {
	for kind, mime := range familyTypes {
		t.Run(kind, func(t *testing.T) {
			content := packageZip(t, kind)
			typedAs(t, content, mime)
			name := "legit." + kind
			r := runPipeline(t, pipelineSetup{name: name, content: content})
			got := r.one(t, name)
			if got.result.Error != nil || got.result.Malware || got.result.NotAnalyzedReason != "" {
				t.Errorf("result = %+v, want an ordinary file", got.result)
			}
			if !r.exists(r.out, name) {
				t.Error("the file must be delivered")
			}
			if len(r.submitted) != 1 || r.submitted[0] != name {
				t.Errorf("submitted %v, want the file alone, whole", r.submitted)
			}
		})
	}
}

// The integrity test catches an encryption that the listing hides: the flag of
// the local headers cleared.
func TestZipFamily_theLocalHeaderBitTrickIsCaughtByTheIntegrityTest(t *testing.T) {
	content := clearLocalEncryptionBit(t, withEncryptedMember(t, packageZip(t, "docx"), "ZipCrypto"))
	typedAs(t, content, familyTypes["docx"])
	r := runPipeline(t, pipelineSetup{name: "trick.docx", content: content})
	notDelivered(t, r, "trick.docx")
}

// A document cut short is typed as a document and 7-Zip cannot open it: a
// definitive failure, never submitted.
func TestZipFamily_aTruncatedDocumentIsNotSubmitted(t *testing.T) {
	full := packageZip(t, "docx")
	cut := full[:len(full)*3/4]
	typedAs(t, cut, familyTypes["docx"])
	r := runPipeline(t, pipelineSetup{name: "cut.docx", content: cut})
	notDelivered(t, r, "cut.docx")
	r = runPipeline(t, pipelineSetup{policy: scanner.Unanalyzable{Encrypted: scanner.PolicyPass, ExtractError: scanner.PolicyAsFile}, name: "cut.docx", content: cut})
	got, ran := r.maybe("cut.docx")
	if !ran || got.result.NotAnalyzedReason != datamodel.NotAnalyzedEncrypted {
		t.Errorf("under {pass, as_file}: reason = %q (ran %v), want marked encrypted", got.result.NotAnalyzedReason, ran)
	}
}

// A zip-family file nested in a zip or in a 7z follows the same rules as a member.
func TestZipFamily_aZipFamilyFileNestedInAnArchiveFollowsTheSameRules(t *testing.T) {
	inner := withEncryptedMember(t, packageZip(t, "docx"), "AES256")
	typedAs(t, inner, familyTypes["docx"])
	plugin := realPlugin(t)
	outer := func(t *testing.T, format string) []byte {
		dir := t.TempDir()
		src := filepath.Join(dir, "inner.docx")
		if err := os.WriteFile(src, inner, 0o600); err != nil {
			t.Fatal(err)
		}
		archive := filepath.Join(dir, "outer."+format)
		if out, err := runCmd(t.Context(), plugin.sze.sevenZipPath, "a", "-t"+format, archive, src); err != nil {
			t.Fatalf("cannot build the archive: %v %s", err, out)
		}
		b, err := os.ReadFile(filepath.Clean(archive))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for _, format := range []string{"zip", "7z"} {
		name := "outer." + format
		t.Run(format+"/default", func(t *testing.T) {
			r := runPipeline(t, pipelineSetup{name: name, content: outer(t, format)})
			notDelivered(t, r, name)
		})
		t.Run(format+"/pass", func(t *testing.T) {
			r := runPipeline(t, pipelineSetup{policy: scanner.Unanalyzable{Encrypted: scanner.PolicyPass}, name: name, content: outer(t, format)})
			got := r.one(t, name)
			if len(got.report.NotAnalyzedExtractedFiles) != 1 || got.report.NotAnalyzedExtractedFiles[0].Reason != datamodel.NotAnalyzedEncrypted {
				t.Errorf("report = %+v, want inner.docx listed as not analyzed, encrypted", got.report.NotAnalyzedExtractedFiles)
			}
		})
	}
}

// BenchmarkCheckOnly measures the check of a package of stored media (read once,
// nothing written); the sizes are those of a large presentation and a large jar:
//
//	go test ./cmd/plugins/extract -run '^$' -bench BenchmarkCheckOnly -benchtime 3x
func BenchmarkCheckOnly(b *testing.B) {
	for _, mib := range []int{200, 1024} {
		b.Run(fmt.Sprintf("%dMiB", mib), func(b *testing.B) {
			sze := realSevenZipForBench(b)
			path := filepath.Join(b.TempDir(), "big.pptx")
			size := writeStoredPackage(b, path, mib)
			limits := plugins.ExtractLimits{MaxFiles: 1000, MaxTotalSize: 1 << 40, CheckOnly: true}
			b.SetBytes(size)
			for b.Loop() {
				if _, err := sze.checkOnly(b.Context(), path, limits); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// writeStoredPackage streams a zip typed as a presentation, holding mib MiB of
// stored media, into path, and returns its size.
func writeStoredPackage(b *testing.B, path string, mib int) int64 {
	b.Helper()
	f, err := os.Create(filepath.Clean(path))
	if err != nil {
		b.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for _, name := range []string{"[Content_Types].xml", "_rels/.rels", "ppt/presentation.xml"} {
		w, werr := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
		if werr != nil {
			b.Fatal(werr)
		}
		if _, werr = w.Write([]byte("<x/>")); werr != nil {
			b.Fatal(werr)
		}
	}
	w, err := zw.CreateHeader(&zip.FileHeader{Name: "ppt/media/video.bin", Method: zip.Store})
	if err != nil {
		b.Fatal(err)
	}
	chunk := bytes.Repeat([]byte("0123456789abcdef"), 1<<16)
	for range mib {
		if _, err = w.Write(chunk); err != nil {
			b.Fatal(err)
		}
	}
	if err = zw.Close(); err != nil {
		b.Fatal(err)
	}
	if err = f.Close(); err != nil {
		b.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		b.Fatal(err)
	}
	return info.Size()
}

// A member encrypted with a password the connector knows is still an encrypted
// member of a document: nothing is extracted, so nothing would be analyzed, and
// the file would be delivered with ciphertext that the analysis cannot read.
func TestZipFamily_aMemberEncryptedWithAKnownPasswordIsEncrypted(t *testing.T) {
	for _, method := range []string{"AES256", "ZipCrypto"} {
		content := func(t *testing.T) []byte {
			b := withMemberPassword(t, packageZip(t, "docx"), method, "infected")
			typedAs(t, b, familyTypes["docx"])
			return b
		}
		t.Run(method+"/default", func(t *testing.T) {
			r := runPipeline(t, pipelineSetup{name: "known.docx", content: content(t)})
			notDelivered(t, r, "known.docx")
		})
		t.Run(method+"/pass", func(t *testing.T) {
			r := runPipeline(t, pipelineSetup{policy: scanner.Unanalyzable{Encrypted: scanner.PolicyPass}, name: "known.docx", content: content(t)})
			got := r.one(t, "known.docx")
			if got.result.NotAnalyzedReason != datamodel.NotAnalyzedEncrypted {
				t.Errorf("reason = %q, want the file passed marked encrypted", got.result.NotAnalyzedReason)
			}
		})
	}
}

// 7-Zip takes "-p-" for the literal password "-": a member encrypted with it, or
// with the default password, or with an empty one, is encrypted all the same.
func TestZipFamily_aMemberEncryptedWithAnyPasswordTheConnectorMightTryIsEncrypted(t *testing.T) {
	for _, password := range []string{"-", "infected", ""} {
		for _, kind := range []string{"docx", "jar", "apk"} {
			for _, method := range []string{"AES256", "ZipCrypto"} {
				name := "pw." + kind
				t.Run(fmt.Sprintf("%q/%s/%s", password, kind, method), func(t *testing.T) {
					plugin := realPlugin(t)
					dir := t.TempDir()
					archive := filepath.Join(dir, "p.zip")
					if err := os.WriteFile(archive, packageZip(t, kind), 0o600); err != nil {
						t.Fatal(err)
					}
					secret := filepath.Join(dir, "secret.txt")
					if err := os.WriteFile(secret, []byte("an encrypted member"), 0o600); err != nil {
						t.Fatal(err)
					}
					if out, err := runCmd(t.Context(), plugin.sze.sevenZipPath, "a", "-tzip", "-mem="+method, "-p"+password, archive, secret); err != nil {
						t.Skipf("7-Zip does not make this archive: %v %s", err, out)
					}
					content, err := os.ReadFile(filepath.Clean(archive))
					if err != nil {
						t.Fatal(err)
					}
					typedAs(t, content, familyTypes[kind])
					r := runPipeline(t, pipelineSetup{name: name, content: content})
					notDelivered(t, r, name)
				})
			}
		}
	}
}

// Nothing the plugin runs uses "-p-", which 7-Zip reads as a password: every call
// without a known password carries the random one of the process.
func TestRun_noCallUsesDashPForNoPassword(t *testing.T) {
	plugin := realPlugin(t)
	calls := filepath.Join(t.TempDir(), "calls")
	plugin.sze.sevenZipPath = recordingWrapper(t, plugin.sze.sevenZipPath, calls)
	plugin.sze.config = extractorConfig{DefaultPasswords: []string{"infected"}}
	dir := t.TempDir()
	archive := filepath.Join(dir, "plain.zip")
	if err := os.WriteFile(archive, packageZip(t, "docx"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := plugin.sze.extract(t.Context(), archive, t.TempDir(), nil, openLimits); err != nil {
		t.Fatalf("extract() error = %v", err)
	}
	if _, err := plugin.sze.checkOnly(t.Context(), archive, plugins.ExtractLimits{MaxFiles: 100, MaxTotalSize: 1 << 30, CheckOnly: true}); err != nil {
		t.Fatalf("checkOnly() error = %v", err)
	}
	b, err := os.ReadFile(filepath.Clean(calls))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) < 4 {
		t.Fatalf("7-Zip ran %d times, want the listings, a test and an extraction", len(lines))
	}
	random, err := noPassword()
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range lines {
		if strings.Contains(" "+line+" ", " -p- ") {
			t.Errorf("a call uses -p-: %s", line)
		}
		if !strings.Contains(line, "-P"+random) && !strings.Contains(line, "-Pinfected") {
			t.Errorf("a call carries neither the random password nor a known one: %s", line)
		}
	}
	if len(random) != 32 {
		t.Errorf("the password of the process has %d characters, want 32 hexadecimal", len(random))
	}
}

// An archive encrypted with "-" is no longer opened by the first attempt of an
// extraction: it is encrypted unless "-" is a password the connector knows.
func TestExtract_anArchiveEncryptedWithDashIsNotOpenedByTheFirstAttempt(t *testing.T) {
	plugin := realPlugin(t)
	plugin.sze.config = extractorConfig{DefaultPasswords: []string{"infected"}}
	dir := t.TempDir()
	archive := filepath.Join(dir, "dash.zip")
	secret := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(secret, []byte("an encrypted member"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := runCmd(t.Context(), plugin.sze.sevenZipPath, "a", "-tzip", "-mem=AES256", "-p-", archive, secret); err != nil {
		t.Fatalf("cannot build the archive: %v %s", err, out)
	}
	_, err := plugin.ExtractFile(archive, t.TempDir(), openLimits)
	if !errors.Is(err, plugins.ErrEncrypted) {
		t.Errorf("ExtractFile() error = %v, want ErrEncrypted: the first attempt must not use \"-p-\"", err)
	}
}
