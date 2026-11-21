//go:build linux

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/scanner"
)

// notDelivered fails when the file reached OUTPUT or left INPUT.
func notDelivered(t *testing.T, r *t17Run, name string) {
	t.Helper()
	if r.exists(r.out, name) {
		t.Errorf("%s was delivered to OUTPUT", name)
	}
	if !r.exists(r.in, name) {
		t.Errorf("%s left INPUT", name)
	}
}

// A zip cut before its central directory keeps its signature: 7-Zip says "not an
// archive", and what the local entries hold (an encrypted one included) is
// recoverable. It is never a plain file.
func TestTruncatedZipIsNeverAPlainFile(t *testing.T) {
	for _, fx := range []string{"enc_aes.zip", "enc_zipcrypto.zip", "known_password.zip", "aes_one_corrupt.zip"} {
		for _, percent := range []int{10, 20, 50, 90} {
			c := cutCase(fx, percent)
			name := fmt.Sprintf("%s-%d.zip", fx, percent)
			t.Run(name+"/default", func(t *testing.T) {
				r := runT17(t, t17Setup{name: name, content: c.content(t)})
				notDelivered(t, r, name)
				if got, ran := r.maybe(name); ran && got.result.Error == nil {
					t.Errorf("result = %+v, want the failure", got.result)
				}
			})
			t.Run(name+"/pass and as_file", func(t *testing.T) {
				r := runT17(t, t17Setup{policy: scanner.Unanalyzable{Encrypted: scanner.PolicyPass, ExtractError: scanner.PolicyAsFile}, name: name, content: c.content(t)})
				got, ran := r.maybe(name)
				if !ran {
					t.Fatalf("the actions never ran for %s", name)
				}
				if got.result.NotAnalyzedReason != datamodel.NotAnalyzedEncrypted {
					t.Errorf("reason = %q, want the file passed marked encrypted, never extract-error nor clean", got.result.NotAnalyzedReason)
				}
			})
		}
	}
}

// 7z is typed on its six-byte signature only: a byte flipped in the rest of the
// start header makes 7-Zip refuse it, and it is still a 7z.
func TestSevenZipWithAFlippedStartHeaderByteIsNeverAPlainFile(t *testing.T) {
	if testing.Short() {
		t.Skip("48 real extractions")
	}
	for _, fx := range []string{"enc_headers.7z", "enc_content.7z"} {
		base := t17Fixture(t, fx)
		for off := 8; off <= 31; off++ {
			t.Run(fmt.Sprintf("%s/%d", fx, off), func(t *testing.T) {
				b := bytes.Clone(base)
				b[off] ^= 0x5a
				name := fmt.Sprintf("flip%d.7z", off)
				r := runT17(t, t17Setup{name: name, content: b})
				notDelivered(t, r, name)
			})
		}
	}
}

func truncatedTar(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	body := bytes.Repeat([]byte("member content "), 100)
	if err := tw.WriteHeader(&tar.Header{Name: "a.txt", Mode: 0o600, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()[:900]
}

func truncatedGzip(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	data := make([]byte, 0, 100000)
	for i := range 100000 {
		data = append(data, byte(i*7+i/13))
	}
	if _, err := zw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()[:buf.Len()/2]
}

// compressed builds a file of the given 7-Zip format holding some bytes, cut in
// half.
func compressedAndCut(t *testing.T, format string) []byte {
	t.Helper()
	plugin := realPlugin(t)
	dir := t.TempDir()
	src := filepath.Join(dir, "data.bin")
	data := make([]byte, 0, 200000)
	for i := range 200000 {
		data = append(data, byte((i*31+i/7)&0xff))
	}
	if err := os.WriteFile(src, data, 0o600); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(dir, "data."+format)
	if out, err := runCmd(t.Context(), plugin.sze.sevenZipPath, "a", "-t"+format, archive, src); err != nil {
		t.Fatalf("cannot build the %s: %v %s", format, err, out)
	}
	b, err := os.ReadFile(filepath.Clean(archive))
	if err != nil {
		t.Fatal(err)
	}
	return b[:len(b)/2]
}

func TestOtherTruncatedArchivesAreNeverPlainFiles(t *testing.T) {
	sevenZip := t17Fixture(t, "enc_content.7z")
	cases := []struct {
		name    string
		content []byte
	}{
		{"cut.gz", truncatedGzip(t)},
		{"cut.tar", truncatedTar(t)},
		{"cut.7z", sevenZip[:len(sevenZip)/2]},
		{"cut.xz", compressedAndCut(t, "xz")},
		{"cut.bz2", compressedAndCut(t, "bzip2")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := runT17(t, t17Setup{name: c.name, content: c.content})
			notDelivered(t, r, c.name)
		})
	}
}

// A truncated zip that is a member of a real outer archive follows the rule too.
func TestTruncatedZipNestedInARealArchiveIsNeverAPlainFile(t *testing.T) {
	plugin := realPlugin(t)
	cut := t17Fixture(t, "enc_aes.zip")
	cut = cut[:len(cut)/2]
	for _, format := range []string{"zip", "7z"} {
		t.Run(format, func(t *testing.T) {
			dir := t.TempDir()
			src := filepath.Join(dir, "inner.zip")
			if err := os.WriteFile(src, cut, 0o600); err != nil {
				t.Fatal(err)
			}
			archive := filepath.Join(dir, "outer."+format)
			if out, err := runCmd(t.Context(), plugin.sze.sevenZipPath, "a", "-t"+format, archive, src); err != nil {
				t.Fatalf("cannot build the archive: %v %s", err, out)
			}
			content, err := os.ReadFile(filepath.Clean(archive))
			if err != nil {
				t.Fatal(err)
			}
			name := "outer." + format
			r := runT17(t, t17Setup{name: name, content: content})
			notDelivered(t, r, name)
			r = runT17(t, t17Setup{policy: scanner.Unanalyzable{Encrypted: scanner.PolicyPass, ExtractError: scanner.PolicyAsFile}, name: name, content: content})
			got, ran := r.maybe(name)
			if !ran || len(got.report.NotAnalyzedExtractedFiles) != 1 || got.report.NotAnalyzedExtractedFiles[0].Reason != datamodel.NotAnalyzedEncrypted {
				t.Errorf("report = %+v (ran %v), want inner.zip listed as not analyzed, encrypted", got.report.NotAnalyzedExtractedFiles, ran)
			}
		})
	}
}

// What is not typed as an archive stays a plain file when 7-Zip refuses it, as
// before.
func TestWhatIsNotTypedAsAnArchiveStaysAPlainFile(t *testing.T) {
	png := append([]byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"), bytes.Repeat([]byte{0x01}, 200)...)
	binary := append([]byte{0x00, 0x01, 0x02, 0x03}, bytes.Repeat([]byte{0x9c, 0x17}, 300)...)
	cases := []struct {
		name    string
		content []byte
	}{{"image.png", png}, {"blob.bin", binary}}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := runT17(t, t17Setup{name: c.name, content: c.content})
			got := r.one(t, c.name)
			if got.result.Error != nil || got.result.NotAnalyzedReason != "" {
				t.Errorf("result = error %v reason %q, want an ordinary plain file", got.result.Error, got.result.NotAnalyzedReason)
			}
			if !r.exists(r.out, c.name) {
				t.Error("the file must be delivered")
			}
		})
	}
}

// The accepted false positives: a text that starts with the signature of an
// archive is typed as one, 7-Zip cannot open it, and it stays in INPUT.
func TestATextThatStartsLikeAnArchiveStaysInInput(t *testing.T) {
	cases := []struct{ name, content string }{
		{"bzh.txt", "BZh9 is how this text starts, and nothing else"},
		{"pk.txt", "PK\x03\x04 and then only text that is no archive"},
		{"cpio.txt", "070707 and then only text that is no archive at all"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := runT17(t, t17Setup{name: c.name, content: []byte(c.content)})
			notDelivered(t, r, c.name)
		})
	}
}
