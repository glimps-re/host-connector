//go:build linux

package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/glimps-re/host-connector/pkg/plugins"
)

func extractFixture(t *testing.T, name string, passwords []string) error {
	t.Helper()
	plugin := realPlugin(t)
	plugin.sze.config = extractorConfig{DefaultPasswords: []string{"infected"}}
	archive, err := filepath.Abs(fixture(t, filepath.Join("t17a", name)))
	if err != nil {
		t.Fatal(err)
	}
	_, err = plugin.sze.extract(t.Context(), archive, t.TempDir(), passwords, plugins.ExtractLimits{MaxFileSize: 1 << 20, MaxFiles: 1000, MaxTotalSize: 1 << 30})
	return err
}

// With the real 7-Zip: what an encryption explains is told from corruption.
func TestT17a_realEncryptionOrCorruption(t *testing.T) {
	tests := []struct {
		name      string
		fixture   string
		passwords []string
		want      string // "encrypted" or "error"
	}{
		{"(a) AES with the known password, one flipped byte", "aes_one_corrupt.zip", nil, "error"},
		{"(b) the same with an intact member next to it", "aes_two_corrupt.zip", nil, "error"},
		{"(c) ZipCrypto with an unknown password, six members", "zc6.zip", nil, "encrypted"},
		{"(d) 7z with encrypted content", "enc_content.7z", nil, "encrypted"},
		{"(d) 7z with encrypted headers", "enc_headers.7z", nil, "encrypted"},
		{"(e) a configured password that is wrong, after the known one that opened it", "aes_one_corrupt.zip", []string{"another-password"}, "error"},
		{"(f) a forged archive comment and a method 7-Zip does not know", "forged_comment.zip", nil, "error"},
		{"(g) non-solid 7z, known password, one member corrupted and one intact", "seven_two_corrupt.7z", nil, "error"},
		{"(g) solid 7z, known password, the last of three members corrupted", "solid3_corrupt.7z", nil, "error"},
		{"(h) two members with the same name, the first one corrupted, known password", "dup_corrupt.7z", nil, "error"},
		{"a plain member and an encrypted homonym with an unknown password", "homonym_mixed.7z", nil, "error"},
		{"six encrypted members and an empty one, unknown password", "enc_with_empty.7z", nil, "encrypted"},
		{"250 plain members and one ZipCrypto member with an unknown password: partial encryption", "mixed_many.zip", nil, "encrypted"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := extractFixture(t, tt.fixture, tt.passwords)
			if err == nil {
				t.Fatal("extraction succeeded, want a failure")
			}
			encrypted := errors.Is(err, ErrInvalidPassword)
			if encrypted != (tt.want == "encrypted") {
				t.Errorf("error = %v; encrypted = %v, want %s", err, encrypted, tt.want)
			}
		})
	}
}

// listing is a 7z whose technical listing is the text given.
func listingSevenZip(t *testing.T, listing string) *sevenZipExtract {
	t.Helper()
	dir := t.TempDir()
	text := filepath.Join(dir, "listing.txt")
	if err := os.WriteFile(text, []byte(listing), 0o600); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, "7z")
	if err := os.WriteFile(script, []byte("#!/bin/sh\ncat "+text+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(script, fakeSevenZipMode); err != nil {
		t.Fatal(err)
	}
	return &sevenZipExtract{sevenZipPath: script, logger: failingSevenZip(t, "", "-").logger}
}

// The technical listing is read by block: what is before the first separator
// is the archive's, and in a member only the first "Encrypted =" line counts.
func TestEncryptionInfo_readsTheListingByBlock(t *testing.T) {
	member := func(name, enc string) string {
		return "Path = " + name + "\nFolder = -\nEncrypted = " + enc + "\nMethod = Store\n\n"
	}
	header := func(typ, comment string) string {
		return "7-Zip 25.01\n\nListing archive: a\n\n--\nPath = a\nType = " + typ + "\n" + comment + "\n----------\n"
	}
	tests := []struct {
		name      string
		listing   string
		entries   int
		wantEnc   bool
		wantZip   bool
		wantError bool
	}{
		{"a member says encrypted", header("zip", "") + member("a.txt", "+") + member("b.txt", "-"), 2, true, true, false},
		{"no member says it", header("7z", "") + member("a.txt", "-"), 1, false, false, false},
		{"the comment of the archive forges the line", header("zip", "Comment = \n{\nhi\nEncrypted = +\nType = 7z\n}\n") + member("a.txt", "-"), 1, false, true, false},
		{"a second Encrypted line in a block does not count", header("zip", "") + "Path = a.txt\nEncrypted = -\nEncrypted = +\n\n", 1, false, true, false},
		{"a forged separator and Encrypted line in the comment: two separators", header("rar", "Comment = \nx\n----------\nEncrypted = +\n") + member("a.txt", "-"), 0, false, false, true},
		{"a forged separator and a Type line in the comment", header("rar", "Comment = \nx\n----------\nType = rar\n") + member("a.txt", "-"), 0, false, false, true},
		{"an Encrypted line before the first member", header("zip", "") + "Encrypted = +\n" + member("a.txt", "-"), 0, false, false, true},
		{"fewer members than announced", header("zip", "") + member("a.txt", "-"), 3, false, false, true},
		{"no separator", "7-Zip\n\nPath = a\nType = zip\n", 0, false, false, true},
		{"no member at all", header("zip", ""), 0, false, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := listingSevenZip(t, tt.listing).encryptionInfo(t.Context(), "a.zip", tt.entries)
			if (err != nil) != tt.wantError {
				t.Fatalf("error = %v, want error %v", err, tt.wantError)
			}
			if err == nil && (info.encrypted != tt.wantEnc || info.zip != tt.wantZip) {
				t.Errorf("info = %+v, want encrypted %v, zip %v", info, tt.wantEnc, tt.wantZip)
			}
		})
	}
}

// Whatever the technical listing is made to say outside of a member, a failure
// that an encryption can explain stays an extraction error unless a member says
// it is encrypted: on the extraction path and on the list path.
func TestDecideEncryption_aForgedListingIsNotEncryption(t *testing.T) {
	listing := "7-Zip\n\n--\nPath = a\nType = rar\nComment = \nx\n----------\nEncrypted = +\n\n----------\nPath = a.txt\nEncrypted = -\n\n"
	sze := listingSevenZip(t, listing)
	archive := filepath.Join(t.TempDir(), "a.rar")
	if err := os.WriteFile(archive, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	hint := &encryptionHintError{members: 1, quoted: "ERROR: Unsupported Method : a.txt"}
	for name, entries := range map[string]int{"extraction path": 1, "list path": 0} {
		t.Run(name, func(t *testing.T) {
			got := sze.decideEncryption(t.Context(), archive, encTrace{hintRuns: 1}, entries, hint)
			if errors.Is(got, ErrInvalidPassword) || !errors.Is(got, errEncryptionHint) {
				t.Errorf("got %v, want an extraction error", got)
			}
		})
	}
}

// A hint run that named fewer members than its batch held extracted the others:
// the password opened the archive.
func TestEncryptionHintError_countsTheMembersItNames(t *testing.T) {
	_, err := handleSevenZipError(errors.New("exit 2"),
		"ERROR: Data Error in encrypted file. Wrong password? : a.txt\nERROR: CRC Failed in encrypted file. Wrong password? : a.txt\nERROR: Unsupported Method : b.txt\n",
		slog.New(slog.DiscardHandler), "a.7z")
	hint, ok := errors.AsType[*encryptionHintError](err)
	if !ok || hint.members != 2 {
		t.Errorf("error = %v, want a hint naming 2 distinct members", err)
	}
}

// The context ends while the listing is read: its error is what comes back, not
// "the listing is not as expected".
func TestDecideEncryption_theEndOfTheContextIsReturned(t *testing.T) {
	sze := listingSevenZip(t, "7-Zip\n\n--\nPath = a\nType = zip\n\n----------\nPath = m\nEncrypted = -\n\n")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	archive := filepath.Join(t.TempDir(), "a.zip")
	if err := os.WriteFile(archive, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	got := sze.decideEncryption(ctx, archive, encTrace{hintRuns: 1}, 1, &encryptionHintError{members: 1})
	if !errors.Is(got, context.Canceled) {
		t.Errorf("got %v, want the end of the context", got)
	}
}
