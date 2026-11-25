//go:build linux

package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

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
	tests := []struct {
		name, stderr string
		wantMembers  int
	}{
		{
			name:        "two lines of a.txt and one of b.txt",
			stderr:      "ERROR: Data Error in encrypted file. Wrong password? : a.txt\nERROR: CRC Failed in encrypted file. Wrong password? : a.txt\nERROR: Unsupported Method : b.txt\n",
			wantMembers: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := handleSevenZipError(errors.New("exit 2"), tt.stderr, slog.New(slog.DiscardHandler), "a.7z")
			hint, ok := errors.AsType[*encryptionHintError](err)
			if !ok || hint.members != tt.wantMembers {
				t.Errorf("error = %v, want a hint naming %d distinct members", err, tt.wantMembers)
			}
		})
	}
}

// The context ends while the listing is read: its error is what comes back, not
// "the listing is not as expected".
func TestDecideEncryption_theEndOfTheContextIsReturned(t *testing.T) {
	tests := []struct {
		name, listing string
	}{
		{name: "a zip of one plain member", listing: "7-Zip\n\n--\nPath = a\nType = zip\n\n----------\nPath = m\nEncrypted = -\n\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sze := listingSevenZip(t, tt.listing)
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
		})
	}
}
