//go:build linux

package main

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/glimps-re/host-connector/pkg/plugins"
)

// fakeSevenZipMode is the mode of a fake 7z script: a test fixture.
const fakeSevenZipMode os.FileMode = 0o700

// "Unsupported Method" and the data errors of an encrypted member only suggest
// an encryption: 7-Zip says them for a corrupted member, or a compression it does
// not know. Whole labels count, never what follows them.
func TestHandleSevenZipError_encryptionLines(t *testing.T) {
	tests := []struct {
		name     string
		stderr   string
		password bool // a password failure for sure
		hint     bool // a failure an encryption can explain
	}{
		{"wrong password", "ERROR: Wrong password : a.txt\n", true, false},
		{"encrypted headers", "ERROR: a.zip : Cannot open encrypted archive. Wrong password?\n", true, false},
		{"encrypted headers, p7zip spelling", "ERROR: a.zip : Can not open encrypted archive. Wrong password?\n", true, false},
		{"unsupported method", "ERROR: Unsupported Method : a.txt\n", false, true},
		{"data error in an encrypted file", "ERROR: Data Error in encrypted file. Wrong password? : a.txt\n", false, true},
		{"crc failed in an encrypted file", "ERROR: CRC Failed in encrypted file. Wrong password? : a.txt\n", false, true},
		{"a member named like the label does not count", "ERROR: Something else : Wrong password\n", false, false},
		{"a link line holding the label does not count", "ERROR: Dangerous link path was ignored : Wrong password : target\n", false, false},
		{"a label that only starts like one does not count", "ERROR: Unsupported Method of the member : a.txt\n", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := handleSevenZipError(errors.New("exit status 2"), tt.stderr, slog.New(slog.DiscardHandler), "a.zip")
			if got := errors.Is(err, ErrInvalidPassword); got != tt.password {
				t.Errorf("password failure = %v (error %v), want %v", got, err, tt.password)
			}
			if got := errors.Is(err, errEncryptionHint); got != tt.hint {
				t.Errorf("encryption hint = %v (error %v), want %v", got, err, tt.hint)
			}
		})
	}
}

// fakeSevenZip is a 7z that fails with stderr on every run but the technical
// listing, which prints encrypted.
func failingSevenZip(t *testing.T, stderr, encrypted string) *SevenZipExtractPlugin {
	t.Helper()
	script := filepath.Join(t.TempDir(), "7z")
	listing := "printf '%s\\n' '--' 'Path = a' 'Type = 7z' '' '----------' 'Path = m' 'Encrypted = " + encrypted + "' ''"
	body := "#!/bin/sh\ncase \" $* \" in *\" -slt \"*) " + listing + "; exit 0;; esac\necho '" + stderr + "' >&2\nexit 2\n"
	if err := os.WriteFile(script, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(script, fakeSevenZipMode); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.DiscardHandler)
	return &SevenZipExtractPlugin{sze: &sevenZipExtract{sevenZipPath: script, logger: logger}, logger: logger, consoleLogger: logger}
}

func extractFake(t *testing.T, p *SevenZipExtractPlugin) error {
	t.Helper()
	archive := filepath.Join(t.TempDir(), "a.zip")
	if err := os.WriteFile(archive, []byte("not really an archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := p.ExtractFile(archive, t.TempDir(), plugins.ExtractLimits{})
	return err
}

// A failure an encryption can explain is an encrypted archive only if the
// listing marks a member encrypted; otherwise it is an extraction error.
func TestSevenZipExtractPlugin_aHintIsEncryptionOnlyIfTheListingSaysSo(t *testing.T) {
	for _, hint := range []string{
		"ERROR: Unsupported Method : secret.zip",
		"ERROR: Data Error in encrypted file. Wrong password? : secret.zip",
		"ERROR: CRC Failed in encrypted file. Wrong password? : secret.zip",
	} {
		t.Run(hint, func(t *testing.T) {
			if err := extractFake(t, failingSevenZip(t, hint, "+")); !errors.Is(err, plugins.ErrEncrypted) {
				t.Errorf("a member marked encrypted: error = %v, want plugins.ErrEncrypted", err)
			}
			err := extractFake(t, failingSevenZip(t, hint, "-"))
			if err == nil || errors.Is(err, plugins.ErrEncrypted) {
				t.Errorf("no member marked encrypted: error = %v, want an extraction error that is not encryption", err)
			}
		})
	}
}

// The decision from what the passwords said, with a listing that marks a member
// encrypted.
func TestDecideEncryption(t *testing.T) {
	p := failingSevenZip(t, "ERROR: x", "+")
	archive := filepath.Join(t.TempDir(), "a.zip")
	if err := os.WriteFile(archive, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	hint := errors.Join(errEncryptionHint, errors.New("quoted"))
	tests := []struct {
		name  string
		trace encTrace
		err   error
		want  string // "encrypted", "error" or "same"
	}{
		{"a password refused for sure, nothing extracted", encTrace{wrong: 2}, ErrInvalidPassword, "encrypted"},
		{"hints only, a member says encrypted, nothing opened it (a 7z archive)", encTrace{hintRuns: 2}, hint, "encrypted"},
		{"a member was extracted, then a hint", encTrace{hintRuns: 1, extracted: true}, hint, "error"},
		{"nothing to do with an encryption", encTrace{}, errors.New("other"), "same"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := p.sze.decideEncryption(t.Context(), archive, tt.trace, 0, tt.err)
			switch tt.want {
			case "encrypted":
				if !errors.Is(got, ErrInvalidPassword) {
					t.Errorf("got %v, want ErrInvalidPassword", got)
				}
			case "error":
				if errors.Is(got, ErrInvalidPassword) || !errors.Is(got, errEncryptionHint) {
					t.Errorf("got %v, want an extraction error", got)
				}
			default:
				if !errors.Is(got, tt.err) {
					t.Errorf("got %v, want the error unchanged", got)
				}
			}
		})
	}
}
