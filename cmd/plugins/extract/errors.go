package main

import (
	"errors"
	"log/slog"
	"os/exec"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/glimps-re/host-connector/pkg/plugins"
)

const (
	// pathToken replaces the archive and output paths in 7z's error output
	// before it is classified: 7z copies them, and the archive name is chosen
	// by whoever deposited the file. A NUL cannot be part of a name.
	pathToken = "\x00path"

	errLinePrefix = "ERROR: "
	labelSep      = " : "

	// outputFileLabel and nameTooLong are what 7z says when the file system refuses
	// the name of a member it extracts (ENAMETOOLONG).
	outputFileLabel = "Cannot open output file"
	nameTooLong     = "errno=36 : File name too long"

	// exitFatal is the exit code of 7z for a fatal error.
	exitFatal = 2

	// maxQuotedOutput bounds the 7z output quoted in an error or a log.
	maxQuotedOutput = 1024
)

var (
	ErrInvalidPassword   = errors.New("invalid password")
	ErrUnsupportedFormat = plugins.ErrUnsupportedFormat
	ErrFileNotFound      = errors.New("file not found")

	errSevenZipRecoverable = errors.New("recoverable sevenzip error")
	// errEncryptionHint is the failure of a password for a reason an encryption
	// can explain: it is an encrypted archive only if the listing says a member is
	// encrypted and no password opened it.
	errEncryptionHint = errors.New("7z failed on a member in a way an encryption can explain")
)

var (
	linkLabels = []string{
		"Dangerous link path was ignored",
		"Dangerous link via another link was ignored",
		"Dangerous symbolic link path was ignored",
	}
	// wrongPasswordLabels are the labels with which 7z says, for sure, that a
	// password is wrong; encryptedOpenLines are what it says, after the path of
	// the archive, when the headers themselves are encrypted (the second spelling
	// is p7zip 16.02's). encryptionHintLabels only suggest an encryption: 7z uses
	// them for a corrupted member as well, or for a compression it does not know.
	wrongPasswordLabels = []string{"Wrong password"}
	encryptedOpenLines  = []string{
		"Cannot open encrypted archive. Wrong password?",
		"Can not open encrypted archive. Wrong password?",
	}
	encryptionHintLabels = []string{
		"Unsupported Method",
		"Data Error in encrypted file. Wrong password?",
		"CRC Failed in encrypted file. Wrong password?",
	}
	recoverableLabels = []string{"Headers Error", "Data Error", "CRC Failed", "Unexpected end of archive"}
	// recoverableLines are the lines 7z prints alone, under its ERRORS: or WARNINGS: blocks.
	recoverableLines = []string{
		"Headers Error", "Data Error", "Unexpected end of archive",
		"There are some data after the end of the payload data",
	}
)

// encryptionHintError is the failure of a run that only suggested an encryption:
// how many distinct members it named, and what 7z said.
type encryptionHintError struct {
	members int
	quoted  string
}

func (e *encryptionHintError) Error() string {
	return errEncryptionHint.Error() + ": " + e.quoted
}

func (e *encryptionHintError) Is(target error) bool { return target == errEncryptionHint }

// sevenZipOutput is what a failed 7z run said, classified line by line.
type sevenZipOutput struct {
	wrongPassword bool
	// encryptionHint is set by a line that an encryption can explain, without
	// proving it.
	encryptionHint bool
	// hintMembers are the distinct members named by the hint lines.
	hintMembers  map[string]struct{}
	notAnArchive bool
	notFound     bool
	recoverable  bool
	// links are the members 7z refused to create as links.
	links []string
	// other is set when an error line is none of the above.
	other bool
}

// classifyStderr reads the error lines of 7z. Only the label of a line counts
// (the text before its first " : "): the rest is a member name or a path,
// which the archive controls. paths are neutralized first.
func classifyStderr(stderr string, paths []string) sevenZipOutput {
	for _, p := range paths {
		if p != "" {
			stderr = strings.ReplaceAll(stderr, p, pathToken)
		}
	}
	var out sevenZipOutput
	for line := range strings.SplitSeq(stderr, "\n") {
		switch {
		case line == "":
		case line == "Is not archive":
			out.notAnArchive = true
		case slices.Contains(recoverableLines, line):
			out.recoverable = true
		case strings.HasPrefix(line, errLinePrefix):
			out.classifyError(strings.TrimPrefix(line, errLinePrefix))
		}
	}
	return out
}

func (o *sevenZipOutput) classifyError(body string) {
	label, rest, hasRest := strings.Cut(body, labelSep)
	switch {
	case slices.Contains(wrongPasswordLabels, label), label == pathToken && slices.Contains(encryptedOpenLines, rest):
		// Only whole labels count, never a part of what follows: the names of the
		// members are the archive's.
		o.wrongPassword = true
	case slices.Contains(encryptionHintLabels, label):
		o.encryptionHint = true
		if hasRest {
			if o.hintMembers == nil {
				o.hintMembers = map[string]struct{}{}
			}
			o.hintMembers[rest] = struct{}{}
		}
	case slices.Contains(linkLabels, label) && hasRest:
		name, _, _ := strings.Cut(rest, labelSep)
		o.links = append(o.links, name)
	case label == pathToken && rest == "Cannot open the file as archive":
		o.notAnArchive = true
	case label == pathToken && rest == pathToken:
		// 7z repeats the path of an archive it cannot open; the lines that follow
		// say why, and are classified on their own.
	case strings.HasPrefix(label, "errno=") && rest == "No such file or directory":
		o.notFound = true
	case label == outputFileLabel && strings.HasPrefix(rest, nameTooLong):
		// The extraction cannot create a member (a name made too long by a rename
		// on a clash, a path over PATH_MAX): the archive is damaged for it, and
		// retrying would fail the same way for ever.
		o.recoverable = true
	case slices.Contains(recoverableLabels, label) || slices.Contains(recoverableLabels, body):
		o.recoverable = true
	default:
		o.other = true
	}
}

// sanitizeOutput makes 7z's output fit to be logged or returned: valid UTF-8,
// no control or bidirectional character, at most maxQuotedOutput bytes.
func sanitizeOutput(s string) string {
	s = strings.ToValidUTF8(s, "")
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\n':
			b.WriteString(" | ")
		case unicode.IsControl(r) || isBidi(r):
		default:
			b.WriteRune(r)
		}
		if b.Len() >= maxQuotedOutput {
			break
		}
	}
	out := b.String()
	if len(out) > maxQuotedOutput {
		cut := maxQuotedOutput
		for cut > 0 && !utf8.RuneStart(out[cut]) {
			cut--
		}
		out = out[:cut]
	}
	return strings.TrimSpace(out)
}

func isBidi(r rune) bool {
	switch {
	case r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069:
		return true
	}
	return r == 0x200E || r == 0x200F || r == 0x061C
}

// handleSevenZipError turns the end of a 7z run into an error. A refused link
// is tolerated only when every error line of 7z is one: anything else wins.
// paths (the archive, the output folder) are neutralized before classifying.
func handleSevenZipError(sevenZipErr error, stderr string, logger *slog.Logger, paths ...string) (symLinkFiles []string, err error) {
	if sevenZipErr == nil {
		return nil, nil
	}
	if stderr == "" {
		// 7z says nothing but "fatal error" (exit code 2) when it only found the
		// archive damaged, as when a listing stops on a truncated zip.
		if exitErr, ok := errors.AsType[*exec.ExitError](sevenZipErr); ok && exitErr.ExitCode() == exitFatal {
			return nil, errors.Join(errSevenZipRecoverable, sevenZipErr)
		}
		return nil, sevenZipErr
	}
	out := classifyStderr(stderr, paths)
	quoted := sanitizeOutput(stderr)
	switch {
	case out.wrongPassword:
		return nil, ErrInvalidPassword
	case out.encryptionHint && !out.other:
		return nil, &encryptionHintError{members: len(out.hintMembers), quoted: quoted}
	case out.notAnArchive:
		return nil, ErrUnsupportedFormat
	case out.notFound:
		return nil, ErrFileNotFound
	case out.other:
	case out.recoverable:
		return nil, errors.Join(errSevenZipRecoverable, errors.New(quoted))
	case len(out.links) > 0:
		// With recent versions of 7z a refused link makes 7z exit with code 2
		// although the other members were extracted.
		// see https://sourceforge.net/p/sevenzip/bugs/2356/
		return out.links, nil
	}
	err = errors.Join(sevenZipErr, errors.New(quoted))
	logger.Error("7z unsupported error", slog.String("retrieved error", quoted))
	return nil, err
}
