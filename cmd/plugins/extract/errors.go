package main

import (
	"errors"
	"log/slog"
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

	// maxQuotedOutput bounds the 7z output quoted in an error or a log.
	maxQuotedOutput = 1024
)

var (
	ErrInvalidPassword   = errors.New("invalid password")
	ErrUnsupportedFormat = plugins.ErrUnsupportedFormat
	ErrFileNotFound      = errors.New("file not found")

	errSevenZipRecoverable = errors.New("recoverable sevenzip error")
)

var (
	linkLabels = []string{
		"Dangerous link path was ignored",
		"Dangerous link via another link was ignored",
		"Dangerous symbolic link path was ignored",
	}
	recoverableLabels = []string{"Headers Error", "Data Error", "Unexpected end of archive"}
	// recoverableLines are the lines 7z prints alone, under its ERRORS: or WARNINGS: blocks.
	recoverableLines = []string{
		"Headers Error", "Data Error", "Unexpected end of archive",
		"There are some data after the end of the payload data",
	}
)

// sevenZipOutput is what a failed 7z run said, classified line by line.
type sevenZipOutput struct {
	wrongPassword bool
	notAnArchive  bool
	notFound      bool
	recoverable   bool
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
	case label == "Wrong password":
		o.wrongPassword = true
	case slices.Contains(linkLabels, label) && hasRest:
		name, _, _ := strings.Cut(rest, labelSep)
		o.links = append(o.links, name)
	case label == pathToken && rest == "Cannot open the file as archive":
		o.notAnArchive = true
	case strings.HasPrefix(label, "errno=") && rest == "No such file or directory":
		o.notFound = true
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
		return nil, sevenZipErr
	}
	out := classifyStderr(stderr, paths)
	quoted := sanitizeOutput(stderr)
	switch {
	case out.wrongPassword:
		return nil, ErrInvalidPassword
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
