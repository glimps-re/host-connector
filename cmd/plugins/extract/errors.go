package main

import (
	"errors"
	"log/slog"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/glimps-re/host-connector/internal/displaytext"
	"github.com/glimps-re/host-connector/pkg/plugins"
)

const (
	// pathToken replaces the archive and output paths in 7z's error output
	// before it is classified: 7z copies them, and the archive name is chosen
	// by whoever deposited the file. A NUL cannot be part of a name.
	pathToken = "\x00path"

	errLinePrefix = "ERROR: "
	labelSep      = " : "

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
	// Both lists rely on 7-Zip 25.01 printing a newline of a member name as "_" in
	// these lines (pinned by a test on the real binary): a name cannot write a line.
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
	recoverableLabels = []string{"Headers Error", "Data Error", "CRC Failed", "Unexpected end of archive", "There are some data after the end of the payload data"}
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
	// sealed is set once a line has repeated a name of the archive that no list
	// knows to be free of newlines (a member that could not be created, a link
	// target...): its errno alone decides, and nothing after it is read, since the
	// name may have written it.
	sealed bool
}

// classifyStderr reads the error lines of 7z. Only the label of a line counts
// (the text before its first " : "), because the rest is a member name or a path,
// which the archive controls; the one thing read in the rest is the errno of a member
// that cannot be created, which 7z writes before the name. paths are neutralized
// first.
func classifyStderr(stderr string, paths []string) sevenZipOutput {
	for _, p := range paths {
		if p != "" {
			stderr = strings.ReplaceAll(stderr, p, pathToken)
		}
	}
	var out sevenZipOutput
	lines := strings.Split(stderr, "\n")
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		if out.sealed {
			break
		}
		if len(out.links) > 0 && isErrorLine(line) && !isLinkLine(line) {
			// A refused link has repeated a name of the archive (the member, then
			// the target): nothing after it is believed but another refused link,
			// whatever it says, since the name may have written it. It is damage,
			// which fails the archive closed and is not retried. The cost is that a
			// genuine failure of the host in the same run as a genuine refused link
			// is a definitive anomaly instead of a retry.
			out.recoverable = true
			continue
		}
		switch {
		case line == errLinePrefix+pathToken && i+1 < len(lines) && slices.Contains(encryptedOpenLines, lines[i+1]):
			// Extracting, 7z writes the refusal of an archive with encrypted
			// headers on two lines (the path, the sentence), listing on one. The
			// sentence counts only right after the path of the archive, which is
			// ours: alone it could come from the content.
			out.wrongPassword = true
			i++
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

// isErrorLine tells whether a line of stderr says something about the archive.
func isErrorLine(line string) bool {
	return strings.HasPrefix(line, errLinePrefix) || line == "Is not archive" || slices.Contains(recoverableLines, line)
}

// linkName reads the line of a refused link, once for every use: the label, then the
// name of the member. A line that has no name (the label alone, or an empty name) is not
// one, and counts as any other line.
func linkName(body string) (name string, ok bool) {
	label, rest, hasRest := strings.Cut(body, labelSep)
	if !hasRest || !slices.Contains(linkLabels, label) {
		return "", false
	}
	name, _, _ = strings.Cut(rest, labelSep)
	return name, name != ""
}

// isLinkLine tells whether a line is the refusal of a link.
func isLinkLine(line string) bool {
	body, found := strings.CutPrefix(line, errLinePrefix)
	if !found {
		return false
	}
	_, ok := linkName(body)
	return ok
}

func (o *sevenZipOutput) classifyError(body string) {
	label, rest, hasRest := strings.Cut(body, labelSep)
	linkMember, isLink := linkName(body)
	switch {
	case isLink:
		o.links = append(o.links, linkMember)
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
	case label == pathToken && rest == "Cannot open the file as archive":
		o.notAnArchive = true
	case label == pathToken && rest == pathToken:
		// 7z repeats the path of an archive it cannot open; the lines that follow
		// say why, and are classified on their own.
	case strings.HasPrefix(label, "errno=") && rest == "No such file or directory":
		o.notFound = true
	case slices.Contains(recoverableLabels, label) || slices.Contains(recoverableLabels, body):
		// Damage is believed whoever says it: it only fails the archive closed.
		o.recoverable = true
	default:
		// Any other label is taken for one that repeats a name of the archive,
		// raw (7z prints "Cannot open output file", "Cannot create hard link", the
		// target of a link... with the name as the archive spells it, newlines
		// included): a list of the labels that do would miss one.
		o.classifyEchoing(label, rest)
	}
}

// archiveErrnos are the errors of the file system that a member causes by what it is
// (a name that goes through a file, that is a directory, a link that loops, a name
// too long): the archive is damaged for them, and retrying would fail the same way
// for ever. Any other errno (permission, space, quota, read-only, i/o, too many open
// files) is the host's, and is retried. ENOTDIR and ENAMETOOLONG are met with real
// archives; EISDIR and ELOOP were not met with 7-Zip 25.01 (it renames, or refuses the
// link, first) and are kept for what the file system may say. ENOTDIR and ELOOP can
// also be the doing of a process of the host that changes the output folder while 7z
// works; the archive is then failed closed instead of retried, which a retry would
// put right: such a process is the host's to prevent.
var archiveErrnos = []syscall.Errno{syscall.ENOTDIR, syscall.EISDIR, syscall.ELOOP, syscall.ENAMETOOLONG}

// labelErrnos are the errnos that are the archive's doing for one label more than the
// others: a link toward a target that is not in the archive (ENOENT), or toward a
// directory (EPERM), and a folder over a file the archive made before (EEXIST). A
// hard link toward a member left out of the extraction for its size gives ENOENT too,
// and the archive is then an anomaly: it is not extracted, whatever else it holds.
// EPERM on a link creation can also come from a host file system without hard links
// (FAT, some FUSE), deterministically: the archive is then failed closed, never retried.
var labelErrnos = map[string][]syscall.Errno{
	"Cannot create hard link":     {syscall.ENOENT, syscall.EPERM},
	"Cannot create symbolic link": {syscall.ENOENT, syscall.EPERM},
	"Cannot create folder":        {syscall.EEXIST},
}

// classifyEchoing reads a line that may repeat a name of the archive: errno=N : the
// text of the error : the names. Nothing after it is read: the errno alone decides.
// A line that has no errno is an unknown error.
func (o *sevenZipOutput) classifyEchoing(label, rest string) {
	o.sealed = true
	token := label
	if !strings.HasPrefix(label, "errno=") {
		token, _, _ = strings.Cut(rest, labelSep)
	}
	digits, found := strings.CutPrefix(token, "errno=")
	n, err := strconv.ParseUint(digits, 10, 16)
	if !found || err != nil {
		o.other = true
		return
	}
	errno := syscall.Errno(n)
	if slices.Contains(archiveErrnos, errno) || slices.Contains(labelErrnos[label], errno) {
		o.recoverable = true
		return
	}
	o.other = true
}

// sanitizeOutput makes 7z's output fit to be logged or returned: valid UTF-8,
// no hidden rune (displaytext.IsHidden), at most maxQuotedOutput bytes.
func sanitizeOutput(s string) string {
	s = strings.ToValidUTF8(s, "")
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\n':
			b.WriteString(" | ")
		case displaytext.IsHidden(r):
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
