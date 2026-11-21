// Package main implements a MIME type-based file filtering plugin.
//
// Filters files based on MIME types detected via libmagic. Forbidden types are
// flagged as malicious, skipped types are marked as safe, others pass through.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strings"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
	"github.com/vimeo/go-magic/magic"
)

// FTFilterPlugin provides MIME type-based file filtering.
type FTFilterPlugin struct {
	ForbiddenTypes map[string]struct{} // MIME types to flag as malicious
	SkippedTypes   map[string]struct{} // MIME types to mark as safe
	logger         *slog.Logger
	consoleLogger  *slog.Logger
}

// Config defines MIME type filtering rules.
type Config struct {
	ForbiddenTypes []string `mapstructure:"forbidden_types,omitempty"`
	SkippedTypes   []string `mapstructure:"skipped_types,omitempty"`
}

var (
	_ plugins.Plugin    = &FTFilterPlugin{}
	_ plugins.Validator = &FTFilterPlugin{}

	// HCPlugin is the exported plugin instance.
	HCPlugin FTFilterPlugin
)

func (p *FTFilterPlugin) GetDefaultConfig() (config any) {
	return new(Config)
}

// entryPattern is what a list entry is: type/subtype of at most 127 bytes, the
// characters of RFC 6838, no space and no parameter.
var entryPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]*/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]*$`)

// Validate checks the configuration: a type is listed as type/subtype without
// parameters (an entry that could never match would silently turn a filter off), and
// skipped_types must not hold application/octet-stream. It has no effect.
func (p *FTFilterPlugin) Validate(rawConfig any, _ plugins.ValidationContext) error {
	config, ok := rawConfig.(*Config)
	if !ok {
		return errors.New("invalid config passed")
	}
	for _, list := range []struct {
		key   string
		types []string
	}{{"forbidden_types", config.ForbiddenTypes}, {"skipped_types", config.SkippedTypes}} {
		for _, mime := range list.types {
			switch {
			case strings.Contains(mime, ";"):
				return fmt.Errorf("%s: %q has a parameter: list the type without parameters", list.key, mime)
			case len(mime) > maxMIMELen || !entryPattern.MatchString(mime):
				return fmt.Errorf("%s: %q is not a MIME type (type/subtype, at most %d bytes, no space)", list.key, mime, maxMIMELen)
			}
		}
	}
	for _, mime := range config.SkippedTypes {
		if essence(mime) == octetStreamMime {
			return fmt.Errorf("skipped_types: %s would waive every file that is not recognized", octetStreamMime)
		}
	}
	return nil
}

// Init initializes the plugin with libmagic and configuration.
func (p *FTFilterPlugin) Init(rawConfig any, hcc plugins.HCContext) error {
	p.logger = hcc.GetLogger().With(slog.String("plugin", "filetype_filter"))
	p.consoleLogger = hcc.GetConsoleLogger()

	dbErr := magic.AddMagicDir(magic.GetDefaultDir())
	if dbErr != nil {
		p.logger.Warn("could not add default magic dir", slog.String("dir", magic.GetDefaultDir()), slog.String("error", dbErr.Error()))
	}

	config, ok := rawConfig.(*Config)
	if !ok {
		return errors.New("invalid config passed")
	}
	if err := p.Validate(config, nil); err != nil {
		return err
	}
	if err := p.checkDatabase(dbErr, len(config.ForbiddenTypes) > 0, hcc.GetWorkDir()); err != nil {
		return err
	}

	p.ForbiddenTypes = make(map[string]struct{}, len(config.ForbiddenTypes))
	p.SkippedTypes = make(map[string]struct{}, len(config.SkippedTypes))

	for _, mime := range config.ForbiddenTypes {
		p.ForbiddenTypes[essence(mime)] = struct{}{}
	}

	for _, mime := range config.SkippedTypes {
		p.SkippedTypes[essence(mime)] = struct{}{}
	}

	hcc.RegisterOnScanFile(p.OnScanFile)

	p.logger.Info("plugin initialized",
		slog.String("forbidden_types", strings.Join(config.ForbiddenTypes, ", ")),
		slog.String("skipped_types", strings.Join(config.SkippedTypes, ", ")),
	)
	p.consoleLogger.Info(fmt.Sprintf("filetypefilter plugin initialized, forbidden_types: %s, skipped_types: %s",
		strings.Join(config.ForbiddenTypes, ", "), strings.Join(config.SkippedTypes, ", ")))
	return nil
}

// Close frees the libmagic handles.
func (p *FTFilterPlugin) Close(context.Context) error {
	closeCookies()
	return nil
}

// probeType types a known image the way files are typed, with the plugin's own
// handle, from a file made in dir (the private directory of the plugin); a variable
// so that tests can make it fail.
var probeType = func(dir string) (mime string, err error) {
	f, err := os.CreateTemp(dir, "probe-*.png")
	if err != nil {
		return "", err
	}
	name := f.Name()
	defer func() {
		if e := os.Remove(name); e != nil && !errors.Is(e, os.ErrNotExist) {
			err = errors.Join(err, e)
		}
	}()
	if _, err = f.Write(probeContent); err != nil {
		return "", errors.Join(err, f.Close())
	}
	if err = f.Close(); err != nil {
		return "", err
	}
	t, err := typeOf(name)
	return essence(t.mime), err
}

// probeContent is typed image/png by any working libmagic database: Init checks it.
var probeContent = []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89")

// checkDatabase tells whether libmagic can be opened and types a known content as
// it should. When it does not the types are not reliable: with forbidden_types the
// filter would silently refuse nothing, so the configuration is refused; without,
// it only warns.
func (p *FTFilterPlugin) checkDatabase(loadErr error, forbidden bool, workDir string) error {
	cause := ""
	if loadErr != nil {
		cause = loadErr.Error()
	} else if got, err := probeType(workDir); err != nil {
		cause = err.Error()
	} else if got != "image/png" {
		cause = fmt.Sprintf("a known image is typed as %q", got)
	}
	if cause == "" {
		return nil
	}
	if forbidden {
		return fmt.Errorf("the libmagic database cannot be used (%s): forbidden_types would refuse nothing", cause)
	}
	p.logger.Warn("the libmagic database cannot be used: files will be typed application/octet-stream and skipped_types will waive none of them", slog.String("cause", cause))
	p.consoleLogger.Warn(fmt.Sprintf("filetype_filter: the libmagic database cannot be used (%s): the types of the files are not reliable", cause))
	return nil
}

// errNotRegular says that a file is not a regular one: a FIFO or a device is never
// opened to be typed, it could block for ever.
var errNotRegular = errors.New("not a regular file")

// octetStreamMime types a content libmagic does not recognize: a file made so
// that it is not recognized stays under the forbidden types of the generic type.
// It never waives a file: see typed.defaulted.
const octetStreamMime = "application/octet-stream"

// bytesMax is MAGIC_PARAM_BYTES_MAX, how much of a file libmagic examines: the
// default of the library (7 MiB), set explicitly so that an upgrade of libmagic
// cannot change what the plugin reads without anyone noticing, and never lowered.
// A file larger than this is typed from what libmagic reads of it, so its type
// may not be the one of its whole content: it is never waived by skipped_types.
var bytesMax uint64 = 7 << 20

// mimePattern is what libmagic's answer must look like to be a type:
// type/subtype with optional ;name=value parameters, of the characters of RFC 6838
// and without a space or a comma, at most 127 bytes. Letters of either case are
// allowed, and so are parameters: libmagic's own types have both
// (application/SIMH-tape-data, audio/AMR, text/x-Algol68, application/grib;edition=1),
// and refusing them would fail a file for the name of its type. Anything else
// libmagic says (its text when it cannot read, such as "regular file, no read
// permission") is not a type.
var mimePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]*/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]*(;[A-Za-z0-9!#$&^_.+-]+=[A-Za-z0-9!#$&^_.+-]+)*$`)

const maxMIMELen = 127

// isMIMEType tells whether s is a well-formed MIME type.
func isMIMEType(s string) bool {
	return len(s) <= maxMIMELen && mimePattern.MatchString(s)
}

// essence is the part of a type before its parameters, in lower case: what
// forbidden_types and skipped_types are matched on (MIME types are not case
// sensitive, RFC 6838).
func essence(mime string) string {
	before, _, _ := strings.Cut(mime, ";")
	return strings.ToLower(before)
}

// withType gives t the type libmagic found. An empty answer, without an error, is
// the generic type, as is the one libmagic gives data it does not know; anything
// that is not a well-formed type is an error.
func withType(t typed, mime string) (typed, error) {
	switch {
	case mime == "" || essence(mime) == octetStreamMime:
		t.mime, t.defaulted = octetStreamMime, true
	case !isMIMEType(mime):
		return typed{}, fmt.Errorf("libmagic gave no MIME type: %q", mime)
	default:
		t.mime = mime
	}
	return t, nil
}

// typed is what is known of the content of a file.
type typed struct {
	mime string
	size int64
	// defaulted is set when libmagic recognized nothing and the type is the
	// generic one (it answers application/octet-stream for data it does not
	// know): such a type may refuse a file, never waive it, or content made not to
	// be recognized would be let through unanalyzed.
	defaulted bool
}

// OnScanFile filters files based on MIME type (forbidden=malicious, skipped=safe).
// The type is the one libmagic gives the whole file. The location is the core's
// open descriptor for the duration of the call: it is typed through its name, never
// closed.
//
// A file larger than bytesMax is never waived (see bytesMax): it goes to the
// analysis, and forbidden_types still applies to the type found.
//
// A file that cannot be typed (unreadable, a libmagic error or a typing that takes
// too long) is refused with an error when forbidden_types is not empty (it stays
// where it is, in error, and nothing is delivered), and left to the analysis with a
// warning otherwise.
func (p *FTFilterPlugin) OnScanFile(filename string, location string, sha256 string, _ bool) (res *datamodel.Result) {
	t, err := typeOf(location)
	if err != nil {
		p.logger.Warn("could not type the file", slog.String("file", filename), slog.String("location", location), slog.String("error", err.Error()))
		if len(p.ForbiddenTypes) > 0 {
			p.consoleLogger.Warn(fmt.Sprintf("filetype_filter could not type %q, the file is refused: %s", filename, err.Error()))
			return &datamodel.Result{Filename: filename, SHA256: sha256, Error: fmt.Errorf("the type of the file could not be determined: %w", err)}
		}
		p.consoleLogger.Warn(fmt.Sprintf("filetype_filter could not type %q, the filter is not applied: %s", filename, err.Error()))
		return nil
	}
	mime, size := t.mime, t.size
	match := essence(mime)
	if t.defaulted {
		p.logger.Debug("libmagic gave no type, typed as the generic type", slog.String("file", location), slog.String("mime", mime))
	}
	if _, ok := p.ForbiddenTypes[match]; ok {
		p.consoleLogger.Debug(fmt.Sprintf("filtered file based on its type (blacklist) file=%s, mime=%s", location, mime))
		p.logger.Debug("set file as malware",
			slog.String("file", location),
			slog.String("sha256", sha256),
			slog.String("mime", mime))
		return &datamodel.Result{
			Filename:       filename,
			FileType:       mime,
			Malware:        true,
			SHA256:         sha256,
			Score:          1000,
			Malwares:       []string{"forbidden_files"},
			MalwareReason:  datamodel.FilteredFileType,
			FilteredVolume: size,
			FileSize:       size,
		}
	}

	if _, ok := p.SkippedTypes[match]; ok && !t.defaulted && size >= 0 && uint64(size) > bytesMax {
		p.logger.Debug("file not waived: larger than what libmagic reads", slog.String("file", location), slog.String("mime", mime), slog.Int64("size", size))
	}
	if _, ok := p.SkippedTypes[match]; ok && !t.defaulted && size >= 0 && uint64(size) <= bytesMax {
		p.consoleLogger.Debug(fmt.Sprintf("filtered file based on its type (whitelist) file=%s, mime=%s", location, mime))
		p.logger.Debug("set file as legit",
			slog.String("file", location),
			slog.String("sha256", sha256),
			slog.String("mime", mime))
		return &datamodel.Result{
			Filename:       filename,
			FileType:       mime,
			Malware:        false,
			SHA256:         sha256,
			Score:          -500,
			FilteredVolume: size,
			FileSize:       size,
		}
	}

	return nil
}

func main() {}
