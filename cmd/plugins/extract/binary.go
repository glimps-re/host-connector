package main

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/glimps-re/host-connector/pkg/plugins"
)

// proofTimeout bounds the test of a binary: its banner and the known-answer
// extraction; a variable for tests.
var proofTimeout = 10 * time.Second

const (
	binDirName = "extract-bin"
	binName    = "7zzs"
	// deployedMode is the mode of the embedded binary once deployed.
	deployedMode os.FileMode = 0o500
	dirMode      os.FileMode = 0o700
	bannerLimit              = 4096
)

// referenceArchive is a 7z of three members, one named "evil\n.exe" next to a
// genuine "evil_.exe", followed by 28 bytes. A supported 7z lists 3 members
// whose names are sanitized, reports the data after the archive, and extracts
// only 2 files.
//
//go:embed testdata/reference.7z
var referenceArchive []byte

// binary is the 7-Zip the plugin runs, deployed or configured.
type binary struct {
	path string
	// deployDir is the folder created for an embedded binary, "" for a
	// configured one.
	deployDir string
}

// remove deletes what was deployed; a configured binary is never touched.
func (b *binary) remove() error {
	if b == nil || b.deployDir == "" {
		return nil
	}
	err := os.RemoveAll(b.deployDir)
	if err == nil {
		b.deployDir = ""
	}
	return err
}

// deployEmbedded writes the embedded 7-Zip into a new folder of the private
// work directory: exclusive creation, no link followed, mode 0500.
//
// The folder is new at each call because a configuration builds a new
// Connector, whose plugins run Init in the same work directory while the
// previous ones still run until the new configuration is committed: sharing a
// path would let one instance remove or overwrite the binary of the other.
func deployEmbedded(workDir string) (b *binary, err error) {
	if !filepath.IsAbs(workDir) {
		return nil, fmt.Errorf("the work directory %q is not absolute", workDir)
	}
	base := filepath.Join(workDir, binDirName)
	if err = os.MkdirAll(base, dirMode); err != nil {
		return nil, fmt.Errorf("cannot create %s: %w", base, err)
	}
	dir, err := os.MkdirTemp(base, "b-")
	if err != nil {
		return nil, fmt.Errorf("cannot create a folder for 7-Zip in %s: %w", base, err)
	}
	b = &binary{deployDir: dir, path: filepath.Join(dir, binName)}
	defer func() {
		if err != nil {
			if rmErr := b.remove(); rmErr != nil {
				slog.Warn("cannot remove the folder of a binary that was not deployed", slog.String("dir", dir), slog.String("error", rmErr.Error()))
			}
			b = nil
		}
	}()
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer func() {
		if e := root.Close(); e != nil && err == nil {
			err = e
		}
	}()
	f, err := root.OpenFile(binName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, deployedMode)
	if err != nil {
		return nil, fmt.Errorf("cannot deploy 7-Zip in %s: %w", dir, err)
	}
	if _, err = f.Write(SevenZip); err != nil {
		if closeErr := f.Close(); closeErr != nil {
			slog.Warn("cannot close the 7-Zip being deployed", slog.String("error", closeErr.Error()))
		}
		return nil, fmt.Errorf("cannot write 7-Zip in %s: %w", dir, err)
	}
	if err = f.Close(); err != nil {
		return nil, err
	}
	return b, nil
}

// prepareBinary retains the binary to run, has the core check it, and proves
// it works: the configured seven_zip_path, otherwise the embedded 7-Zip
// deployed under the work directory. Nothing is looked up in PATH: the
// protections rely on the embedded version. On failure nothing is left behind.
func prepareBinary(configured string, vc plugins.ValidationContext, config extractorConfig, logger *slog.Logger) (b *binary, err error) {
	if configured != "" {
		b = &binary{path: configured}
	} else if b, err = deployEmbedded(vc.GetWorkDir()); err != nil {
		return nil, err
	}
	retained := b
	defer func() {
		if err != nil {
			if rmErr := retained.remove(); rmErr != nil {
				logger.Warn("cannot remove the deployed 7-Zip", slog.String("error", rmErr.Error()))
			}
		}
	}()
	if err = vc.DeclareExecutable(b.path); err != nil {
		if configured != "" {
			return nil, fmt.Errorf("seven_zip_path: %w", err)
		}
		return nil, fmt.Errorf("embedded 7-Zip %s: %w", b.path, err)
	}
	logger.Info("7-Zip retained", slog.String("path", b.path), slog.Bool("configured", configured != ""))
	if err = proveBinary(&sevenZipExtract{config: config, sevenZipPath: b.path, logger: logger}, vc.GetWorkDir()); err != nil {
		return nil, err
	}
	return b, nil
}

// proveBinary is the test of a binary; a variable for the tests that do not
// need a real one.
var proveBinary = prove

// bannerVersion matches "7-Zip (z) 25.01 (x64)" and the variants of the name.
var bannerVersion = regexp.MustCompile(`7-Zip(?: \([a-z]\))? (\d+)\.(\d+)`)

// minMajor and minMinor are the oldest 7-Zip accepted: the protections of the
// extraction against links and traversal rely on the fixes of 25.x.
const (
	minMajor = 25
	minMinor = 1
)

// checkBanner accepts the banner of 7-Zip 25.01 or later.
func checkBanner(banner string) error {
	m := bannerVersion.FindStringSubmatch(banner)
	if m == nil {
		return errors.New("its banner does not name a 7-Zip version")
	}
	major, errMajor := strconv.Atoi(m[1])
	minor, errMinor := strconv.Atoi(m[2])
	if errMajor != nil || errMinor != nil {
		return errors.New("its banner version cannot be read")
	}
	if major < minMajor || (major == minMajor && minor < minMinor) {
		return fmt.Errorf("it is 7-Zip %d.%02d, 25.01 or later is required", major, minor)
	}
	return nil
}

// prove runs the binary: its banner, then a known-answer extraction with the
// real options, which checks the listing format the analysis relies on.
func prove(sze *sevenZipExtract, workDir string) error {
	ctx, cancel := context.WithTimeout(context.Background(), proofTimeout)
	defer cancel()

	var banner bytes.Buffer
	_, err := sze.runStream(ctx, "", []string{"i"}, func(r io.Reader) error {
		_, e := banner.ReadFrom(io.LimitReader(r, bannerLimit))
		return e
	})
	if err != nil {
		return cannotRun(sze.sevenZipPath, err)
	}
	if err = checkBanner(banner.String()); err != nil {
		return unsupportedVersion(sze.sevenZipPath, err.Error())
	}

	dir, err := os.MkdirTemp(workDir, "proof-")
	if err != nil {
		return fmt.Errorf("cannot create a folder to test 7-Zip: %w", err)
	}
	defer func() {
		if e := os.RemoveAll(dir); e != nil {
			sze.logger.Warn("cannot remove the folder that tested 7-Zip", slog.String("dir", dir), slog.String("error", e.Error()))
		}
	}()
	archive := filepath.Join(dir, "reference.7z")
	if err = os.WriteFile(archive, referenceArchive, 0o600); err != nil {
		return fmt.Errorf("cannot write the reference archive: %w", err)
	}
	out := filepath.Join(dir, "out")
	if err = os.Mkdir(out, dirMode); err != nil {
		return err
	}
	test := &sevenZipExtract{
		config:       extractorConfig{MaxFileSize: 1 << 20, MaxExtractedFiles: 10, MaxTotalExtractedSize: 1 << 20},
		sevenZipPath: sze.sevenZipPath,
		// The reference archive is built to trip the checks of the analysis.
		logger: slog.New(slog.DiscardHandler),
	}
	res, err := test.extract(ctx, archive, out, nil, plugins.ExtractLimits{MaxFileSize: 1 << 20, MaxFiles: 10, MaxTotalSize: 1 << 20})
	if err != nil {
		if errors.Is(err, plugins.ErrExtractorUnavailable) || errors.Is(err, errSevenZipTimeout) {
			return cannotRun(sze.sevenZipPath, err)
		}
		return unsupportedVersion(sze.sevenZipPath, "the reference archive cannot be listed and extracted: "+sanitizeOutput(err.Error()))
	}
	return checkKnownAnswer(sze.sevenZipPath, res)
}

// checkKnownAnswer compares what 7-Zip made of the reference archive with
// what a supported version makes of it.
func checkKnownAnswer(path string, res extractResult) error {
	switch {
	case res.listed != 3 || res.listedSize != 8:
		return unsupportedVersion(path, fmt.Sprintf("it lists %d members of %d bytes in the reference archive, want 3 of 8 (the listing columns moved?)", res.listed, res.listedSize))
	case !res.tail:
		return unsupportedVersion(path, "it does not report the data after the end of the reference archive (no Tail Size)")
	case res.announced != 3 || res.produced != 2:
		return unsupportedVersion(path, fmt.Sprintf("it does not sanitize member names as expected: %d files extracted of %d announced, want 2 of 3 (the hidden member must cost one file)", res.produced, res.announced))
	case len(res.extractedFiles) != 2:
		return unsupportedVersion(path, fmt.Sprintf("it extracts %d files of the reference archive, want 2", len(res.extractedFiles)))
	}
	names := make([]string, len(res.extractedFiles))
	for i, f := range res.extractedFiles {
		names[i] = filepath.Base(f.Path)
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"a.txt", "evil_.exe"}) {
		return unsupportedVersion(path, fmt.Sprintf("it extracts %q, want a.txt and evil_.exe", names))
	}
	return nil
}

// unsupportedVersion is the error of a 7-Zip whose output the analysis cannot
// rely on, in the format of the configuration errors: what, cause, remedy.
func unsupportedVersion(path, cause string) error {
	return fmt.Errorf("7-Zip %s: version not supported: %s (remedy: use the embedded 7-Zip by leaving seven_zip_path empty, or a 7-Zip 25.01 or compatible)", path, cause)
}

// cannotRun is the error of a 7-Zip that does not run.
func cannotRun(path string, err error) error {
	cause := sanitizeOutput(err.Error())
	remedy := "check that the file is a 7-Zip executable for this system"
	if noexec(path) {
		cause = "the file system is mounted noexec: " + cause
		remedy = "set work_dir to a folder where execution is allowed, or point seven_zip_path to a 7-Zip on such a file system"
	}
	return fmt.Errorf("7-Zip %s cannot run: %s (remedy: %s): %w", path, cause, remedy, plugins.ErrExtractorUnavailable)
}
