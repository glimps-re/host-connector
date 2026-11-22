// Package main implements an archive extraction plugin using 7-Zip.
//
// Extracts archives with configurable limits to prevent extraction bombs.
// Supports password-protected archives and automatically removes dangerous symlinks.
package main

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
)

// SevenZipExtractPlugin provides archive extraction via 7-Zip.
type SevenZipExtractPlugin struct {
	sze           *sevenZipExtract
	bin           *binary
	logger        *slog.Logger
	consoleLogger *slog.Logger

	// baseCtx is the parent of every extraction: Interrupt and Close cancel it,
	// which kills the 7-Zip running, with its process group.
	baseCtx    context.Context
	cancelBase context.CancelFunc
}

// Config defines the extraction behavior. The extraction limits are the global
// ones (max_file_size, recursive_extract_max_files, recursive_extract_max_size):
// the core passes them at each extraction.
type Config struct {
	DefaultPasswords []string `mapstructure:"default_passwords,omitempty"` // Default passwords for encrypted archives
	SevenZipPath     string   `mapstructure:"seven_zip_path,omitempty"`
}

var (
	_ plugins.Plugin      = &SevenZipExtractPlugin{}
	_ plugins.Validator   = &SevenZipExtractPlugin{}
	_ plugins.Interrupter = &SevenZipExtractPlugin{}

	// HCPlugin is the exported plugin instance.
	HCPlugin SevenZipExtractPlugin

	// SevenZip is the embedded 7-Zip binary.
	//
	//go:embed 7zzs
	SevenZip []byte
)

func (p *SevenZipExtractPlugin) GetDefaultConfig() (config any) {
	config = &Config{DefaultPasswords: []string{"infected"}}
	return
}

// Validate checks the configuration like Init does, without any effect: the
// 7-Zip binary is deployed or checked, declared and
// run in the scratch directory of the validation, which leaves the running
// plugin and its binary alone.
func (p *SevenZipExtractPlugin) Validate(rawConfig any, vc plugins.ValidationContext) error {
	config, ok := rawConfig.(*Config)
	if !ok {
		return errors.New("error bad config passed")
	}
	bin, err := prepareBinary(config.SevenZipPath, vc, extractorConfig{DefaultPasswords: config.DefaultPasswords}, vc.GetLogger())
	if err != nil {
		return err
	}
	if rmErr := bin.remove(); rmErr != nil {
		vc.GetLogger().Warn("cannot remove the 7-Zip deployed to validate", slog.String("error", rmErr.Error()))
	}
	return nil
}

// Init sets up the extraction engine and registers callbacks.
func (p *SevenZipExtractPlugin) Init(rawConfig any, hcc plugins.HCContext) (err error) {
	p.logger = hcc.GetLogger().With(slog.String("plugin", "7z"))
	p.consoleLogger = hcc.GetConsoleLogger()

	config, ok := rawConfig.(*Config)
	if !ok {
		return errors.New("error bad config passed")
	}

	econf := extractorConfig{DefaultPasswords: config.DefaultPasswords}
	bin, err := prepareBinary(config.SevenZipPath, hcc, econf, p.logger)
	if err != nil {
		return err
	}
	if p.bin != nil {
		if rmErr := p.bin.remove(); rmErr != nil {
			p.logger.Warn("cannot remove the 7-Zip of a previous Init", slog.String("error", rmErr.Error()))
		}
	}
	p.sze = &sevenZipExtract{config: econf, sevenZipPath: bin.path, logger: p.logger, workDir: hcc.GetWorkDir()}
	p.bin = bin
	if p.cancelBase != nil {
		p.cancelBase()
	}
	p.baseCtx, p.cancelBase = context.WithCancel(context.Background())

	hcc.SetExtractFile(p.ExtractFile)
	p.logger.Info("plugin initialized",
		slog.String("default_passwords", strings.Join(config.DefaultPasswords, ", ")),
		slog.String("seven_zip_path", config.SevenZipPath),
	)
	p.consoleLogger.Info(fmt.Sprintf("extract plugin initialized, default_passwords: %s, seven_zip_path: %s",
		strings.Join(config.DefaultPasswords, ", "), config.SevenZipPath,
	))
	return
}

// ExtractFile extracts archive contents to outputDir within the strictest of
// the plugin's keys and limits. Every failure of 7z is classified: see the
// errors wrapped by the returned error.
func (p *SevenZipExtractPlugin) ExtractFile(archiveLocation, outputDir string, limits plugins.ExtractLimits) (extraction plugins.Extraction, err error) {
	p.consoleLogger.Debug(fmt.Sprintf("start extraction of %s with 7z", archiveLocation))

	parent := p.baseCtx
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, szExtractTimeout)
	defer cancel()
	if limits.NamesOnly {
		return p.namesOnly(ctx, archiveLocation, limits)
	}
	if limits.CheckOnly {
		return p.checkOnly(ctx, archiveLocation, limits)
	}
	result, err := p.sze.extract(ctx, archiveLocation, outputDir, nil, limits)
	if err != nil {
		return plugins.Extraction{}, classifyFailure(err)
	}

	for _, ep := range result.extractedFiles {
		extraction.Files = append(extraction.Files, ep.Path)
		if ep.Size > 0 {
			extraction.Size += uint64(ep.Size)
		}
	}
	extraction.Skipped = result.skipped.entries
	extraction.SkippedCount = result.skipped.count
	if len(result.anomalies) > 0 {
		return p.anomalyOf(archiveLocation, result, extraction)
	}
	return extraction, nil
}

// Interrupt kills the 7-Zip commands running: their extractions return an error
// at once. It makes the plugin unable to extract until its next Init.
func (p *SevenZipExtractPlugin) Interrupt() {
	if p.cancelBase != nil {
		p.cancelBase()
	}
}

// Close interrupts the extractions running and removes the 7-Zip binary
// deployed by Init, if any; calling it again has no effect.
func (p *SevenZipExtractPlugin) Close(_ context.Context) error {
	p.Interrupt()
	if p.bin == nil {
		return nil
	}
	return p.bin.remove()
}

func main() {}

// classifyFailure wraps the failures of an extraction that the scanner tells
// apart: a password no one knows is plugins.ErrEncrypted, and what 7z found
// damaged or inconsistent in the archive is plugins.ErrArchiveAnomaly, with
// plugins.ErrEncryptionPossible since nothing proves that no encrypted content is
// hidden by the damage. Whether a failure that came with a timeout or a
// cancellation is retried is the scanner's to decide.
func classifyFailure(err error) error {
	switch {
	case errors.Is(err, ErrInvalidPassword):
		return fmt.Errorf("%w: %w", plugins.ErrEncrypted, err)
	case errors.Is(err, plugins.ErrArchiveAnomaly):
		if errors.Is(err, plugins.ErrEncryptionPossible) {
			return err
		}
		return errors.Join(err, plugins.ErrEncryptionPossible)
	case errors.Is(err, errSevenZipRecoverable), errors.Is(err, errBadListing), errors.Is(err, errEncryptionHint), errors.Is(err, errSevenZipOutputTooLarge):
		return fmt.Errorf("%w: %w: %w", plugins.ErrArchiveAnomaly, plugins.ErrEncryptionPossible, err)
	}
	return err
}

// anomalyOf is the failure of an archive that 7z found damaged or inconsistent: an
// error wrapping plugins.ErrArchiveAnomaly, with plugins.ErrEncryptionPossible
// unless it was proven that no encrypted content is hidden, and an extract-error
// entry for the report.
func (p *SevenZipExtractPlugin) anomalyOf(archiveLocation string, result extractResult, extraction plugins.Extraction) (plugins.Extraction, error) {
	p.logger.Error("extraction anomaly", slog.String("archive", sanitizeOutput(archiveLocation)), slog.String("anomalies", sanitizeOutput(strings.Join(result.anomalies, "; "))), slog.Bool("encryption_excluded", result.encryptionExcluded))
	extraction.Skipped = append([]datamodel.NotAnalyzedFile{{FileName: truncateName(filepath.Base(archiveLocation)), Reason: datamodel.NotAnalyzedExtractError}}, extraction.Skipped...)
	if len(extraction.Skipped) > datamodel.MaxListedSubfiles {
		extraction.Skipped = extraction.Skipped[:datamodel.MaxListedSubfiles]
	}
	extraction.SkippedCount++
	err := fmt.Errorf("%w: %s", plugins.ErrArchiveAnomaly, sanitizeOutput(strings.Join(result.anomalies, "; ")))
	if !result.encryptionExcluded {
		err = errors.Join(err, plugins.ErrEncryptionPossible)
	}
	return extraction, err
}

// namesOnly gives the names of the files of the archive, or says that they are
// not known (see sevenZipExtract.namesOnly).
func (p *SevenZipExtractPlugin) namesOnly(ctx context.Context, archiveLocation string, limits plugins.ExtractLimits) (plugins.Extraction, error) {
	names, ok, err := p.sze.namesOnly(ctx, archiveLocation, limits.MaxFiles)
	switch {
	case err != nil:
		return plugins.Extraction{}, classifyFailure(err)
	case !ok:
		return plugins.Extraction{}, nil
	}
	return plugins.Extraction{Names: names}, nil
}

// checkOnly checks the archive without extracting anything: what 7z lists and
// what it finds testing every member.
func (p *SevenZipExtractPlugin) checkOnly(ctx context.Context, archiveLocation string, limits plugins.ExtractLimits) (plugins.Extraction, error) {
	result, err := p.sze.checkOnly(ctx, archiveLocation, limits)
	if err != nil {
		return plugins.Extraction{}, classifyFailure(err)
	}
	if len(result.anomalies) > 0 {
		return p.anomalyOf(archiveLocation, result, plugins.Extraction{})
	}
	if result.overBudget {
		// Members left out by the budget, as an extraction leaves them: the caller
		// decides what the files left out become.
		return plugins.Extraction{Skipped: result.skipped.entries, SkippedCount: result.skipped.count}, nil
	}
	return plugins.Extraction{}, nil
}
