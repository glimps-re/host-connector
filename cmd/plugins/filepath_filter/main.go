// Package main implements a path filtering plugin.
//
// Filters files based on their path. Uses two regexp path lists (forbidden and skipped).
// Forbidden paths are flagged as malicious, skipped paths are marked as safe, others pass through.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
)

var (
	logger        = slog.New(slog.DiscardHandler)
	consoleLogger = slog.New(slog.DiscardHandler)

	// HCPlugin is the exported plugin instance.
	HCPlugin FilePathFilterPlugin
)

var _ plugins.Plugin = &FilePathFilterPlugin{}

// FilePathFilterPlugin provides path-based file filtering using regexp.
type FilePathFilterPlugin struct {
	// path regexps to flag as malicious
	ForbiddenPaths map[string]*regexp.Regexp // map originalRegexpStr:compiledRegexp
	// path regexps to mark as safe
	SkippedPaths map[string]*regexp.Regexp // map originalRegexpStr:compiledRegexp
}

// Config defines path regexp lists.
type Config struct {
	ForbiddenPaths []string `mapstructure:"forbidden_paths,omitempty"`
	SkippedPaths   []string `mapstructure:"skipped_paths,omitempty"`
}

func (fp *FilePathFilterPlugin) GetDefaultConfig() any { return &Config{} }

// Init initializes the plugin with configuration.
func (fp *FilePathFilterPlugin) Init(rawConfig any, hcc plugins.HCContext) (err error) {
	logger = hcc.GetLogger().With(slog.String("plugin", "filepath_filter"))
	consoleLogger = hcc.GetConsoleLogger()

	config, ok := rawConfig.(*Config)
	if !ok {
		err = fmt.Errorf("invalid config type, expected %T, got %T", &Config{}, rawConfig)
		return
	}

	err = checkPatternsConflicts(config.ForbiddenPaths, config.SkippedPaths)
	if err != nil {
		return
	}

	fp.ForbiddenPaths, err = compileRegexps(config.ForbiddenPaths)
	if err != nil {
		return
	}
	fp.SkippedPaths, err = compileRegexps(config.SkippedPaths)
	if err != nil {
		return
	}

	hcc.RegisterOnScanFile(fp.OnScanFile)

	logger.Info("plugin initialized",
		slog.String("forbidden_paths", strings.Join(config.ForbiddenPaths, ", ")),
		slog.String("skipped_paths", strings.Join(config.SkippedPaths, ", ")),
	)
	consoleLogger.Info(fmt.Sprintf("filepath_filter plugin initialized, forbidden_paths: %s, skipped_paths: %s",
		strings.Join(config.ForbiddenPaths, ", "), strings.Join(config.SkippedPaths, ", ")))
	return
}

// Close cleans up plugin resources (no-op for this plugin).
func (fp *FilePathFilterPlugin) Close(context.Context) error { return nil }

// OnScanFile filters files based on their path (location).
// location example:
//   - "/home/user/documents/virus.exe"
//   - "/tmp/extract-abc123/subdir/virus.exe"
//
// fileName example:
//   - "/home/user/documents/virus.exe"
//   - "subdir/virus.exe" (archive relative path)
func (fp *FilePathFilterPlugin) OnScanFile(fileName string, location string, sha256 string, _ bool) (res *datamodel.Result) {
	location = filepath.Clean(location)
	fileInfo, err := os.Stat(location)
	if err != nil {
		return
	}

	// forbidden paths take priority over skipped paths
	for strRegexp, regexp := range fp.ForbiddenPaths {
		if regexp.MatchString(location) {
			logger.Debug("filtered file based on its path (blacklist)",
				slog.String("file", location),
				slog.String("sha256", sha256),
				slog.String("regexp", strRegexp))
			consoleLogger.Debug(fmt.Sprintf("filtered file based on its path (blacklist) file=%s, regexp=%s", location, strRegexp))

			res = &datamodel.Result{
				Filename:       fileName,
				Location:       location,
				Malware:        true,
				SHA256:         sha256,
				Score:          1000,
				Malwares:       []string{"forbidden_file_path"},
				MalwareReason:  datamodel.FilteredFilePath,
				FilteredVolume: fileInfo.Size(),
				FileSize:       fileInfo.Size(),
			}
			return
		}
	}

	for strRegexp, regexp := range fp.SkippedPaths {
		if regexp.MatchString(location) {
			logger.Debug("filtered file based on its path (whitelist)",
				slog.String("file", location),
				slog.String("sha256", sha256),
				slog.String("regexp", strRegexp))
			consoleLogger.Debug(fmt.Sprintf("filtered file based on its path (whitelist) file=%s, regexp=%s", location, strRegexp))

			res = &datamodel.Result{
				Filename:       fileName,
				Location:       location,
				Malware:        false,
				SHA256:         sha256,
				Score:          -500,
				FilteredVolume: fileInfo.Size(),
				FileSize:       fileInfo.Size(),
			}
			return
		}
	}
	return
}

// checkPatternsConflicts returns an error if any pattern exists in both lists.
func checkPatternsConflicts(forbidden, skipped []string) (err error) {
	forbiddenSet := make(map[string]struct{}, len(forbidden))
	for _, pattern := range forbidden {
		forbiddenSet[pattern] = struct{}{}
	}

	for _, pattern := range skipped {
		if _, exists := forbiddenSet[pattern]; exists {
			err = fmt.Errorf("pattern %q is in both forbidden_paths and skipped_paths", pattern)
			return
		}
	}
	return
}

func compileRegexps(pathPatterns []string) (res map[string]*regexp.Regexp, err error) {
	res = make(map[string]*regexp.Regexp, len(pathPatterns))
	for _, pattern := range pathPatterns {
		var compiledRegexp *regexp.Regexp
		compiledRegexp, err = regexp.Compile(pattern)
		if err != nil {
			err = fmt.Errorf("error compiling regexp %s : %w", pattern, err)
			return
		}
		res[pattern] = compiledRegexp
	}
	return
}

func main() {}
