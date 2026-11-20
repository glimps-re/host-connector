package scanner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/glimps-re/connector-integration/sdk/events"
	"github.com/glimps-re/host-connector/pkg/plugins"
)

// Declarations lists what plugins declared through DeclareExecutable and
// DeclareOutputDir, for the core to check against the rest of the
// configuration.
type Declarations struct {
	Executables []string
	OutputDirs  []string
}

// declarations collects Declarations from concurrent plugins.
type declarations struct {
	mu sync.Mutex
	d  Declarations
}

func (d *declarations) addExecutable(path string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !slices.Contains(d.d.Executables, path) {
		d.d.Executables = append(d.d.Executables, path)
	}
}

func (d *declarations) addOutputDir(path string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !slices.Contains(d.d.OutputDirs, path) {
		d.d.OutputDirs = append(d.d.OutputDirs, path)
	}
}

func (d *declarations) snapshot() Declarations {
	d.mu.Lock()
	defer d.mu.Unlock()
	return Declarations{
		Executables: slices.Clone(d.d.Executables),
		OutputDirs:  slices.Clone(d.d.OutputDirs),
	}
}

func declareExecutable(d *declarations, path string, log *slog.Logger) error {
	resolved, warnings, err := plugins.CheckExecutable(path)
	if err != nil {
		return err
	}
	for _, w := range warnings {
		log.Warn(w)
	}
	log.Info("executable declared", slog.String("path", resolved))
	// Both forms are recorded: the core compares the configured one too, since
	// that is the path that gets run.
	d.addExecutable(resolved)
	d.addExecutable(filepath.Clean(path))
	return nil
}

func declareOutputDir(d *declarations, path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("output directory %q is not absolute", path)
	}
	d.addOutputDir(filepath.Clean(path))
	return nil
}

// DeclareExecutable implements plugins.ValidationContext for the running
// connector.
func (c *Connector) DeclareExecutable(path string) error {
	return declareExecutable(&c.declared, path, logger)
}

// DeclareOutputDir implements plugins.ValidationContext for the running
// connector.
func (c *Connector) DeclareOutputDir(path string) error {
	return declareOutputDir(&c.declared, path)
}

// Declarations returns what the loaded plugins declared during Init.
func (c *Connector) Declarations() Declarations {
	return c.declared.snapshot()
}

// reservedEventKey tells the keys of the core: a plugin must not raise or
// clear them.
func reservedEventKey(key string) bool {
	return strings.HasPrefix(key, "host-") || key == string(events.GMalwareError) || key == string(events.GMalwareConfigError)
}

// NotifyError raises an error event on the connector manager under key. The
// keys of the core are refused.
func (c *Connector) NotifyError(ctx context.Context, key string, err error) {
	if reservedEventKey(key) {
		logger.Warn("a plugin tried to raise a reserved event, ignored", slog.String("key", key))
		return
	}
	if e := EventHandler.NotifyError(ctx, events.ErrorEventType(key), err); e != nil {
		logger.Warn("could not push console error", slog.String("key", key), slog.String("error", e.Error()))
	}
}

// NotifyResolution clears the error event raised under key. The keys of the
// core are refused.
func (c *Connector) NotifyResolution(ctx context.Context, key string, message string) {
	if reservedEventKey(key) {
		logger.Warn("a plugin tried to clear a reserved event, ignored", slog.String("key", key))
		return
	}
	if e := EventHandler.NotifyResolution(ctx, message, events.ErrorEventType(key)); e != nil {
		logger.Warn("could not push resolution event to connector manager", slog.String("key", key), slog.String("error", e.Error()))
	}
}

// ValidationContext is the plugins.ValidationContext given to Validate: a
// scratch directory removed by Close, and the declarations recorded without
// touching the running connector.
type ValidationContext struct {
	dir      string
	lock     *os.File
	declared declarations
}

var _ plugins.ValidationContext = (*ValidationContext)(nil)

// NewValidationContext creates the scratch directory gmhost-validate-<random>
// (mode 0700) under base, made absolute and created when missing. An empty base
// is the system temporary directory, like the work directory of the connector.
func NewValidationContext(base string) (*ValidationContext, error) {
	if base == "" {
		base = os.TempDir()
	}
	base, err := filepath.Abs(base)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve the validation base directory: %w", err)
	}
	if err = os.MkdirAll(base, 0o700); err != nil {
		return nil, fmt.Errorf("cannot create the validation base directory %s: %w", base, err)
	}
	dir, err := os.MkdirTemp(base, "gmhost-validate-")
	if err != nil {
		return nil, fmt.Errorf("cannot create the validation directory under %s: %w", base, err)
	}
	// Not 0700 until the lock is held, like the work directory: the purge of
	// orphans only considers 0700 directories, so it cannot take a directory
	// whose lock is created but not yet held.
	if err = os.Chmod(dir, validationDirOpen); err != nil {
		return nil, errors.Join(err, os.RemoveAll(dir))
	}
	// The lock marks the directory as alive: the purge of orphan work
	// directories removes a gmhost-* directory whose lock is free (a crash).
	lock, err := createWorkDirLock(filepath.Join(dir, workDirLock))
	if err != nil {
		return nil, errors.Join(fmt.Errorf("cannot lock the validation directory: %w", err), os.RemoveAll(dir))
	}
	if err = os.Chmod(dir, validationDirPrivate); err != nil {
		return nil, errors.Join(err, lock.Close(), os.RemoveAll(dir))
	}
	return &ValidationContext{dir: dir, lock: lock}, nil
}

const (
	validationDirOpen    os.FileMode = 0o750
	validationDirPrivate os.FileMode = 0o700
)

// Close removes the scratch directory with everything a plugin left in it.
func (v *ValidationContext) Close() error {
	var errs []error
	if v.lock != nil {
		errs = append(errs, v.lock.Close())
		v.lock = nil
	}
	if err := os.RemoveAll(v.dir); err != nil {
		errs = append(errs, fmt.Errorf("cannot remove the validation directory %s: %w", v.dir, err))
	}
	return errors.Join(errs...)
}

// GetLogger returns the connector logger.
func (v *ValidationContext) GetLogger() *slog.Logger { return logger }

// GetConsoleLogger returns the console logger.
func (v *ValidationContext) GetConsoleLogger() *slog.Logger { return ConsoleLogger }

// GetWorkDir returns the scratch directory.
func (v *ValidationContext) GetWorkDir() string { return v.dir }

// DeclareExecutable checks and records an executable.
func (v *ValidationContext) DeclareExecutable(path string) error {
	return declareExecutable(&v.declared, path, logger)
}

// DeclareOutputDir records an output directory.
func (v *ValidationContext) DeclareOutputDir(path string) error {
	return declareOutputDir(&v.declared, path)
}

// Declarations returns what the plugins declared during validation.
func (v *ValidationContext) Declarations() Declarations {
	return v.declared.snapshot()
}

// validatePlugin decodes the configuration of one plugin like Init does and
// runs its Validate, if it has one. A panic of the plugin is an error.
func validatePlugin(pc PluginConfig, p plugins.Plugin, vc *ValidationContext) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("plugin %s: validation panicked: %v", pc.Name, r)
		}
	}()
	config := p.GetDefaultConfig()
	if config != nil {
		if err = plugins.DecodeConfig(pc.Name, pc.Config, config); err != nil {
			return err
		}
	} else if len(pc.Config) > 0 {
		return fmt.Errorf("plugin %s: %w: it takes no configuration", pc.Name, errInvalidPlugin)
	}
	v, ok := p.(plugins.Validator)
	if !ok {
		return nil
	}
	if err = v.Validate(config, vc); err != nil {
		return fmt.Errorf("plugin %s: %w", pc.Name, err)
	}
	return nil
}

// validatePlugins runs validatePlugin on every plugin, opening them with open,
// and joins the errors.
func validatePlugins(pluginsConfig []PluginConfig, vc *ValidationContext, open func(file string) (plugins.Plugin, error)) error {
	if err := checkPluginNames(pluginsConfig); err != nil {
		return err
	}
	var errs []error
	for _, pc := range pluginsConfig {
		if pc.File == "" {
			errs = append(errs, fmt.Errorf("plugin %s: %w: missing %q", pc.Name, errInvalidPlugin, "file"))
			continue
		}
		p, err := open(pc.File)
		if err != nil {
			errs = append(errs, fmt.Errorf("plugin %s: %w", pc.Name, err))
			continue
		}
		if err = validatePlugin(pc, p, vc); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
